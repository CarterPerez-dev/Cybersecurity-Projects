# 02-ARCHITECTURE.md

# System Architecture

## High-Level Pipeline

The scanner follows a linear pipeline: CLI parses arguments, the engine orchestrates, scanners extract and detect, and reporters format output.

```
┌──────────────────────────────────────────────────────────┐
│                     CLI Layer (Typer)                     │
│                                                          │
│  dlp-scan file ./data -f json -o results.json            │
│  dlp-scan db postgres://user:pass@host/db                │
│  dlp-scan network capture.pcap                           │
│  dlp-scan report summary results.json                    │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                    ScanEngine                             │
│                                                          │
│  Loads config ─► Builds DetectorRegistry ─► Selects      │
│  scanner type ─► Runs scan ─► Routes to reporter         │
└──────────────────────┬───────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
┌──────────────┐ ┌──────────┐ ┌──────────────┐
│ FileScanner  │ │DBScanner │ │NetworkScanner│
│              │ │          │ │              │
│ Walk dirs    │ │ Schema   │ │ PCAP parse   │
│ Extract text │ │ introspect│ │ TCP reassembly│
│ Run detectors│ │ Sample   │ │ DNS exfil    │
│              │ │ rows     │ │ DPI protocol │
│              │ │ Detect   │ │ Detect       │
└──────┬───────┘ └────┬─────┘ └──────┬───────┘
       │              │              │
       └──────────────┼──────────────┘
                      ▼
┌──────────────────────────────────────────────────────────┐
│                 DetectorRegistry                          │
│                                                          │
│  PatternDetector ─► ContextBoost ─► CooccurrenceBoost    │
│       │                                                  │
│       └─► EntropyDetector (parallel)                     │
│                                                          │
│  Rules: PII | Financial | Credentials | Health           │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                    Reporter Layer                         │
│                                                          │
│  ConsoleReporter ─► Rich tables with severity colors     │
│  JsonReporter    ─► Structured JSON with metadata        │
│  SarifReporter   ─► SARIF 2.1.0 for CI/CD pipelines     │
│  CsvReporter     ─► Flat CSV for compliance teams        │
└──────────────────────────────────────────────────────────┘
```

## Component Breakdown

### CLI Layer

**Purpose:** Parse command-line arguments, propagate global options, route to the correct scan command or report utility.

**Files:** `cli.py`, `commands/scan.py`, `commands/report.py`

The root Typer app in `cli.py` defines a callback that captures `--config`, `--verbose`, and `--version` into Click's context object. The scan commands (`file`, `db`, `network`) are defined in `commands/scan.py` and registered as top-level commands through a `register(app)` function that calls `app.command("file")(scan_file)` for each. This avoids nesting under a `scan` subgroup while keeping the command definitions in their own module.

The `report` subgroup is a separate Typer instance added via `app.add_typer(report_app, name="report")`. It provides `convert` (JSON to other formats) and `summary` (print Rich table from JSON results).

### ScanEngine

**Purpose:** Single orchestration point that connects config to scanners to reporters.

**File:** `engine.py`

The engine takes a `ScanConfig` and constructs a `DetectorRegistry` by unpacking detection configuration into individual parameters:

```python
class ScanEngine:
    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        detection = config.detection
        allowlist_vals = detection.allowlists.values
        self._registry = DetectorRegistry(
            enable_patterns=detection.enable_rules,
            disable_patterns=detection.disable_rules,
            allowlist_values=(
                frozenset(allowlist_vals)
                if allowlist_vals else None
            ),
            context_window_tokens=(
                detection.context_window_tokens
            ),
        )
```

The engine exposes `scan_files`, `scan_database`, and `scan_network`, each of which constructs the appropriate scanner, runs it, and returns a `ScanResult`. Report generation uses a `REPORTER_MAP` dict that maps format strings to reporter classes.

### DetectorRegistry

**Purpose:** Central hub that loads detection rules, filters them by enable/disable globs, and runs the full scoring pipeline against text.

**File:** `detectors/registry.py`

The registry loads all rules from four rule modules (PII, Financial, Credentials, Health), filters them using `fnmatch.fnmatch` against enable/disable patterns, and wraps the survivors in a `PatternDetector`. When `detect()` is called:

1. `PatternDetector` runs all regex patterns, validates matches with checksums (Luhn, Mod-97, Mod-11), and filters against the allowlist
2. `apply_context_boost` scans a token window around each match for relevant keywords and adjusts scores based on proximity
3. `_apply_cooccurrence_boost` adds a bonus when multiple different PII types appear within 500 characters of each other
4. `EntropyDetector` independently finds high-entropy regions using a sliding window

```
Text Input
    │
    ▼
┌─────────────────────────┐
│    PatternDetector       │
│                          │
│ For each rule:           │
│   regex.finditer(text)   │
│   ─► allowlist filter    │
│   ─► validator (Luhn,    │
│       Mod-97, SSN area)  │
│   ─► base_score + boost  │
└─────────┬───────────────┘
          │
          ▼
┌─────────────────────────┐
│    Context Boost         │
│                          │
│ Token window ±10 tokens  │
│ Keyword proximity search │
│ Distance-weighted boost  │
│ (0.05 to 0.35)           │
└─────────┬───────────────┘
          │
          ▼
┌─────────────────────────┐
│   Co-occurrence Boost    │
│                          │
│ Different rule_ids       │
│ within 500 chars ─► +0.15│
└─────────┬───────────────┘
          │
          ▼
┌─────────────────────────┐
│   Entropy Detector       │
│                          │
│ Sliding 256-byte window  │
│ Shannon H >= 7.2 bits    │
│ Independent matches      │
└─────────┬───────────────┘
          │
          ▼
     DetectorMatch[]
```

### Scanners

**Purpose:** Each scanner handles a different scan surface (files, databases, network) and converts raw data into text that the DetectorRegistry can process.

**Files:** `scanners/file_scanner.py`, `scanners/db_scanner.py`, `scanners/network_scanner.py`

All scanners follow the same `Scanner` protocol: a `scan(target: str) -> ScanResult` method. They share a common flow: iterate over targets, extract text, run detection, convert matches to findings via `match_to_finding` in `scoring.py` (which handles severity classification, compliance lookup, remediation, and redaction in one call), and aggregate into a `ScanResult`.

**FileScanner** walks a directory tree, applies extension and exclusion filters, dispatches each file to the appropriate extractor based on extension, and runs the detector on each `TextChunk`. The extension-to-extractor mapping is built once by `_build_extension_map`, which iterates over all extractor instances and indexes by their `supported_extensions`.

**DatabaseScanner** connects via URI scheme detection (postgres, mysql, mongodb, sqlite), introspects the schema to find text-type columns, samples rows using database-native sampling (TABLESAMPLE BERNOULLI for PostgreSQL, RAND() for MySQL, $sample for MongoDB), and scans column values.

**NetworkScanner** reads PCAP files via `read_pcap`, feeds packets into a `FlowTracker` for TCP reassembly, and processes DNS traffic inline through `parse_dns` and `DnsExfilDetector`. Each packet payload is also checked by `detect_base64_payload` for encoded data. After packet iteration, the scanner reassembles TCP flows, identifies the application protocol via `identify_protocol`, extracts text with protocol awareness (`parse_http` for HTTP bodies and sensitive headers, skip encrypted TLS/SSH, UTF-8 decode for everything else), and runs detection on the extracted text.

### Extractors

**Purpose:** Convert binary and structured file formats into uniform `TextChunk` objects that carry both the extracted text and a `Location` describing where it came from.

**Files:** `extractors/plaintext.py`, `extractors/pdf.py`, `extractors/office.py`, `extractors/structured.py`, `extractors/archive.py`, `extractors/email.py`

All extractors implement the `Extractor` protocol: `extract(path) -> list[TextChunk]` and `supported_extensions -> frozenset[str]`.

```
┌───────────────────────────────────────────────┐
│              Extractor Protocol                │
│  extract(path) -> list[TextChunk]             │
│  supported_extensions -> frozenset[str]        │
└───────────────────────────────────────────────┘
         │
    ┌────┴────┬──────────┬──────────┬──────┐
    ▼         ▼          ▼          ▼      ▼
Plaintext   PDF      Office   Structured  Archive
.txt .log  .pdf    .docx     .csv .json  .zip
.cfg .py           .xlsx     .xml .yaml  .tar.gz
.html .md          .xls      .parquet    .tar.bz2
.ts .go                      .avro
...                          .tsv
```

The `PlaintextExtractor` chunks files into 500-line blocks to keep memory bounded. Binary format extractors (PDF via PyMuPDF, DOCX via python-docx, XLSX via openpyxl) each return one `TextChunk` per page/sheet/section. The archive extractor recurses into compressed files up to a configurable depth with zip bomb protection (compression ratio threshold check).

### Reporters

**Purpose:** Take a `ScanResult` and serialize it into the requested output format.

**Files:** `reporters/console.py`, `reporters/json_report.py`, `reporters/sarif.py`, `reporters/csv_report.py`

Each reporter has a `generate(result) -> str` method. The `ConsoleReporter` also has a `display(result)` method for Rich-formatted terminal output with severity-colored tables.

The JSON reporter outputs a structured document with `scan_metadata`, `findings`, and `summary` sections. The SARIF reporter produces a SARIF 2.1.0 document with `tool.driver.rules`, mapping severity levels through `SARIF_SEVERITY_MAP` (critical/high to "error", medium to "warning", low to "note"). The CSV reporter flattens findings into rows.

## Data Models

### Core Models

```python
@dataclass(frozen=True, slots=True)
class Location:
    source_type: str
    uri: str
    line: int | None = None
    column: int | None = None
    byte_offset: int | None = None
    table_name: str | None = None
    column_name: str | None = None
    sheet_name: str | None = None


@dataclass(slots=True)
class Finding:
    finding_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float
    location: Location
    redacted_snippet: str
    compliance_frameworks: list[str]
    remediation: str
    detected_at: datetime


@dataclass(slots=True)
class ScanResult:
    scan_id: str
    tool_version: str
    scan_started_at: datetime
    scan_completed_at: datetime | None
    targets_scanned: int
    findings: list[Finding]
    errors: list[str]
```

`Location` is frozen because it represents a fact about where something was found. `Finding` is mutable because fields like `finding_id` and `detected_at` get defaults from factory functions. `ScanResult` aggregates findings and provides computed properties (`findings_by_severity`, `findings_by_rule`, `findings_by_framework`) that group counts for summary reporting.

The `TextChunk` dataclass carries extracted text paired with its `Location`, forming the bridge between extractors and detectors. Every text fragment knows exactly where it came from, which lets findings carry precise location information through the pipeline.

### Detection Models

```python
@dataclass(frozen=True, slots=True)
class DetectionRule:
    rule_id: str
    rule_name: str
    pattern: re.Pattern[str]
    base_score: float
    context_keywords: list[str]
    validator: Callable[[str], bool] | None
    compliance_frameworks: list[str]


@dataclass(frozen=True, slots=True)
class DetectorMatch:
    rule_id: str
    rule_name: str
    start: int
    end: int
    matched_text: str
    score: float
    context_keywords: list[str]
    compliance_frameworks: list[str]
```

`DetectionRule` is a specification: the regex pattern to match, the base confidence score, optional checksum validator, and context keywords. `DetectorMatch` is a result: what was found, where in the text, and the current score after validation. The `score` field gets modified through the boost pipeline (context, co-occurrence) before being mapped to a `Severity` level and placed into a `Finding`.

## Configuration Architecture

```
┌────────────────────────────────────────────┐
│            .dlp-scanner.yml                │
│                                            │
│  scan:                                     │
│    file: { max_file_size_mb, recursive }   │
│    database: { sample_percentage }         │
│    network: { bpf_filter, max_packets }    │
│  detection:                                │
│    min_confidence, enable_rules,           │
│    disable_rules, allowlists               │
│  compliance: { frameworks }                │
│  output: { format, redaction_style }       │
│  logging: { level, json_output }           │
└────────────────┬───────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────┐
│         load_config(path) -> ScanConfig    │
│                                            │
│  1. Check CLI --config flag                │
│  2. Search candidates:                     │
│     .dlp-scanner.yml                       │
│     .dlp-scanner.yaml                      │
│     ~/.dlp-scanner.yml                     │
│  3. Parse YAML via ruamel.yaml             │
│  4. Validate with Pydantic 2.x models     │
│  5. Return ScanConfig with defaults        │
└────────────────────────────────────────────┘
```

Every configuration value has a constant default defined in `constants.py`. The Pydantic models in `config.py` use these constants as field defaults, so a completely empty config file produces a working scanner. Constrained-choice fields (`severity_threshold`, `format`, `redaction_style`) use `Literal` types defined in `constants.py` (e.g., `Literal["critical", "high", "medium", "low"]`), so Pydantic rejects invalid values at parse time rather than silently accepting a typo. The config loader uses `ruamel.yaml` (not PyYAML) because it preserves comments and handles YAML 1.2.

The YAML structure uses a `scan:` top-level key to group scanner-specific config, while `detection:`, `compliance:`, `output:`, and `logging:` sit at root level. This mirrors how users think about configuration: "how to scan" vs. "what to detect" vs. "how to report".

## Data Flow: File Scan

Step-by-step walkthrough of `dlp-scan file ./data -f json`:

```
1. Typer parses args
   └─► main() callback stores config_path="" and verbose=False in ctx.obj

2. scan_file() receives ctx, target="./data", format="json"
   └─► _run_scan() validates format, loads config, sets logging to WARNING
       (WARNING for machine-readable formats keeps stdout clean)

3. ScanEngine(config) constructs DetectorRegistry
   └─► Registry loads 29 rules from PII/Financial/Credential/Health modules
   └─► Filters through enable_rules=["*"], disable_rules=[]

4. engine.scan_files("./data")
   └─► FileScanner.scan() creates ScanResult, walks directory

5. For each file in ./data/**/*:
   └─► Check extension against include_extensions
   └─► Check path against exclude_patterns
   └─► Check file size against max_file_size_mb
   └─► Select extractor by extension (e.g. .csv -> CsvExtractor)
   └─► extractor.extract(path) -> list[TextChunk]

6. For each TextChunk:
   └─► registry.detect(chunk.text) -> list[DetectorMatch]
       ├─► PatternDetector: regex match + allowlist + validator
       ├─► apply_context_boost: keyword proximity scoring
       ├─► _apply_cooccurrence_boost: multi-PII bonus
       └─► EntropyDetector: high-entropy region detection

7. For each DetectorMatch above min_confidence:
   └─► match_to_finding(match, text, location, redaction_style)
       ├─► score_to_severity(match.score) -> Severity
       ├─► get_frameworks_for_rule(match.rule_id) -> compliance list
       ├─► get_remediation_for_rule(match.rule_id) -> guidance string
       └─► redact(chunk.text, start, end, style) -> snippet
   └─► Append Finding to ScanResult

8. Back in _run_scan():
   └─► engine.generate_report(result, "json")
   └─► JsonReporter().generate(result) -> JSON string
   └─► typer.echo(output) -> stdout
```

## Design Patterns

### Protocol-Based Polymorphism

The codebase uses Python's `typing.Protocol` instead of abstract base classes for extension points. The `Extractor`, `Scanner`, and `Detector` protocols define structural interfaces without requiring inheritance.

```python
class Extractor(Protocol):
    def extract(self, path: str) -> list[TextChunk]: ...

    @property
    def supported_extensions(self) -> frozenset[str]: ...
```

Any class with matching method signatures satisfies the protocol. This means you can add a new extractor (say, for .pptx files) without importing the base module. The type checker verifies compliance; the runtime never checks inheritance.

**Why not ABCs:** Abstract base classes force an import dependency and mandate `super().__init__()` chains. Protocols are lighter and match Python's duck typing philosophy. Since extractors are stateless (no shared state or lifecycle), there is nothing an ABC would provide beyond the type contract.

### Registry Pattern

The `DetectorRegistry` centralizes rule management: loading, filtering, and execution. Individual rule modules (pii.py, financial.py, credentials.py, health.py) each export a list of `DetectionRule` objects. The registry merges them into `ALL_RULES`, applies glob filtering, and wraps the result in a `PatternDetector`.

This keeps rule definitions declarative. Adding a new rule is a matter of appending a `DetectionRule` to the appropriate list. The registry handles filtering and execution without rule authors needing to understand the scoring pipeline.

### Command Registration Pattern

CLI commands are defined in `commands/scan.py` as plain functions and registered on the root app through a `register(app)` function:

```python
def register(app: typer.Typer) -> None:
    app.command("file")(scan_file)
    app.command("db")(scan_db)
    app.command("network")(scan_network)
```

This achieves top-level commands (`dlp-scan file`, not `dlp-scan scan file`) while keeping the command logic out of `cli.py`. The `_run_scan` helper deduplicates the shared logic (config loading, format validation, output routing) across all three scan types.

## Compliance Mapping

The compliance module maps rule IDs to regulatory frameworks and remediation guidance using two static dictionaries:

```
RULE_FRAMEWORK_MAP: rule_id -> [frameworks]
RULE_REMEDIATION_MAP: rule_id -> guidance string
```

Rule IDs match actual detection rules (e.g., `FIN_CREDIT_CARD_VISA`, `FIN_CREDIT_CARD_MC`, not a generic `FIN_CREDIT_CARD`). Network exfiltration indicators (`NET_DNS_EXFIL_*`, `NET_ENCODED_*`) are also mapped. Every rule has a remediation entry with specific guidance text; unknown rules fall back to a generic default.

When a `DetectorMatch` is converted to a `Finding` via `match_to_finding` in `scoring.py`, the function calls `get_frameworks_for_rule` and `get_remediation_for_rule` to decorate the finding with compliance metadata. If the detection rule itself also carries `compliance_frameworks`, both sets are merged.

This design keeps detection rules independent of compliance logic. The PII module does not need to know that HIPAA cares about SSNs. The compliance module owns that mapping, and it can be updated independently when regulations change.

## Redaction Pipeline

```
matched text
     │
     ▼
 style == "none"?  ─yes─►  raw snippet with context
     │ no
     ▼
 style == "full"?  ─yes─►  [REDACTED] with context
     │ no
     ▼
 _partial_redact()
     │
     ├─ 9+ digit number  ─►  *****6789  (mask all but last 4)
     ├─ email address     ─►  j****@example.com
     └─ generic string    ─►  keep last 25%
     │
     ▼
 _build_snippet()
     │
     └─ ±20 chars context  ─►  "...SSN: *****6789 for..."
```

Partial redaction is the default because it gives analysts enough to identify the data type and triage priority without exposing the full sensitive value. The last 4 digits of SSNs and credit cards are considered non-sensitive by PCI-DSS (you can print them on receipts), so partial redaction for those types is compliant.

## Network Analysis Architecture

```
┌────────────────────────────────────────────┐
│              PCAP File                     │
│  (.pcap or .pcapng)                        │
└────────────────┬───────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────┐
│            pcap.read_pcap()                │
│                                            │
│  dpkt.pcap.Reader / dpkt.pcapng.Reader     │
│  Parse Ethernet -> IP -> TCP/UDP           │
│  Yield PacketInfo(src_ip, dst_ip,          │
│       src_port, dst_port, payload,         │
│       tcp_seq, tcp_flags)                  │
└────────────────┬───────────────────────────┘
                 │
         ┌───────┴───────┐
         ▼               ▼
┌─────────────┐  ┌───────────────┐
│FlowTracker  │  │DnsExfilDetector│
│             │  │               │
│Track by     │  │Label length   │
│4-tuple key  │  │check (>50)    │
│             │  │               │
│Reassemble   │  │Subdomain      │
│TCP streams  │  │entropy (>4.0) │
│by seq num   │  │               │
│             │  │QNAME length   │
│Dedup retx   │  │check (>100)   │
└──────┬──────┘  │               │
       │         │TXT volume     │
       ▼         │ratio check    │
┌─────────────┐  └───────┬───────┘
│Protocol ID  │          │
│(DPI)        │          ▼
│             │  ExfilIndicator[]
│HTTP: method │
│  prefix     │
│TLS: \x16\x03│
│SSH: SSH-    │
│SMTP: 220   │
└──────┬──────┘
       │
       ▼
  Reassembled text
  sent to DetectorRegistry
```

The flow tracker creates bidirectional flow keys by sorting the forward and reverse 4-tuples, so `(A, B, 80, 12345)` and `(B, A, 12345, 80)` map to the same flow. TCP reassembly sorts segments by sequence number and deduplicates retransmissions. Without reassembly, a credit card number split across two TCP segments would be missed.

The DNS exfiltration detector runs independently of the regex-based detectors. It analyzes DNS queries for encoding signals: base64-like entropy in subdomain labels, abnormally long labels, long QNAMEs, and suspicious TXT query volume ratios. The OilRig APT campaign used exactly these patterns to exfiltrate stolen documents through DNS tunneling to C2 infrastructure.

## Error Handling Strategy

Errors are collected, not thrown. Each scanner appends error messages to `ScanResult.errors` and continues scanning the remaining targets. The CLI checks `result.errors` after the scan completes and exits with code 1 if any errors occurred, but the partial results are still reported.

This "collect and continue" approach means a single corrupt PDF in a directory of 10,000 files does not abort the scan. The Equifax breach investigation found that scanning tools that failed on individual files often left entire directories unscanned, which is why modern DLP tools treat extraction failures as warnings rather than fatal errors.

## Performance Considerations

**File scanning** is I/O-bound. The scanner processes files sequentially to avoid overwhelming disk I/O. Text extraction for binary formats (PDF, Office) can be CPU-intensive, but these files are typically a small fraction of the total.

**Detection** scales linearly with text length times rule count. With 29 rules and an average text chunk of 500 lines, a single detection pass takes microseconds. The entropy detector is more expensive due to its sliding window, so it only runs when enabled and only against high-level text chunks (not individual regex matches).

**Memory** stays bounded through chunking. The plaintext extractor reads 500 lines at a time. Archive extraction enforces depth limits and zip bomb ratio checks.

## Key Files Reference

- `cli.py` - Entry point, global options, Typer app
- `engine.py` - Orchestration, connects config to scanners to reporters
- `config.py` - Pydantic models, YAML loading, config search
- `constants.py` - All magic numbers, thresholds, type literals
- `models.py` - Finding, Location, ScanResult, TextChunk
- `compliance.py` - Rule-to-framework mapping, severity classification
- `scoring.py` - Shared match-to-finding conversion for all scanners
- `redaction.py` - Partial/full/none redaction strategies
- `detectors/registry.py` - Rule loading, filtering, scoring pipeline
- `detectors/pattern.py` - Regex matching with allowlist and checksum validation
- `detectors/context.py` - Keyword proximity boost, co-occurrence boost
- `detectors/entropy.py` - Shannon entropy detection, sliding window
- `detectors/rules/` - Rule definitions (pii, financial, credentials, health)
- `extractors/` - Text extraction from 14+ file formats
- `scanners/` - File, database, network scan implementations
- `network/` - PCAP parsing, flow tracking, DPI, DNS exfiltration
- `reporters/` - Console, JSON, SARIF, CSV output
- `commands/` - CLI command implementations (scan, report)

## Next Steps

Now that you understand the architecture:
1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for the code walkthrough
2. Try modifying a detection rule in `detectors/rules/pii.py` to see how the scoring pipeline responds
