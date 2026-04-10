# 03-IMPLEMENTATION.md

# Implementation Guide

This document walks through how the code works. We cover the detection engine, file extraction, network analysis, and CLI integration, with code snippets from the actual project.

## File Structure

```
src/dlp_scanner/
├── __init__.py
├── cli.py                  # Typer entry point
├── engine.py               # Scan orchestration
├── config.py               # Pydantic config models
├── constants.py            # Thresholds, types, defaults
├── models.py               # Finding, Location, ScanResult
├── compliance.py           # Rule-to-framework mapping
├── redaction.py            # Snippet masking
├── log.py                  # structlog configuration
├── scoring.py              # Shared match-to-finding conversion
├── commands/
│   ├── scan.py             # file, db, network commands
│   └── report.py           # convert, summary commands
├── detectors/
│   ├── base.py             # DetectionRule, DetectorMatch
│   ├── pattern.py          # Regex + checksum detection
│   ├── context.py          # Keyword proximity scoring
│   ├── entropy.py          # Shannon entropy detection
│   ├── registry.py         # Central detector registry
│   └── rules/
│       ├── pii.py          # SSN, email, phone, passport
│       ├── financial.py    # Credit cards, IBAN, NHS
│       ├── credentials.py  # AWS, GitHub, JWT, Stripe
│       └── health.py       # Medical records, DEA, NPI
├── extractors/
│   ├── base.py             # Extractor protocol
│   ├── plaintext.py        # .txt, .log, .cfg, source code
│   ├── pdf.py              # .pdf via PyMuPDF
│   ├── office.py           # .docx, .xlsx, .xls
│   ├── structured.py       # .csv, .json, .xml, .yaml, .parquet, .avro
│   ├── archive.py          # .zip, .tar.gz, .tar.bz2
│   └── email.py            # .eml, .msg
├── network/
│   ├── pcap.py             # PCAP/PCAPNG packet reader
│   ├── flow_tracker.py     # TCP flow reassembly
│   ├── protocols.py        # DPI protocol identification
│   └── exfiltration.py     # DNS exfil detection
├── reporters/
│   ├── base.py             # Reporter protocol
│   ├── console.py          # Rich terminal output
│   ├── json_report.py      # Structured JSON
│   ├── sarif.py            # SARIF 2.1.0
│   └── csv_report.py       # Flat CSV
└── scanners/
    ├── base.py             # Scanner protocol
    ├── file_scanner.py     # Directory walking + extraction
    ├── db_scanner.py       # DB schema introspection
    └── network_scanner.py  # PCAP payload scanning
```

## Building the Detection Engine

### Detection Rules

Every detection rule is a data structure, not a class hierarchy. The `DetectionRule` dataclass holds the regex pattern, base confidence score, optional validator function, context keywords, and compliance framework tags:

```python
@dataclass(frozen=True, slots=True)
class DetectionRule:
    rule_id: str
    rule_name: str
    pattern: re.Pattern[str]
    base_score: float
    context_keywords: list[str] = field(default_factory=list)
    validator: Callable[[str], bool] | None = None
    compliance_frameworks: list[str] = field(
        default_factory=list
    )
```

Rule modules export plain lists of these structs. Here is the SSN rule from `detectors/rules/pii.py`:

```python
SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}"
    r"[-\s]?"
    r"(?!00)\d{2}"
    r"[-\s]?"
    r"(?!0000)\d{4}\b"
)

PII_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="PII_SSN",
        rule_name="US Social Security Number",
        pattern=SSN_PATTERN,
        base_score=0.45,
        context_keywords=SSN_CONTEXT,
        validator=_validate_ssn,
        compliance_frameworks=[
            "HIPAA", "CCPA", "GLBA", "GDPR",
        ],
    ),
    ...
]
```

The regex uses negative lookaheads (`(?!000|666|9\d{2})`) to reject SSN area numbers the Social Security Administration has never assigned. This is a first-pass structural filter. The real validation happens in `_validate_ssn`, which the `PatternDetector` calls for every regex match.

**Why base_score is 0.45, not higher:** A 9-digit number matching the SSN format appears in serial numbers, zip+4 codes, phone fragments, and test data constantly. The string `456-78-9012` matches the SSN pattern and passes area/group/serial validation, but without context it could be anything. A base of 0.45 keeps it in the "medium" severity tier until context boosts push it higher.

### Checksum Validation

The three checksum validators demonstrate different mathematical approaches to the same problem: distinguishing real identifiers from random digit sequences.

**Luhn algorithm** for credit cards (in `detectors/rules/financial.py`):

```python
def luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False

    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0
```

The algorithm works right-to-left: take every other digit starting from the rightmost, sum them. For the remaining digits, double each, and if the result exceeds 9, subtract 9 (which is what `sum(divmod(d * 2, 10))` does). If the grand total is divisible by 10, the number is valid. A random 16-digit number has about a 10% chance of passing Luhn, so it reduces false positives by roughly 90%.

**Mod-97** for IBANs (ISO 7064):

```python
def iban_check(value: str) -> bool:
    cleaned = value.replace(" ", "").upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False

    rearranged = cleaned[4:] + cleaned[:4]
    numeric = ""
    for char in rearranged:
        if char.isalpha():
            numeric += str(ord(char) - ord("A") + 10)
        else:
            numeric += char

    return int(numeric) % 97 == 1
```

Move the country code and check digits (first 4 chars) to the end, convert letters to two-digit numbers (A=10, B=11, etc.), then check that the entire number mod 97 equals 1. The false positive rate is approximately 1 in 97.

**Mod-11** for NHS numbers:

```python
def nhs_check(value: str) -> bool:
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 10 or not digits.isdigit():
        return False

    weights = range(10, 1, -1)
    total = sum(
        int(d) * w
        for d, w in zip(digits[:9], weights, strict=False)
    )
    remainder = 11 - (total % 11)
    if remainder == 11:
        remainder = 0
    if remainder == 10:
        return False
    return remainder == int(digits[9])
```

Multiply the first 9 digits by descending weights (10, 9, 8, ..., 2), sum them, compute `11 - (sum mod 11)`, and compare to the check digit. If the result is 10, the number is invalid (NHS never issues these). If the result is 11, the check digit is 0.

**Luhn-80840** for NPIs (in `detectors/rules/health.py`):

```python
def _validate_npi(value: str) -> bool:
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 10 or not digits.isdigit():
        return False

    prefixed = "80840" + digits
    total = 0
    for i, d in enumerate(reversed(prefixed)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
```

NPI (National Provider Identifier) validation is a Luhn variant. The trick is prepending `80840` (the healthcare industry prefix assigned by ANSI) before running the standard Luhn algorithm. This prefix is not part of the NPI itself, but the ISO standard requires it for check digit computation. A random 10-digit number has about a 10% chance of passing, making this check useful but not definitive. The base score of 0.10 reflects that NPI patterns match many unrelated 10-digit numbers, and context keywords like "provider" or "npi" are needed to push the score into actionable territory.

### Pattern Detection

The `PatternDetector` in `detectors/pattern.py` iterates over all active rules, runs each regex against the input text, filters through the allowlist, and applies checksum validation:

```python
class PatternDetector:
    def detect(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []

        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                matched_text = m.group()

                if self._is_allowlisted(matched_text):
                    continue

                score = rule.base_score

                if rule.validator is not None:
                    if rule.validator(matched_text):
                        score = min(1.0, score + CHECKSUM_BOOST)
                    else:
                        continue

                matches.append(
                    DetectorMatch(
                        rule_id=rule.rule_id,
                        ...
                        score=score,
                    )
                )

        return matches
```

When a rule has a validator and the match fails validation, the match is discarded entirely (`continue`). A Visa pattern that matches `4532015112830366` but fails Luhn is not a credit card. When validation passes, the score gets a +0.30 boost (`CHECKSUM_BOOST`). This is aggressive because checksum-passing matches are overwhelmingly real: the Luhn+Visa prefix combination has a false positive rate under 1%.

The allowlist uses a frozen set lookup, defaulting to `KNOWN_TEST_VALUES` (common test card numbers, example SSNs like `123-45-6789`). This prevents DLP tools from flagging their own test data, which is a common complaint in production deployments.

### Context Keyword Scoring

After pattern detection, `apply_context_boost` in `detectors/context.py` scans the surrounding text for keywords that indicate the matched value is actually sensitive data:

```python
def apply_context_boost(
    text: str,
    matches: list[DetectorMatch],
    window_tokens: int = DEFAULT_CONTEXT_WINDOW_TOKENS,
) -> list[DetectorMatch]:
    tokens = text.lower().split()
    boosted: list[DetectorMatch] = []

    for match in matches:
        if not match.context_keywords:
            boosted.append(match)
            continue

        char_to_token = _char_offset_to_token_index(
            text, match.start
        )
        window_start = max(
            0, char_to_token - window_tokens
        )
        window_end = min(
            len(tokens), char_to_token + window_tokens
        )
        window_text = " ".join(
            tokens[window_start:window_end]
        )

        boost = _compute_keyword_boost(
            window_text,
            match.context_keywords,
            window_tokens,
        )

        new_score = min(1.0, match.score + boost)
        ...
```

The window is bidirectional: 10 tokens in each direction from the match. The boost is distance-weighted: a keyword right next to the match contributes up to `CONTEXT_BOOST_MAX` (0.35), while one at the edge of the window contributes almost nothing. This reflects a real observation: "SSN: 456-78-9012" is almost certainly an SSN, while "SSN" appearing 50 words away from "456-78-9012" is weaker signal.

The `_compute_keyword_boost` function finds the best keyword match in the window and computes `CONTEXT_BOOST_MAX * proximity_factor`, where proximity is `1.0 - (distance / max_distance)`. Only the highest-scoring keyword matters, not the sum of all keywords. This prevents keyword stuffing from inflating scores.

### Co-occurrence Boost

After context boosting, `_apply_cooccurrence_boost` checks whether multiple different PII types appear near each other:

```python
def _apply_cooccurrence_boost(
    matches: list[DetectorMatch],
) -> list[DetectorMatch]:
    if len(matches) < 2:
        return matches

    proximity_threshold = 500

    for i, match in enumerate(matches):
        has_neighbor = False
        for j, other in enumerate(matches):
            if i == j:
                continue
            if other.rule_id == match.rule_id:
                continue
            distance = abs(match.start - other.start)
            if distance < proximity_threshold:
                has_neighbor = True
                break

        if has_neighbor:
            new_score = min(
                1.0, match.score + COOCCURRENCE_BOOST
            )
            ...
```

An SSN near a credit card number is stronger evidence than either alone. The boost is +0.15 (`COOCCURRENCE_BOOST`), and it requires different `rule_id` values (two SSNs next to each other do not trigger it). The 500-character threshold roughly corresponds to a short paragraph or a few database columns.

This heuristic matters in practice. The Capital One breach data contained CSV exports where SSNs, credit card numbers, and addresses appeared in adjacent columns. Co-occurrence detection would have flagged these files as critical priority.

### Shannon Entropy Detection

The `EntropyDetector` in `detectors/entropy.py` finds high-entropy regions that may contain secrets, encrypted data, or base64-encoded credentials:

```python
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
    )
```

Shannon entropy measures the average information content per byte. English text sits around 3.5-4.5 bits. Base64-encoded data is 5.5-6.0. Truly random bytes approach 8.0 (log2(256)). The detector uses a sliding window of 256 bytes with a 128-byte step:

```python
def detect_high_entropy_regions(
    data: bytes,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    window_size: int = WINDOW_SIZE,
    step: int = WINDOW_STEP,
) -> list[tuple[int, int, float]]:
    ...
    while i + window_size <= len(data):
        window = data[i:i + window_size]
        h = shannon_entropy(window)

        if h >= threshold:
            end = i + window_size
            while end + step <= len(data):
                next_window = data[
                    end - window_size + step:end + step
                ]
                next_h = shannon_entropy(next_window)
                if next_h < threshold:
                    break
                h = max(h, next_h)
                end += step

            regions.append((i, end, h))
            i = end
        else:
            i += step
```

When the entropy exceeds the threshold (default 7.2), the detector extends the region forward until entropy drops below the threshold. This merges adjacent high-entropy windows into a single region rather than reporting dozens of overlapping detections.

The default threshold of 7.2 is intentionally high. Network payloads containing binary protocol data or compressed content often hit 6.0-7.0, which would generate massive false positive volume. At 7.2, the detector primarily catches encrypted blobs, base64-encoded secrets, and random key material.

## File Extraction Pipeline

### The Extractor Protocol

All extractors implement a two-method protocol:

```python
class Extractor(Protocol):
    def extract(self, path: str) -> list[TextChunk]: ...

    @property
    def supported_extensions(self) -> frozenset[str]: ...
```

The `FileScanner` builds an extension-to-extractor map at initialization by iterating over all extractor instances and indexing by their supported extensions. When scanning a file, it looks up the extractor by the file's extension and calls `extract`.

### Plaintext Extraction

The `PlaintextExtractor` reads files in 500-line chunks to keep memory bounded:

```python
class PlaintextExtractor:
    def extract(self, path: str) -> list[TextChunk]:
        chunks: list[TextChunk] = []

        with open(
            path, encoding="utf-8", errors="replace",
        ) as f:
            lines: list[str] = []
            line_number = 1
            chunk_start = 1

            for line in f:
                lines.append(line)
                if len(lines) >= CHUNK_MAX_LINES:
                    chunks.append(
                        TextChunk(
                            text="".join(lines),
                            location=Location(
                                source_type="file",
                                uri=path,
                                line=chunk_start,
                            ),
                        )
                    )
                    chunk_start = line_number + 1
                    lines = []
                line_number += 1

            if lines:
                chunks.append(...)

        return chunks
```

Each `TextChunk` carries the starting line number in its `Location`, so findings can report where in the file the match occurred. The `errors="replace"` parameter means binary-contaminated text files (common in log files with embedded binary data) will not crash the extractor.

### Extension Map Construction

The `_build_extension_map` function in `file_scanner.py` constructs the mapping from extensions to extractors:

```python
def _build_extension_map() -> dict[str, Extractor]:
    extractors: list[Extractor] = [
        PlaintextExtractor(),
        PDFExtractor(),
        DocxExtractor(),
        XlsxExtractor(),
        XlsExtractor(),
        CsvExtractor(),
        JsonExtractor(),
        XmlExtractor(),
        YamlExtractor(),
        ParquetExtractor(),
        AvroExtractor(),
        ArchiveExtractor(),
        EmlExtractor(),
        MsgExtractor(),
    ]

    ext_map: dict[str, Extractor] = {}
    for extractor in extractors:
        for ext in extractor.supported_extensions:
            ext_map[ext] = extractor

    return ext_map
```

Adding a new format means creating an extractor class with `extract` and `supported_extensions`, then adding it to this list. The scanner does not need to know anything about the format.

### File Scanner Walk Logic

The `FileScanner._scan_directory` method applies a chain of filters before dispatching to an extractor:

```python
def _scan_directory(self, directory, result):
    iterator = (
        directory.rglob("*")
        if self._file_config.recursive
        else directory.glob("*")
    )

    for path in iterator:
        if not path.is_file():
            continue
        if self._is_excluded(path, directory):
            continue

        suffix = _get_full_suffix(path)
        if suffix not in self._allowed_extensions:
            continue

        file_size = path.stat().st_size
        if file_size > max_bytes:
            continue
        if file_size == 0:
            continue

        self._scan_file(path, result)
        result.targets_scanned += 1
```

The `_get_full_suffix` function handles compound extensions like `.tar.gz` and `.tar.bz2` by checking the filename suffix before falling back to `path.suffix.lower()`. The exclusion check matches against the relative path, the filename, and individual path components, so a pattern like `__pycache__` matches regardless of depth.

## Network Analysis

### Scanner Orchestration

The `NetworkScanner` ties together the network modules into a multi-pass pipeline. The old implementation decoded raw packets as UTF-8 and ran detection directly. The rewrite is protocol-aware:

```python
def _scan_pcap(self, path, result):
    tracker = FlowTracker()
    dns_detector = DnsExfilDetector(
        entropy_threshold=(
            self._net_config.dns_label_entropy_threshold
        ),
    )
    packet_count = 0

    for packet in read_pcap(
        path,
        max_packets=self._net_config.max_packets,
    ):
        packet_count += 1
        tracker.add_packet(packet)

        if (
            packet.protocol == "udp"
            and (
                packet.src_port == DNS_PORT
                or packet.dst_port == DNS_PORT
            )
        ):
            self._process_dns_packet(
                packet.payload, packet.src_ip,
                packet.dst_ip, path, packet_count,
                dns_detector, result,
            )

        if packet.payload:
            exfil_indicators = detect_base64_payload(
                packet.payload,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
            )
            for indicator in exfil_indicators:
                finding = _indicator_to_finding(
                    indicator, str(path), packet_count,
                )
                result.findings.append(finding)

    txt_indicators = dns_detector.check_txt_volume()
    for indicator in txt_indicators:
        ...

    self._scan_reassembled_flows(tracker, path, result)
```

Three things happen during the packet loop: every packet goes into the `FlowTracker` for later TCP reassembly, UDP packets on port 53 are parsed as DNS and fed to the `DnsExfilDetector`, and every payload is checked for base64/hex-encoded data by `detect_base64_payload`. After the loop, TXT query volume ratios are checked and TCP flows are reassembled for content scanning.

The reassembled flow scanning uses protocol-aware text extraction:

```python
def _extract_scannable_text(self, stream, protocol):
    if protocol == "http":
        return self._extract_http_text(stream)
    if protocol in ("tls", "ssh"):
        return ""
    try:
        return stream.decode("utf-8", errors="replace")
    except Exception:
        return ""
```

HTTP flows get parsed by `parse_http`, which extracts URIs, sensitive headers (`cookie`, `authorization`, `set-cookie`), and bodies. TLS and SSH flows are skipped entirely since the content is encrypted and cannot be scanned. Everything else falls through to a UTF-8 decode attempt.

DNS exfiltration indicators and encoded payload detections are converted to `Finding` objects through `_indicator_to_finding`, which maps indicator types to rule IDs via the `EXFIL_RULE_MAP` lookup table. Regex-based detections from reassembled flows go through `match_to_finding` like the other scanners.

### PCAP Parsing

The `read_pcap` function in `network/pcap.py` reads packets using dpkt and yields `PacketInfo` structs:

```python
def read_pcap(path, max_packets=0):
    with open(path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        count = 0
        for timestamp, buf in pcap:
            if max_packets > 0 and count >= max_packets:
                break

            packet = _parse_ethernet(timestamp, buf)
            if packet is not None:
                yield packet
                count += 1
```

The try/except fallback handles both PCAP (libpcap) and PCAPNG (Wireshark's newer format). dpkt is used instead of Scapy because it is roughly 100x faster for bulk packet parsing. Scapy constructs rich protocol objects with dissection layers; dpkt does minimal parsing and gives you raw bytes.

### TCP Flow Reassembly

The `FlowTracker` in `network/flow_tracker.py` groups packets into flows and reassembles TCP streams:

```python
def make_flow_key(packet):
    forward = (
        packet.src_ip, packet.dst_ip,
        packet.src_port, packet.dst_port,
    )
    reverse = (
        packet.dst_ip, packet.src_ip,
        packet.dst_port, packet.src_port,
    )
    return min(forward, reverse)
```

The bidirectional key is the lexicographically smaller of the forward and reverse 4-tuples. This means `(A->B)` and `(B->A)` packets land in the same flow. The `reassemble_stream` method sorts segments by TCP sequence number and deduplicates retransmissions:

```python
def reassemble_stream(self, key):
    flow = self._flows.get(key)
    if flow is None:
        return b""

    sorted_segments = sorted(
        flow.segments, key=lambda s: s[0]
    )

    seen_offsets: set[int] = set()
    parts: list[bytes] = []
    for seq, data in sorted_segments:
        if seq not in seen_offsets:
            seen_offsets.add(seq)
            parts.append(data)

    return b"".join(parts)
```

TCP retransmissions reuse the same sequence number, so deduplication by sequence number prevents duplicate data in the reassembled stream. This is a simplified reassembly that does not handle overlapping segments (where retransmissions contain different data), but it covers the common case.

### Protocol Identification

The `identify_protocol` function in `network/protocols.py` performs Deep Packet Inspection using byte prefix matching:

```python
def identify_protocol(payload: bytes) -> str:
    if not payload:
        return "unknown"

    if _is_http_request(payload):
        return "http"
    if payload.startswith(HTTP_RESPONSE_PREFIX):
        return "http"
    if (len(payload) > 2
            and payload[:2] == TLS_RECORD_PREFIX):
        return "tls"
    if payload.startswith(SSH_PREFIX):
        return "ssh"
    if payload.startswith(SMTP_BANNER_PREFIX):
        return "smtp"

    return "unknown"
```

HTTP requests are identified by checking if the first word before a space is a known HTTP method (`GET`, `POST`, `PUT`, etc.). TLS records start with `\x16\x03` (ContentType=Handshake + major version 3). SSH banners start with `SSH-`. SMTP server greetings start with `220`.

This matters for DLP because the same sensitive data requires different handling depending on the transport protocol. An SSN in an HTTP body can be read and flagged with high confidence. The same SSN in a TLS-encrypted stream cannot be read, but you can flag the flow as "encrypted traffic containing unknown data" and correlate with other signals.

### DNS Exfiltration Detection

The `DnsExfilDetector` in `network/exfiltration.py` analyzes DNS queries for patterns that suggest data tunneling:

```python
def _check_subdomain_entropy(self, name, src_ip, dst_ip):
    parts = name.split(".")
    if len(parts) < 3:
        return None

    subdomain = ".".join(parts[:-2])
    if not subdomain:
        return None

    entropy = shannon_entropy_str(subdomain)
    if entropy > self._entropy_threshold:
        return ExfilIndicator(
            indicator_type="dns_high_entropy",
            description=(
                f"High subdomain entropy ({entropy:.2f}) "
                f"suggesting DNS tunneling"
            ),
            confidence=min(
                0.95,
                0.50 + (entropy - 3.0) * 0.15,
            ),
            source_ip=src_ip,
            dst_ip=dst_ip,
            evidence=name,
        )
```

Legitimate subdomains (`www`, `mail`, `api`, `cdn`) have very low entropy. A query like `aGVsbG8gd29ybGQ.evil.com` has subdomain entropy above 4.0 because the base64-encoded data uses most of the alphanumeric character space. The detector extracts everything before the last two domain labels (the registerable domain), computes Shannon entropy, and flags queries above the threshold.

The confidence score scales linearly from 0.50 (at entropy 3.0) to 0.95 (at entropy 6.0). This captures the observation that higher entropy means more confident detection: entropy 4.1 might be a CDN hash, but entropy 5.5 is almost certainly encoded data.

## Compliance and Severity Classification

### Severity Mapping

The `score_to_severity` function in `compliance.py` maps confidence scores to severity levels using a threshold table:

```python
SEVERITY_SCORE_THRESHOLDS = [
    (0.85, "critical"),
    (0.65, "high"),
    (0.40, "medium"),
    (0.20, "low"),
]

def score_to_severity(score: float) -> Severity:
    for threshold, severity in SEVERITY_SCORE_THRESHOLDS:
        if score >= threshold:
            return severity
    return "low"
```

The thresholds are tuned so that:
- **Critical** (0.85+): checksum-validated matches with context keywords (e.g., SSN near "social security")
- **High** (0.65+): checksum-validated matches or strong context without validation
- **Medium** (0.40+): pattern matches without strong validation or context
- **Low** (0.20+): weak matches that might be false positives

### Framework Mapping

The `RULE_FRAMEWORK_MAP` in `compliance.py` is a static lookup table:

```python
RULE_FRAMEWORK_MAP = {
    "PII_SSN": ["HIPAA", "CCPA", "GLBA", "GDPR"],
    "PII_DRIVERS_LICENSE_FL": ["CCPA", "HIPAA"],
    "FIN_CREDIT_CARD_VISA": ["PCI_DSS", "GLBA"],
    "FIN_CREDIT_CARD_MC": ["PCI_DSS", "GLBA"],
    "FIN_IBAN": ["GDPR", "GLBA"],
    "HEALTH_NPI": ["HIPAA"],
    "NET_DNS_EXFIL_HIGH_ENTROPY": [],
    ...
}
```

Rule IDs match actual detection rules rather than using generic categories. Credit card rules are split by brand (`FIN_CREDIT_CARD_VISA`, `FIN_CREDIT_CARD_MC`, `FIN_CREDIT_CARD_AMEX`, `FIN_CREDIT_CARD_DISC`), each triggering PCI-DSS and GLBA. State-specific driver's license rules (`PII_DRIVERS_LICENSE_FL`, `PII_DRIVERS_LICENSE_IL`) map to CCPA and HIPAA alongside the generic CA pattern. Network exfiltration indicators (`NET_DNS_EXFIL_*`, `NET_ENCODED_*`) carry empty framework lists since DNS tunneling is a detection concern, not a regulatory data type.

SSNs trigger four frameworks because they are considered protected health information (HIPAA), personal information (CCPA), financial identifiers (GLBA), and personal data (GDPR). Every rule also has a corresponding entry in `RULE_REMEDIATION_MAP` with specific guidance text. Unknown rules fall back to a generic default.

The mapping is intentionally conservative. An SSN could trigger SOX if it appears in financial reporting data, but without business context the scanner cannot determine that. The listed frameworks are the ones where the mere presence of the data type creates a compliance obligation.

## Shared Scoring Module

The `match_to_finding` function in `scoring.py` centralizes the conversion from `DetectorMatch` to `Finding`. All three scanners import from this single location instead of duplicating the severity/compliance/redaction logic:

```python
def match_to_finding(
    match: DetectorMatch,
    text: str,
    location: Location,
    redaction_style: RedactionStyle,
) -> Finding:
    severity = score_to_severity(match.score)
    frameworks = get_frameworks_for_rule(match.rule_id)
    if match.compliance_frameworks:
        combined = (
            set(frameworks) | set(match.compliance_frameworks)
        )
        frameworks = sorted(combined)
    remediation = get_remediation_for_rule(match.rule_id)

    snippet = redact(
        text, match.start, match.end,
        style=redaction_style,
    )

    return Finding(
        rule_id=match.rule_id,
        rule_name=match.rule_name,
        severity=severity,
        confidence=match.score,
        location=location,
        redacted_snippet=snippet,
        compliance_frameworks=frameworks,
        remediation=remediation,
    )
```

The function chains severity classification, compliance framework lookup, remediation guidance, and redaction in one call. The framework merging logic handles the case where a detection rule carries its own `compliance_frameworks` list: those are merged with the frameworks from the compliance module, deduplicated, and sorted for deterministic output.

Each scanner calls this in its match loop:

```python
for match in matches:
    if match.score < min_confidence:
        continue

    finding = match_to_finding(
        match, chunk.text, chunk.location,
        self._redaction_style,
    )
    result.findings.append(finding)
```

Adding a new compliance framework or changing severity thresholds affects all three scanners uniformly without touching scanner code.

## Redaction

The `redact` function in `redaction.py` builds a snippet with masked content:

```python
def redact(text, start, end, style="partial"):
    matched = text[start:end]

    if style == "none":
        return _build_snippet(text, start, end, matched)
    if style == "full":
        return _build_snippet(
            text, start, end, REDACTED_LABEL
        )

    redacted = _partial_redact(matched)
    return _build_snippet(text, start, end, redacted)
```

The `_partial_redact` function applies format-aware masking:

```python
def _partial_redact(value):
    stripped = value.replace("-", "").replace(" ", "")

    if len(stripped) >= 9 and stripped.isdigit():
        return MASK_CHAR * (len(value) - 4) + value[-4:]

    if "@" in value:
        local, domain = value.rsplit("@", maxsplit=1)
        masked_local = (
            local[0] + MASK_CHAR * (len(local) - 1)
        )
        return f"{masked_local}@{domain}"

    if len(value) > 8:
        visible = max(4, len(value) // 4)
        return (
            MASK_CHAR * (len(value) - visible)
            + value[-visible:]
        )

    return MASK_CHAR * len(value)
```

For digit sequences (SSNs, credit cards), it preserves the last 4 digits: `***-**-6789`. For emails, it keeps the first character and domain: `j****@example.com`. For other strings (API keys, tokens), it shows the last 25%. Short values under 8 characters are fully masked.

The `_build_snippet` function adds 20 characters of context on each side and prepends/appends `...` when the context is truncated. This gives analysts enough surrounding text to understand what the data was near without exposing full document contents.

## CLI Integration

### Global Option Propagation

The Typer callback stores global options in Click's context dict:

```python
@app.callback()
def main(ctx: typer.Context, config: ..., verbose: ..., version: ...):
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose
```

Subcommands retrieve these via `ctx.ensure_object(dict)`:

```python
def _run_scan(ctx, scan_type, target, output_format, output_file):
    obj: dict[str, Any] = ctx.ensure_object(dict)
    config_path = obj.get("config_path", "")
    verbose = obj.get("verbose", False)
```

This pattern lets `dlp-scan -v -c custom.yml file ./data` propagate the verbose flag and config path to the file scan command without duplicating those options on every subcommand.

### Logging Strategy

The logging level adapts to the output format:

```python
if verbose:
    configure_logging(level="DEBUG")
elif output_format == "console":
    configure_logging(level="INFO")
else:
    configure_logging(level="WARNING")
```

When output is machine-readable (JSON, SARIF, CSV), logging is set to WARNING so that structlog messages written to stderr do not contaminate stdout. This prevents `dlp-scan file ./data -f json | jq` from breaking because log lines mixed into the JSON output. For console output, INFO-level logging provides progress feedback. Verbose mode enables DEBUG for troubleshooting.

### Report Conversion

The `report convert` command reads a JSON scan result and regenerates it in another format:

```python
@report_app.command("convert")
def convert(input_file, output_format="sarif", output_file=""):
    raw = path.read_bytes()
    data = orjson.loads(raw)
    result = _rebuild_result(data)

    config = ScanConfig()
    engine = ScanEngine(config)

    output = engine.generate_report(result, fmt)
    ...
```

The `_rebuild_result` function deserializes the JSON structure back into `ScanResult`, `Finding`, and `Location` objects. It reads from the `scan_metadata` section for scan-level fields and iterates `findings` to reconstruct each `Finding` with its `Location`. This is necessary because `orjson.loads` produces plain dicts, but the reporters expect typed dataclass instances.

## Testing Strategy

### Property-Based Testing

The project uses Hypothesis for property-based testing of detection rules. Instead of testing a few known inputs, Hypothesis generates random strings constrained by rule formats and verifies that the detection pipeline handles them correctly.

For validators: Hypothesis generates random digit sequences and verifies that `luhn_check`, `iban_check`, and `nhs_check` only return True for inputs that satisfy the mathematical properties (divisibility by 10, mod 97 = 1, mod 11 check digit match).

For the context boost: Hypothesis generates random text with embedded keywords at varying distances and verifies that the boost is always between 0 and `CONTEXT_BOOST_MAX`, and that closer keywords produce higher boosts.

### Running Tests

```bash
uv run pytest -m unit              # fast unit tests
uv run pytest -m integration       # tests with file I/O
uv run pytest --cov=src            # coverage report
```

The test suite uses markers (`unit`, `integration`, `slow`) to separate fast tests from those requiring real filesystem access. The `conftest.py` provides shared fixtures for temporary directories, sample configs, and test data files.

## Dependencies

- **typer**: CLI framework with type-hint argument declaration. The `Annotated` style avoids decorators stacking up.
- **rich**: Terminal tables with colors. Used by `ConsoleReporter` for severity-colored output.
- **structlog**: Structured logging with stdlib integration. JSON or console rendering based on config.
- **pydantic**: Config validation. Catches invalid YAML values before the scan starts.
- **orjson**: Fast JSON serialization. 3-10x faster than stdlib json for large finding lists.
- **ruamel.yaml**: YAML parser that handles 1.2 spec and preserves comments.
- **dpkt**: PCAP parsing. ~100x faster than Scapy for bulk packet iteration.
- **pymupdf**: PDF text extraction with layout preservation.
- **python-docx/openpyxl/xlrd**: Office format extraction.
- **defusedxml/lxml**: Safe XML parsing (defusedxml blocks XXE attacks).
- **pyarrow/fastavro**: Columnar format extraction (Parquet, Avro).
- **asyncpg/aiomysql/pymongo/aiosqlite**: Async database drivers.

## Next Steps

You have seen how the code works. Now:
1. Try the challenges in [04-CHALLENGES.md](./04-CHALLENGES.md) for extension ideas
2. Modify a detection rule and run the tests to see how the scoring changes
3. Scan your own files with `dlp-scan file ./your-directory` and inspect the output
