# 04-CHALLENGES.md

# Extension Challenges

You have built a DLP scanner with file, database, and network scanning, a confidence scoring pipeline, compliance mapping, and multi-format reporting. These challenges extend it into new territory.

Ordered by difficulty. The easy ones take an hour or two. The advanced ones are multi-day efforts that teach you skills used in production DLP systems.

## Easy Challenges

### Challenge 1: Add a New PII Rule (Date of Birth)

**What to build:** A detection rule for dates of birth in common formats: `MM/DD/YYYY`, `YYYY-MM-DD`, `DD-Mon-YYYY`.

**Why it matters:** Date of birth is classified as PHI under HIPAA's 18 identifiers and as personal data under GDPR. The 2015 Anthem breach exposed 78.8 million records including DOBs, and the combination of DOB + name + zip code is enough to uniquely identify 87% of the US population (Latanya Sweeney's research at Carnegie Mellon).

**What you will learn:**
- Writing regex patterns that match multiple date formats
- Adding a validation function that rejects impossible dates (month 13, day 32, Feb 30)
- Tuning base_score relative to false positive rate (dates appear everywhere)

**Hints:**
- Create the rule in a new file `detectors/rules/pii_extended.py` and add the rules list to `ALL_RULES` in `registry.py`
- Use a low base_score (0.10-0.15) because date strings are extremely common
- Context keywords like "date of birth", "dob", "birthday", "born on" should provide the majority of the signal
- The validator should parse the matched string into a real date and reject invalid ones
- Add the rule to `RULE_FRAMEWORK_MAP` in `compliance.py` with HIPAA and GDPR

**Test it works:** Create a text file with "Patient DOB: 03/15/1987" and "Order date: 03/15/1987". The first should score higher than the second due to context keywords.

### Challenge 2: HTML Report Output

**What to build:** A new reporter that generates a standalone HTML file with a sortable findings table, severity color coding, and a summary chart.

**Why it matters:** Compliance teams often need to share scan results with non-technical stakeholders who do not have command-line tools. An HTML report that opens in a browser is more accessible than JSON or CSV.

**What you will learn:**
- Implementing the reporter pattern (match the existing protocol)
- HTML template generation in Python (string templates or Jinja2)
- Adding a new output format to the CLI without modifying existing code

**Hints:**
- Create `reporters/html_report.py` with a `HtmlReporter` class
- Add `"html"` to `REPORTER_MAP` in `engine.py` and `VALID_FORMATS` in `commands/scan.py`
- Use inline CSS so the report is a single self-contained HTML file with no external dependencies
- Color severity levels using the same scheme as the console reporter (red for critical, yellow for medium, green for low)
- Include a summary section at the top with counts by severity and framework

**Test it works:** Run `dlp-scan file ./data -f html -o report.html` and open the file in a browser. The table should be sortable by clicking column headers (add minimal JavaScript for this).

### Challenge 3: Allowlist by File Path Pattern

**What to build:** Extend the allowlist system to suppress findings from files matching glob patterns. Currently, `allowlists.file_patterns` exists in the config but is not enforced during scanning.

**Why it matters:** Test fixtures, mock data, and seed files intentionally contain fake PII. Teams waste hours triaging findings from `tests/fixtures/sample_data.csv` that contain test credit card numbers. Path-based allowlisting eliminates this noise.

**What you will learn:**
- Connecting config to scan-time behavior
- Glob pattern matching with `fnmatch`
- The difference between value-level and file-level suppression

**Hints:**
- The `AllowlistConfig.file_patterns` field already exists in `config.py`
- Add the check in `FileScanner._scan_file` before running detection, or in `_scan_directory` before scanning the file
- Match against the relative path from the scan target, not the absolute path
- Patterns like `test_*`, `*_fixture*`, and `mock_*` should match filenames

**Test it works:** Create a file `test_data.txt` with a valid SSN. Scan with `file_patterns: ["test_*"]` in config. The SSN should not appear in results.

## Intermediate Challenges

### Challenge 4: Incremental Scanning with Hash Cache

**What to build:** A scan cache that stores SHA-256 hashes of scanned files and skips unchanged files on subsequent scans.

**Why it matters:** Large codebases and file shares contain millions of files. Re-scanning unchanged files wastes time. Symantec DLP and Microsoft Purview both use content hashing to skip unchanged files, reducing scan time by 60-90% on repeated scans.

**What you will learn:**
- Content-addressable caching strategies
- SQLite as an embedded metadata store
- Cache invalidation (the hardest problem in computer science, and one you actually have to solve)

**Implementation approach:**

1. **Create `cache.py`** with a `ScanCache` class backed by SQLite
   - Table: `(file_path TEXT, content_hash TEXT, scan_time TEXT, finding_count INTEGER)`
   - Hash computation: SHA-256 of file contents
   - Lookup: if the file exists in cache with the same hash, skip scanning and load cached finding count

2. **Integrate with `FileScanner`**
   - Before extracting text, check the cache
   - After scanning, store the hash and finding count
   - Add `--no-cache` flag to force full rescan

3. **Handle invalidation edge cases:**
   - What if detection rules change between scans? (The same file might produce different findings with new rules)
   - What if the config changes min_confidence? (Previously-suppressed findings might now be reportable)
   - What if a file is deleted? (Stale cache entries should not appear in results)

**Hints:**
- Store a hash of the active rule set and config in the cache. If either changes, invalidate the entire cache
- Use `aiosqlite` to match the async pattern of the database scanner, or use synchronous sqlite3 since file scanning is already synchronous
- The cache file should live next to the config: `.dlp-scanner-cache.db`

**Extra credit:** Add `dlp-scan cache stats` and `dlp-scan cache clear` subcommands.

### Challenge 5: Severity Override by Compliance Framework

**What to build:** A config option that overrides severity based on compliance framework requirements. For example, any PCI-DSS finding should be at least "high" regardless of confidence score, because PCI-DSS does not have a concept of "low severity" unencrypted card data.

**Why it matters:** Different compliance frameworks have different severity thresholds. GDPR treats unencrypted email addresses as medium priority for remediation, but PCI-DSS treats any unencrypted PAN as a blocking finding. Production DLP tools let compliance teams configure per-framework severity floors.

**What you will learn:**
- Adding config-driven behavior to the scoring pipeline
- The tension between confidence-based and policy-based severity
- How production DLP tools balance detection accuracy with compliance requirements

**Implementation approach:**

1. **Add to config:**
   ```yaml
   compliance:
     severity_overrides:
       PCI_DSS: "high"
       HIPAA: "medium"
   ```

2. **Apply after scoring:** In the `_match_to_finding` function (or equivalent), after computing severity from confidence, check if any of the finding's compliance frameworks have a severity floor, and upgrade if necessary

3. **Preserve original confidence:** The confidence score should not change. Only the severity classification changes. This lets analysts see that a finding scored 0.35 (normally "low") but was elevated to "high" because of PCI-DSS policy

**Hints:**
- Add `severity_overrides: dict[str, str]` to `ComplianceConfig` in `config.py`
- Use `SEVERITY_ORDER` from `constants.py` to compare severity levels numerically
- Log when a severity is overridden so analysts understand why a low-confidence finding shows up as high severity

### Challenge 6: Database Column Name Heuristic Scoring

**What to build:** A pre-scan heuristic that boosts detection confidence for columns whose names suggest sensitive data (e.g., `ssn`, `credit_card_number`, `patient_dob`).

**Why it matters:** Database schema names are strong metadata signals. A column named `ssn` in a table named `employees` is almost certainly storing Social Security Numbers, even before you look at the data. The Capital One breach investigation found that the compromised S3 bucket contained CSV exports with column headers like `SSN` and `AccountNumber`, which would have been trivially detectable with column-name analysis.

**What you will learn:**
- Schema introspection as a detection signal
- Combining metadata and content signals
- How production DLP tools use schema analysis to prioritize scanning

**Implementation approach:**

1. **Create a column name classifier** with patterns mapping column names to rule IDs:
   ```
   *ssn*, *social_sec* -> PII_SSN
   *credit_card*, *card_num*, *pan* -> FIN_CREDIT_CARD
   *email*, *e_mail* -> PII_EMAIL
   *dob*, *date_of_birth*, *birthday* -> PII_DOB
   ```

2. **Apply as a context boost** in the database scanner: when a column name matches a pattern, add a pre-boost to the base score before running the normal detection pipeline

3. **Carry through to findings:** Add the column name match as additional evidence in the finding's metadata

**Hints:**
- Implement this in `scanners/db_scanner.py` before the detection loop
- Use `fnmatch` for column name pattern matching (same as rule filtering)
- A modest boost (+0.15 to +0.25) is appropriate. Column names are strong signals but not definitive (a column named `ssn_backup_old` might be empty or encrypted)

## Advanced Challenges

### Challenge 7: Custom Rule Language

**What to build:** A YAML-based rule definition format that lets users create detection rules without writing Python. Rules should support regex patterns, base scores, context keywords, and compliance framework tags.

**Why it matters:** Production DLP tools (Symantec DLP, Netskope) let compliance teams define custom rules through policy editors because not every regulated data type is covered by built-in rules. European IBANs, Brazilian CPFs, Indian Aadhaar numbers, and industry-specific identifiers all need custom patterns.

**What you will learn:**
- DSL design (keeping it simple enough to be useful, complex enough to be powerful)
- Safe regex compilation (preventing ReDoS)
- Hot reloading user-defined rules

**Implementation approach:**

1. **Define the rule schema:**
   ```yaml
   rules:
     - id: CUSTOM_BR_CPF
       name: "Brazilian CPF Number"
       pattern: '\b\d{3}\.\d{3}\.\d{3}-\d{2}\b'
       base_score: 0.40
       context_keywords: ["cpf", "cadastro"]
       compliance: ["LGPD"]
       validator: "mod11"
   ```

2. **Build a rule loader** that reads YAML files from a `rules/` directory, compiles regex patterns safely (with timeout protection against catastrophic backtracking), and creates `DetectionRule` objects

3. **Register custom rules** alongside built-in rules in the `DetectorRegistry`

4. **Add built-in validator references** (mod11, luhn, mod97) that users can reference by name instead of writing Python

**Gotchas:**
- Regex compilation must be safe: a user-provided pattern like `(a+)+b` causes catastrophic backtracking. Consider using the `regex` library with timeout, or validate patterns against known ReDoS patterns
- Custom rules should not be able to override or shadow built-in rules. Use ID prefixes (`CUSTOM_`) to namespace them
- Validator functions referenced by name need a registry of their own

### Challenge 8: Real-Time File Monitoring

**What to build:** A watch mode that monitors directories for file changes using filesystem events and scans new or modified files automatically.

**Why it matters:** Batch scanning finds problems after the fact. Real-time monitoring catches sensitive data as soon as it hits disk. This is how endpoint DLP agents (CrowdStrike Falcon DLP, Digital Guardian) work: they hook filesystem events and scan in real time.

**What you will learn:**
- Filesystem event monitoring with `watchdog` or `inotify`
- Event debouncing (a single file save can trigger multiple events)
- Background scanning without blocking the event loop

**Architecture changes:**

```
┌──────────────────────────────┐
│  FileSystemEventHandler       │
│  (watchdog or inotify)        │
│                               │
│  on_modified -> debounce      │
│  on_created  -> scan_file     │
│  on_moved    -> scan_dest     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  ScanQueue (asyncio.Queue)    │
│                               │
│  Dedup by path               │
│  Rate limit scanning          │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  FileScanner.scan(file)       │
│  → Finding → Alert            │
└──────────────────────────────┘
```

**Implementation steps:**

1. Add `watchdog` as a dependency
2. Create `commands/watch.py` with a `dlp-scan watch ./directory` command
3. Implement a debouncer that batches filesystem events within a 500ms window
4. Use the existing `FileScanner._scan_file` for individual file scanning
5. Output findings to console in real time (stream mode, not batch)

**Gotchas:**
- Editor save operations often create temporary files, write to them, then rename. This generates create, modify, and rename events. You need to scan the final file, not the intermediate temp files
- Large file copies trigger `on_modified` repeatedly as data is written. Debounce by waiting until the file size stabilizes
- The watch mode should respect the same exclude patterns and extension filters as batch scanning

### Challenge 9: SIEM Integration via Syslog

**What to build:** A reporter that sends findings to a SIEM (Splunk, Elastic, QRadar) via syslog (RFC 5424) or HTTP Event Collector (Splunk HEC).

**Why it matters:** DLP findings are useless if they sit in a JSON file that nobody reads. Production DLP deployments send alerts to SIEMs where SOC analysts triage them alongside firewall logs, EDR alerts, and authentication events. Correlating a DLP finding with a VPN login from an unusual location turns a medium-severity alert into an incident.

**What you will learn:**
- Syslog protocol formatting (RFC 5424 structured data)
- HTTP-based log shipping (Splunk HEC, Elastic Ingest)
- Alert fatigue management (batching, deduplication, severity filtering)

**Implementation approach:**

1. **Create `reporters/syslog_reporter.py`** that formats findings as RFC 5424 syslog messages:
   ```
   <134>1 2026-04-08T10:30:00Z scanner dlp-scan - -
   [finding@dlp rule_id="PII_SSN" severity="critical"
   confidence="0.92" uri="employees.csv"] SSN detected
   ```

2. **Add Splunk HEC support** as an alternative transport: POST JSON payloads to `https://splunk:8088/services/collector/event` with an HEC token

3. **Add config:**
   ```yaml
   output:
     siem:
       type: "syslog"        # or "splunk_hec"
       host: "siem.corp.com"
       port: 514
       protocol: "tcp"       # or "udp"
       hec_token: ""         # for Splunk HEC
   ```

4. **Implement batching:** Send findings in batches of 50 with a 5-second flush interval to avoid overwhelming the SIEM

## Expert Challenges

### Challenge 10: Machine Learning False Positive Reduction

**What to build:** A feedback loop where analysts can mark findings as true positive or false positive, and a classifier learns to suppress likely false positives on future scans.

**Why it matters:** The single biggest complaint about DLP tools is false positive volume. Symantec DLP deployments commonly see 40-60% false positive rates on initial rollout. Analysts spend hours dismissing findings that match SSN patterns but are actually serial numbers, batch IDs, or zip+4 codes. A classifier trained on analyst feedback can reduce false positives by 70-80% while maintaining detection recall.

**What you will learn:**
- Feature engineering from detection signals (confidence, context keywords found, rule type, file type, surrounding text patterns)
- Online learning: updating a model as new feedback arrives without retraining from scratch
- The precision-recall tradeoff in security tooling (a false negative is a missed breach; a false positive is analyst fatigue)

**Implementation phases:**

**Phase 1: Feedback Collection**
- Add `dlp-scan feedback <finding_id> --true-positive` and `--false-positive` commands
- Store feedback in a SQLite database: `(finding_id, rule_id, features_json, label, timestamp)`
- Extract features: confidence, rule_id, file extension, context keywords matched, co-occurrence count, surrounding text entropy

**Phase 2: Classifier**
- Train a logistic regression or gradient boosted tree on accumulated feedback
- Features: one-hot encode rule_id, numeric confidence, boolean context_found, file_extension category
- Use scikit-learn with ONNX export for deployment without the full sklearn dependency

**Phase 3: Integration**
- After the detection pipeline produces matches, run the classifier as a post-filter
- Matches classified as likely false positives get demoted (severity lowered, or moved to a "suppressed" section)
- Never fully suppress a detection. Always show suppressed findings in a separate section so analysts can audit the classifier

**Success criteria:**
- [ ] Feedback collection works and stores features
- [ ] Classifier trains on 50+ labeled examples
- [ ] False positive rate drops by at least 30% on held-out test set
- [ ] No true positives are fully suppressed (only demoted)
- [ ] Model retrains automatically when feedback count crosses thresholds (100, 500, 1000)

## Real-World Integration Challenges

### Integrate with GitHub Code Scanning

**The goal:** Upload SARIF output to GitHub Code Scanning so DLP findings appear as annotations on pull requests.

**What you will learn:**
- GitHub Code Scanning API
- SARIF upload via GitHub Actions
- CI/CD pipeline integration for security tooling

**Steps:**

1. Create a GitHub Actions workflow that runs `dlp-scan file . -f sarif -o results.sarif` on pull requests
2. Upload the SARIF file using the `github/codeql-action/upload-sarif` action
3. Configure `on: pull_request` to scan only changed files (use `git diff --name-only` to get the list)
4. Set severity filtering so only high/critical findings block the PR

### Scan AWS S3 Buckets

**The goal:** Add an S3 scanner that lists objects in a bucket, downloads them to a temp directory, and scans with the existing file scanner.

**What you will learn:**
- boto3 integration for S3 object listing and download
- Temporary file management for large object scanning
- Credential handling (IAM roles vs. access keys)

**Steps:**

1. Add `dlp-scan s3 s3://bucket-name/prefix` command
2. Use boto3 to list objects, filter by extension
3. Download each object to a temp directory (use `tempfile.mkdtemp`)
4. Scan with `FileScanner` and map findings back to S3 URIs
5. Clean up temp files after scanning

This directly addresses the Capital One breach scenario: unencrypted PII in S3 buckets that nobody knew existed.

## Performance Challenge

### Handle 1 Million Files

**The goal:** Make the file scanner handle a directory with 1 million files without running out of memory or taking more than an hour.

**Current bottleneck:** `Path.rglob("*")` generates a list of all files before scanning starts. With 1 million files, this consumes significant memory and delays the first scan result.

**Optimization approaches:**

**Approach 1: Streaming directory walk**
- Replace `rglob` with `os.scandir` recursive walk that yields files one at a time
- Process and discard each file before reading the next
- Memory stays constant regardless of directory size

**Approach 2: Parallel extraction**
- Use `concurrent.futures.ThreadPoolExecutor` for I/O-bound extraction (file reads, PDF parsing)
- Use `concurrent.futures.ProcessPoolExecutor` for CPU-bound detection (regex matching on large texts)
- Tune pool sizes based on profiling

**Approach 3: Prioritized scanning**
- Scan high-risk extensions first (`.csv`, `.xlsx`, `.sql`) before low-risk ones (`.log`, `.txt`)
- Report findings as they are discovered (streaming output) instead of waiting for the full scan to complete

**Benchmark it:**

```bash
time dlp-scan file /large-directory -f json -o results.json
```

Target: under 60 minutes for 1 million files with an average file size of 10KB.

## Challenge Completion

Track your progress:

- [ ] Easy 1: Date of Birth Rule
- [ ] Easy 2: HTML Report Output
- [ ] Easy 3: Allowlist by File Path
- [ ] Intermediate 4: Incremental Scanning
- [ ] Intermediate 5: Severity Override
- [ ] Intermediate 6: Column Name Heuristic
- [ ] Advanced 7: Custom Rule Language
- [ ] Advanced 8: Real-Time Monitoring
- [ ] Advanced 9: SIEM Integration
- [ ] Expert 10: ML False Positive Reduction
- [ ] Integration: GitHub Code Scanning
- [ ] Integration: S3 Bucket Scanning
- [ ] Performance: 1 Million Files

## Study Real Implementations

Compare your work to production DLP tools:

- **Nightfall AI**: Cloud-native DLP with ML-based detection. Open-sourced their detection patterns. Look at how they handle multi-format extraction
- **truffleHog**: Focuses on credential detection in git repos. Their entropy-based detection and regex patterns for API keys are similar to this project's credential rules
- **detect-secrets**: Yelp's secret scanner. Compare their plugin architecture to the detector registry pattern in this project
- **Microsoft Purview**: Enterprise DLP with 300+ built-in sensitive information types. Their documentation on exact data match (EDM) and trainable classifiers shows where the field is heading
