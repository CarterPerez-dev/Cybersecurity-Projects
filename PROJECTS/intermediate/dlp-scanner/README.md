```ruby
██████╗ ██╗     ██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║     ██╔══██╗      ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║██║     ██████╔╝█████╗███████╗██║     ███████║██╔██╗ ██║
██║  ██║██║     ██╔═══╝ ╚════╝╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝███████╗██║           ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝ ╚══════╝╚═╝           ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-intermediate-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/dlp-scanner)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Data Loss Prevention scanner for files, databases, and network traffic.

*This is a quick overview. Security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Scans files (PDF, DOCX, XLSX, CSV, JSON, XML, YAML, Parquet, Avro, archives, emails) for PII, credentials, financial data, and PHI
- Scans databases (PostgreSQL, MySQL, MongoDB, SQLite) with schema introspection and sampling
- Scans network captures (PCAP/PCAPNG) with protocol parsing, TCP reassembly, and DNS exfiltration detection
- Confidence scoring pipeline: regex match, checksum validation (Luhn, Mod-97, Mod-11), context keyword proximity, entity co-occurrence
- Maps findings to compliance frameworks (HIPAA, PCI-DSS, GDPR, CCPA, SOX, GLBA, FERPA)
- Reports in console (Rich tables), JSON, SARIF 2.1.0, or CSV

## Quick Start

```bash
bash install.sh
dlp-scan file ./data
```

## Usage

```bash
dlp-scan file ./data/employees/              # scan a directory
dlp-scan file ./report.pdf -f json           # scan a file, JSON output
dlp-scan db postgres://user:pass@host/db     # scan PostgreSQL
dlp-scan db sqlite:///path/to/local.db       # scan SQLite
dlp-scan network capture.pcap               # scan network traffic
dlp-scan file ./data -f sarif -o results.sarif  # SARIF for CI/CD
dlp-scan report convert results.json -f csv  # convert report format
dlp-scan report summary results.json         # print summary stats
```

### Global Options

```
--config, -c    Path to YAML config file
--verbose, -v   Enable debug logging
--version       Show version
```

### Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Console | `-f console` | Interactive review with Rich tables |
| JSON | `-f json` | Structured analysis and archival |
| SARIF | `-f sarif` | GitHub code scanning, CI/CD integration |
| CSV | `-f csv` | Compliance team export, spreadsheet import |

## Stack

**Language:** Python 3.12+

**CLI:** Typer 0.15+ with Rich integration

**Detection:** Regex + checksum validators + Shannon entropy + context keyword scoring

**File Formats:** PyMuPDF, python-docx, openpyxl, xlrd, defusedxml, lxml, pyarrow, fastavro, extract-msg

**Databases:** asyncpg (PostgreSQL), aiomysql (MySQL), pymongo async (MongoDB), aiosqlite (SQLite)

**Network:** dpkt (PCAP parsing), TCP reassembly, DPI protocol identification, DNS exfiltration heuristics

**Config:** Pydantic 2.10+ models with YAML config loading (ruamel.yaml)

**Quality:** ruff, mypy (strict), yapf, pytest + hypothesis, structlog

## Configuration

Copy `.dlp-scanner.yml` to your project root and customize. Key settings:

```yaml
detection:
  min_confidence: 0.20        # minimum score to report
  enable_rules: ["*"]         # glob patterns for rule IDs
  allowlists:
    values: ["123-45-6789"]   # suppress known test values

output:
  format: "console"           # console, json, sarif, csv
  redaction_style: "partial"  # partial, full, none
```

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | DLP theory and real-world breaches |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0)
