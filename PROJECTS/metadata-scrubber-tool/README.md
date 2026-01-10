# 🔒 Metadata Scrubber

A privacy-focused CLI tool that removes sensitive metadata from files. Supports images, PDFs, and Microsoft Office documents. Perfect for protecting your privacy before sharing files online.

[![Tests](https://github.com/Heritage-XioN/metadata-scrubber-tool/actions/workflows/test.yml/badge.svg)](https://github.com/Heritage-XioN/metadata-scrubber-tool/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## ✨ Features

- **Multi-format support** - Images (JPEG, PNG), PDFs, and Office docs (Word, Excel, PowerPoint)
- **Concurrent processing** - Process 1000+ files efficiently with ThreadPoolExecutor
- **Dry-run mode** - Preview what would be scrubbed without making changes
- **Verification reports** - Before/after comparison to confirm removal
- **Smart format detection** - Uses library-level format detection, not just file extensions
- **Beautiful CLI** - Rich progress bars and formatted output
- **Privacy-first** - Removes GPS coordinates, author info, timestamps, camera data

## 📁 Supported Formats

| Category | Extensions | Metadata Removed |
|----------|------------|------------------|
| **Images** | `.jpg`, `.jpeg`, `.png` | EXIF, GPS, camera info, timestamps |
| **PDF** | `.pdf` | Author, creator, producer, dates |
| **Word** | `.docx` | Author, title, comments, keywords |
| **Excel** | `.xlsx`, `.xlsm`, `.xltx`, `.xltm` | Author, title, company, comments |
| **PowerPoint** | `.pptx`, `.pptm`, `.potx`, `.potm` | Author, title, comments, keywords |

## 🚀 Quick Start

### Installation

```bash
# Using uv (recommended)
uv pip install metadata-scrubber

# Or clone and install locally
git clone https://github.com/Heritage-XioN/metadata-scrubber-tool.git
cd metadata-scrubber-tool
uv sync
```

### Basic Usage

```bash
# Read metadata from a file
mst read document.pdf

# Scrub metadata and save to output folder
mst scrub photo.jpg --output ./cleaned

# Batch process entire folder
mst scrub ./documents -r -ext docx --output ./cleaned

# Verify removal
mst verify original.jpg ./cleaned/processed_original.jpg
```

## 📖 Commands

### `mst read` - View Metadata

Extract and display all embedded metadata from a file.

```bash
mst read photo.jpg                      # Single file
mst read report.pdf                     # PDF file
mst read ./docs -r -ext docx            # All Word docs recursively
```

**Example output:**
```
╭────────────────── Metadata Report ──────────────────╮
│ ╭────────────────────┬────────────────────────────╮ │
│ │ Property           │ Value                      │ │
│ ├────────────────────┼────────────────────────────┤ │
│ │ 📷 Camera          │                            │ │
│ │   Make             │ Canon                      │ │
│ │   Model            │ Canon EOS 80D              │ │
│ │   Software         │ Adobe Photoshop            │ │
│ ├────────────────────┼────────────────────────────┤ │
│ │ 📍 GPS             │                            │ │
│ │   GPSLatitude      │ 40.7128                    │ │
│ │   GPSLongitude     │ -74.0060                   │ │
│ ├────────────────────┼────────────────────────────┤ │
│ │ 📅 Dates           │                            │ │
│ │   DateTimeOriginal │ 2024:01:15 14:30:00        │ │
│ │   created          │ 2024-01-15 14:30:00        │ │
│ ╰────────────────────┴────────────────────────────╯ │
╰─────────────────────────────────────────────────────╯
```

---

### `mst scrub` - Remove Metadata

Remove sensitive metadata from files and save cleaned copies.

```bash
mst scrub photo.jpg --output ./out      # Single file
mst scrub ./photos -r -ext jpg -o ./out # All JPEGs in directory
mst scrub ./docs -r -ext pdf --dry-run  # Preview without changes
mst scrub ./files -r -ext xlsx -w 8     # 8 concurrent workers
```

**Example output:**
```
Processing 42 files with 4 workers...

⠸ Scrubbing metadata... ━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 42/42 0:00:12

╭───────────────────── Summary ─────────────────────╮
│ ✅ Processed: 42                                  │
│ ❌ Failed:    0                                   │
│ 📁 Output:    C:\Users\...\cleaned                │
╰───────────────────────────────────────────────────╯
```

**Dry-run example:**
```bash
mst scrub ./photos -r -ext jpg --dry-run
```
```
🔍 DRY-RUN MODE - No files will be modified

Would process 15 files:
  • photo1.jpg → processed_photo1.jpg
  • photo2.jpg → processed_photo2.jpg
  • vacation/beach.jpg → processed_beach.jpg
  ...
```

---

### `mst verify` - Verify Metadata Removal

Compare original and processed files to confirm sensitive data was removed.

```bash
mst verify original.jpg ./out/processed_original.jpg
```

**Example output:**
```
Comparing: test_canon.jpg → processed_test_canon.jpg

                          Verification Report                          
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Property                ┃ Before                   ┃ After          ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ Make                    │ Canon                    │ ✅ Removed     │
│ Model                   │ Canon EOS 80D            │ ✅ Removed     │
│ Software                │ Adobe Photoshop          │ ✅ Removed     │
│ GPSLatitude             │ 40.7128                  │ ✅ Removed     │
│ GPSLongitude            │ -74.0060                 │ ✅ Removed     │
│ Artist                  │ John Smith               │ ✅ Removed     │
│ Copyright               │ © 2024 John Smith        │ ✅ Removed     │
│ DateTimeOriginal        │ 2024:01:15 14:30:00      │ ⚪ Preserved   │
└─────────────────────────┴──────────────────────────┴────────────────┘

✅ Status: CLEAN - All sensitive metadata removed
Removed: 38 | Preserved: 2
```

---

## ⚙️ CLI Options

| Option | Description |
|--------|-------------|
| `-r`, `--recursive` | Process directories recursively |
| `-ext`, `--extension` | Filter by file extension (jpg, png, pdf, docx, xlsx, pptx) |
| `-o`, `--output` | Output directory for cleaned files |
| `-d`, `--dry-run` | Preview without making changes |
| `-w`, `--workers` | Number of concurrent workers (default: 4, max: 16) |
| `-V`, `--verbose` | Show detailed debug logs |
| `-v`, `--version` | Show version |

---

## 🛠️ Development

### Setup

```bash
git clone https://github.com/Heritage-XioN/metadata-scrubber-tool.git
cd metadata-scrubber-tool

# Install with dev dependencies
uv sync --all-extras

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy src
```

### Project Structure

```
src/
├── main.py                   # CLI entry point (Typer app)
├── commands/
│   ├── read.py               # Read metadata command
│   ├── scrub.py              # Scrub metadata command
│   └── verify.py             # Verify removal command
├── services/
│   ├── metadata_factory.py   # Factory for creating handlers
│   ├── metadata_handler.py   # Abstract base class
│   ├── image_handler.py      # JPEG/PNG handler
│   ├── pdf_handler.py        # PDF handler
│   ├── excel_handler.py      # Excel handler
│   ├── powerpoint_handler.py # PowerPoint handler
│   ├── worddoc_handler.py    # Word document handler
│   ├── report_generator.py   # Verification reports
│   └── batch_processor.py    # Concurrent batch processing
└── core/
    ├── jpeg_metadata.py      # JPEG EXIF processor
    └── png_metadata.py       # PNG metadata processor

docs/
├── metadata-risks.md         # Privacy risks documentation
└── best-practices.md         # Secure file sharing guide
```

---

## 📚 Documentation

- **[Metadata Risks](docs/metadata-risks.md)** - Why metadata matters for privacy
- **[Best Practices](docs/best-practices.md)** - Guidelines for secure file sharing

---

## ⚠️ Security Considerations

- **Original files are never modified** - processed copies are created
- **Use `--dry-run`** to preview changes before committing
- **Use `mst verify`** to confirm sensitive data was removed
- **GPS coordinates** are completely stripped for privacy
- **Author information** is removed from all supported formats
- **Always backup files** before scrubbing in production

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

Made with ❤️ for privacy
