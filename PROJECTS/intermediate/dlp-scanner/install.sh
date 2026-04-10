#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

command -v uv >/dev/null 2>&1 || {
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
}

echo "Syncing dependencies..."
uv sync

echo "Downloading spaCy model (optional, for NLP-based detection)..."
uv run python -m spacy download en_core_web_sm 2>/dev/null || true

echo ""
echo "Setup complete. Run the scanner with:"
echo "  uv run dlp-scan --help"
echo ""
echo "Quick start:"
echo "  uv run dlp-scan scan file ./path/to/scan"
echo "  uv run dlp-scan scan db sqlite:///path/to/db.sqlite3"
echo "  uv run dlp-scan scan network ./capture.pcap"
