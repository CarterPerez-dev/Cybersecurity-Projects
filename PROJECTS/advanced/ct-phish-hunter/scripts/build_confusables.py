#!/usr/bin/env python3
"""Regenerate glasswatch/confusables_data.py from the official Unicode confusables table.

Source: https://www.unicode.org/Public/security/latest/confusables.txt (UTS #39)

The upstream file maps ~6000 non-ASCII codepoints to "confusable" replacement
sequences. Most targets are themselves non-ASCII (Greek confused with Cyrillic,
for example), which is not useful for domain-name skeletonization. This script
keeps only the entries whose *entire* target sequence collapses to plain ASCII
letters or digits, since those are the characters that let someone register
"paypal.com" using a Cyrillic "a" and have it look identical in a browser bar.

Run it whenever Unicode ships a new confusables.txt:

    python scripts/build_confusables.py
"""

from __future__ import annotations

import datetime
import sys
import urllib.request

SOURCE_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"
OUTPUT_PATH = "glasswatch/confusables_data.py"


def fetch_confusables_txt(url: str = SOURCE_URL) -> str:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_confusables(raw: str) -> dict[str, str]:
    """Parse confusables.txt into {non_ascii_char: ascii_skeleton}.

    Each data line looks like:
        0430 ; 0061 ; MA  # ( а → a ) CYRILLIC SMALL LETTER A → LATIN SMALL LETTER A
    Only entries where the source is non-ASCII and the full target sequence
    is printable ASCII alphanumerics are kept.
    """
    entries: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        if len(parts) < 3:
            continue
        src_hex, tgt_hex = parts[0], parts[1]
        try:
            src_cp = int(src_hex, 16)
        except ValueError:
            continue
        if src_cp < 128:
            continue  # already ASCII, nothing to normalize
        try:
            tgt_cps = [int(h, 16) for h in tgt_hex.split()]
        except ValueError:
            continue
        target = "".join(chr(cp) for cp in tgt_cps)
        if not target or not all(c.isascii() and c.isalnum() for c in target):
            continue
        entries[chr(src_cp)] = target.lower()
    return entries


def render_module(entries: dict[str, str]) -> str:
    lines = [
        '"""Auto-generated Unicode confusable -> ASCII skeleton table.',
        "",
        f"Source: {SOURCE_URL}",
        f"Generated: {datetime.datetime.now(datetime.timezone.utc).date().isoformat()}",
        f"Entries: {len(entries)}",
        "",
        "Do not hand-edit. Regenerate with scripts/build_confusables.py.",
        '"""',
        "",
        "CONFUSABLES: dict[str, str] = {",
    ]
    for char, target in sorted(entries.items(), key=lambda kv: ord(kv[0])):
        lines.append(f"    {char!r}: {target!r},")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    raw = fetch_confusables_txt()
    entries = parse_confusables(raw)
    if len(entries) < 500:
        print(f"error: only parsed {len(entries)} entries, expected 1000+", file=sys.stderr)
        return 1
    module_src = render_module(entries)
    with open(OUTPUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(module_src)
    print(f"wrote {len(entries)} entries to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
