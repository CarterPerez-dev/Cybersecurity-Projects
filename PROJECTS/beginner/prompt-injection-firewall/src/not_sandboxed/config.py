"""
©AngelaMos | 2026
config.py
"""

from typing import Final


NONCE_BYTES: Final = 8

FENCE_OPEN: Final = "<<<UNTRUSTED-{nonce} origin={channel}:{ref}>>>"
FENCE_CLOSE: Final = "<<<END-{nonce}>>>"

LAYER_NORMALIZE: Final = "normalize"

RULE_DECODE_BUDGET: Final = "decode-budget-exceeded"
RULE_INPUT_TOO_LARGE: Final = "input-too-large"
RULE_TRANSPORT_ENCODED: Final = "transport-encoded"
RULE_TAG_SMUGGLING: Final = "unicode-tag-smuggling"
RULE_ZERO_WIDTH: Final = "unicode-zero-width"
RULE_BIDI_CONTROL: Final = "unicode-bidi-control"
RULE_CONFUSABLE: Final = "unicode-confusable"

MAX_DECODE_DEPTH: Final = 4
MAX_NORMALIZE_BYTES: Final = 262_144
MIN_PRINTABLE_RATIO: Final = 0.85
MIN_ENCODED_LENGTH: Final = 16

BASE64_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/=\n\r"
)
BASE32_ALPHABET: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=\n\r")
HEX_ALPHABET: Final = frozenset("0123456789abcdefABCDEF")

TAG_BLOCK_START: Final = 0xE0000
TAG_BLOCK_END: Final = 0xE007F

ZERO_WIDTH_CODEPOINTS: Final = (
    0x200B,
    0x200C,
    0x200D,
    0x2060,
    0xFEFF,
)
ZERO_WIDTH_CHARS: Final = frozenset(
    chr(point) for point in ZERO_WIDTH_CODEPOINTS
)

BIDI_CODEPOINTS: Final = (
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
)
BIDI_CONTROLS: Final = frozenset(chr(point) for point in BIDI_CODEPOINTS)

CONFUSABLE_CODEPOINTS: Final = {
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0443: "y",
    0x0445: "x",
    0x0455: "s",
    0x0456: "i",
    0x0501: "d",
    0x0410: "A",
    0x0412: "B",
    0x0415: "E",
    0x041A: "K",
    0x041C: "M",
    0x041D: "H",
    0x041E: "O",
    0x0420: "P",
    0x0421: "C",
    0x0422: "T",
    0x0425: "X",
    0x03B1: "a",
    0x03BF: "o",
    0x03BD: "v",
    0x03C1: "p",
    0x0391: "A",
    0x0392: "B",
    0x0395: "E",
    0x0397: "H",
    0x039A: "K",
    0x039C: "M",
    0x039F: "O",
    0x03A1: "P",
    0x03A4: "T",
    0x03A7: "X",
}
CONFUSABLES: Final = {
    chr(point): latin
    for point, latin in CONFUSABLE_CODEPOINTS.items()
}
