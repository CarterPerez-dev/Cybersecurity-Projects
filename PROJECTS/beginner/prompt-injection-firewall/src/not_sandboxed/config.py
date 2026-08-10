"""
©AngelaMos | 2026
config.py
"""

from typing import Final


NONCE_BYTES: Final = 8

FENCE_OPEN: Final = "<<<UNTRUSTED-{nonce} origin={channel}:{ref}>>>"
FENCE_CLOSE: Final = "<<<END-{nonce}>>>"
