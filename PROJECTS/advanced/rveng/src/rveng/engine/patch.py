"""
©AngelaMos | 2026
patch.py
"""

from dataclasses import dataclass


class PatchError(ValueError):
    """
    Raised when a patch cannot be applied within bounds
    """


@dataclass(frozen = True)
class ByteDiff:
    """
    A single differing byte between two equal-length buffers
    """

    offset: int
    before: int
    after: int


def diff(original: bytes, modified: bytes) -> list[ByteDiff]:
    """
    Return the per-byte differences between two equal-length buffers
    """
    if len(original) != len(modified):
        raise PatchError("buffers differ in length")
    out = []
    for offset, (a, b) in enumerate(zip(original, modified)):
        if a != b:
            out.append(ByteDiff(offset = offset, before = a, after = b))
    return out


def apply(original: bytes, offset: int, new_bytes: bytes) -> bytes:
    """
    Return original with new_bytes written at offset, length preserved
    """
    if offset < 0 or offset + len(new_bytes) > len(original):
        raise PatchError("patch out of bounds")
    return (original[: offset] + new_bytes + original[offset + len(new_bytes):])


def verify_patch(
    original: bytes,
    offset: int,
    submitted: bytes,
    known_good: bytes
) -> bool:
    """
    True when applying submitted at offset reproduces the known-good target
    """
    try:
        return apply(original, offset, submitted) == known_good
    except PatchError:
        return False
