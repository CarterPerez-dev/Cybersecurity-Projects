"""Domain-name normalization: punycode decoding and confusable skeletons.

Two separate tricks show up in real phishing certificates:

1. Punycode / IDN homograph attacks. A browser renders "xn--pple-43d.com"
   as "аpple.com" with a Cyrillic а. The wire format is pure ASCII, so a
   naive string comparison against a watchlist never sees the problem.
2. Confusable characters used directly. Nothing stops someone from
   registering a domain containing a look-alike character without ever
   going through punycode round-tripping in front of you; you only see it
   once you decode the label back to Unicode.

`skeletonize()` folds both cases down to a plain ASCII string so a
homoglyph domain and its real target compare equal, the way section 4 of
Unicode Technical Standard #39 (unicode.org/reports/tr39) describes.
"""

from __future__ import annotations

import unicodedata

from glasswatch.confusables_data import CONFUSABLES


def decode_label(label: str) -> tuple[str, bool]:
    """Decode a single DNS label, resolving punycode (xn--) if present.

    Returns (unicode_label, was_punycode). Falls back to the original
    label unchanged if it claims to be punycode but fails to decode,
    since a malformed xn-- label is not our problem to fix, only to not
    crash on.
    """
    if not label.lower().startswith("xn--"):
        return label, False
    try:
        decoded = label[4:].encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return label, True
    return decoded, True


def skeletonize(label: str) -> str:
    """Fold a Unicode label to its ASCII confusable skeleton, casefolded.

    NFKD first so combining marks and compatibility forms (fullwidth
    characters, ligatures) are already broken apart before the
    per-character confusable table is applied. Characters with no entry
    in the table pass through unchanged, so plain ASCII input is a no-op
    beyond casefolding.
    """
    normalized = unicodedata.normalize("NFKD", label)
    out = []
    for ch in normalized:
        out.append(CONFUSABLES.get(ch, ch))
    return "".join(out).casefold()


def decode_and_skeletonize(label: str) -> tuple[str, str, bool]:
    """Convenience wrapper: decode punycode, then skeletonize.

    Returns (unicode_label, skeleton, was_punycode).
    """
    unicode_label, was_punycode = decode_label(label)
    return unicode_label, skeletonize(unicode_label), was_punycode
