"""Brand-impersonation scoring for a single candidate domain.

Three attack patterns get checked per domain, per DNS label:

- Homoglyph: the label's confusable skeleton matches the brand exactly,
  but the raw characters do not. "pаypal.com" (Cyrillic а) skeletonizes
  to "paypal", same as the real brand.
- Typosquat: the skeleton is a short Levenshtein distance from the brand.
  Catches "paypa1.com", "gooogle.com", "paypal.com" with a swapped pair.
- Combosquat: the brand name appears as a substring of a label alongside
  a phishing keyword, e.g. "paypal-login-verify.net".
- Apex-prefix spoofing: the brand's full domain sits as the leading
  labels of a longer domain it does not control, e.g.
  "paypal.com.account-verify.net". Mobile browsers and some desktop UIs
  truncate long URLs from the right, so this pattern only has to fool
  someone who never sees ".account-verify.net" at all.

Findings stack: a domain can trip more than one rule, and the reasons
list keeps every hit rather than only the highest scoring one, since a
human reviewing the alert wants to know all of it, not just the
headline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from glasswatch.confusables import decode_and_skeletonize, skeletonize
from glasswatch.watchlist import Brand

COMBOSQUAT_KEYWORDS = (
    "login", "signin", "verify", "secure", "security", "account",
    "update", "confirm", "support", "billing", "payment", "wallet",
    "recovery", "unlock", "alert", "suspend", "auth", "portal",
)

# Score contribution per rule. Findings stack (additively, up to a cap),
# so a domain that is both a homoglyph AND punycode-encoded AND uses a
# phishing keyword ends up flagged critical rather than just "high".
SCORE_HOMOGLYPH_EXACT = 60
SCORE_TYPO_DISTANCE_1 = 45
SCORE_TYPO_DISTANCE_2 = 28
SCORE_COMBOSQUAT = 25
SCORE_BRAND_SUBSTRING = 12
SCORE_PUNYCODE_BONUS = 15
SCORE_APEX_PREFIX = 55
SCORE_CAP = 100

SEVERITY_THRESHOLDS = (
    (70, "critical"),
    (45, "high"),
    (25, "medium"),
    (1, "low"),
)


@dataclass
class Finding:
    domain: str
    brand: str
    score: int
    severity: str
    reasons: list[str] = field(default_factory=list)


def levenshtein(a: str, b: str) -> int:
    """Classic O(len(a) * len(b)) edit distance, single-row DP.

    No third-party dependency on purpose: this is the one place a bug
    would silently under- or over-score every domain, so it stays small
    enough to read in one sitting and to hit with known-answer tests.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def _severity_for(score: int) -> str:
    for threshold, name in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return name
    return "info"


def is_legitimate(domain: str, brand_root: str) -> bool:
    """True if `domain` is the brand's own apex or a subdomain of it.

    "paypal.com" and "api.paypal.com" are legitimate. "paypal.com.evil.io"
    is not, because the suffix check is against the *end* of the string,
    not a substring match anywhere in it.
    """
    domain = domain.lower().rstrip(".")
    brand_root = brand_root.lower().rstrip(".")
    return domain == brand_root or domain.endswith("." + brand_root)


def score_domain(domain: str, brand: Brand) -> Finding | None:
    """Score one candidate domain against one watchlist brand.

    Returns None if nothing about the domain is suspicious relative to
    this brand (including the common case: it is the brand's own domain).
    """
    domain = domain.lower().strip(".")
    if not domain or is_legitimate(domain, brand.domain):
        return None

    core_skeleton = skeletonize(brand.core_name)
    labels = domain.split(".")

    score = 0
    reasons: list[str] = []
    had_punycode = False

    brand_labels = brand.domain.split(".")
    if len(brand_labels) >= 2 and labels[:len(brand_labels)] == brand_labels:
        score += SCORE_APEX_PREFIX
        reasons.append(f"apex-domain-as-prefix:{brand.domain}")

    for label in labels:
        unicode_label, label_skeleton, was_punycode = decode_and_skeletonize(label)
        had_punycode = had_punycode or was_punycode

        if label_skeleton == core_skeleton and unicode_label.casefold() != brand.core_name.casefold():
            score += SCORE_HOMOGLYPH_EXACT
            reasons.append(f"homoglyph-exact:{label}")
        elif core_skeleton:
            distance = levenshtein(label_skeleton, core_skeleton)
            if distance == 1:
                score += SCORE_TYPO_DISTANCE_1
                reasons.append(f"typosquat-distance-1:{label}")
            elif distance == 2:
                score += SCORE_TYPO_DISTANCE_2
                reasons.append(f"typosquat-distance-2:{label}")

        if brand.core_name and brand.core_name in unicode_label.casefold() and unicode_label.casefold() != brand.core_name.casefold():
            hits = [kw for kw in COMBOSQUAT_KEYWORDS if kw in unicode_label.casefold()]
            if hits:
                score += SCORE_COMBOSQUAT
                reasons.append(f"combosquat:{label}:{'+'.join(hits)}")
            else:
                score += SCORE_BRAND_SUBSTRING
                reasons.append(f"brand-substring:{label}")

    if not reasons:
        return None

    if had_punycode:
        score += SCORE_PUNYCODE_BONUS
        reasons.append("punycode-encoded")

    score = min(score, SCORE_CAP)
    # de-duplicate while preserving first-seen order
    unique_reasons = list(dict.fromkeys(reasons))

    return Finding(domain=domain, brand=brand.name, score=score,
                    severity=_severity_for(score), reasons=unique_reasons)


def score_against_watchlist(domain: str, brands: list[Brand]) -> list[Finding]:
    """Score one domain against every brand in the watchlist.

    A single domain can plausibly impersonate more than one brand
    (rare, but a combosquat like "paypal-amazon-verify.net" can), so
    this returns every finding above zero rather than only the top one.
    """
    findings = []
    for brand in brands:
        finding = score_domain(domain, brand)
        if finding is not None:
            findings.append(finding)
    return findings
