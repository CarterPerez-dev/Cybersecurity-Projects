"""
©AngelaMos | 2026
context.py
"""


from dlp_scanner.constants import (
    CONTEXT_BOOST_MAX,
    CONTEXT_BOOST_MIN_FLOOR,
    COOCCURRENCE_BOOST,
    DEFAULT_CONTEXT_WINDOW_TOKENS,
)
from dlp_scanner.detectors.base import DetectorMatch


def apply_context_boost(
    text: str,
    matches: list[DetectorMatch],
    window_tokens: int = DEFAULT_CONTEXT_WINDOW_TOKENS,
) -> list[DetectorMatch]:
    """
    Boost match scores based on nearby context keywords
    """
    if not matches:
        return matches

    tokens = text.lower().split()
    boosted: list[DetectorMatch] = []

    for match in matches:
        if not match.context_keywords:
            boosted.append(match)
            continue

        char_to_token = _char_offset_to_token_index(text, match.start)
        window_start = max(0, char_to_token - window_tokens)
        window_end = min(len(tokens), char_to_token + window_tokens)
        window_text = " ".join(tokens[window_start : window_end])

        boost = _compute_keyword_boost(
            window_text,
            match.context_keywords,
            window_tokens,
        )

        new_score = min(1.0, match.score + boost)
        if boost > 0 and new_score < CONTEXT_BOOST_MIN_FLOOR:
            new_score = CONTEXT_BOOST_MIN_FLOOR

        boosted.append(
            DetectorMatch(
                rule_id = match.rule_id,
                rule_name = match.rule_name,
                start = match.start,
                end = match.end,
                matched_text = match.matched_text,
                score = new_score,
                context_keywords = match.context_keywords,
                compliance_frameworks = match.compliance_frameworks,
            )
        )

    return _apply_cooccurrence_boost(boosted)


def _compute_keyword_boost(
    window_text: str,
    keywords: list[str],
    window_tokens: int,
) -> float:
    """
    Compute score boost based on keyword proximity
    """
    best_boost = 0.0

    for keyword in keywords:
        kw_lower = keyword.lower()
        pos = window_text.find(kw_lower)
        if pos < 0:
            continue

        center = len(window_text) // 2
        distance = abs(pos - center)
        max_distance = window_tokens * 5

        proximity_factor = 1.0 - min(1.0, distance / max(1, max_distance))
        boost = CONTEXT_BOOST_MAX * proximity_factor
        best_boost = max(best_boost, boost)

    return best_boost


def _apply_cooccurrence_boost(
    matches: list[DetectorMatch],
) -> list[DetectorMatch]:
    """
    Boost scores when multiple PII types appear near each other
    """
    if len(matches) < 2:
        return matches

    proximity_threshold = 500
    boosted: list[DetectorMatch] = []

    for i, match in enumerate(matches):
        has_neighbor = False
        for j, other in enumerate(matches):
            if i == j:
                continue
            if other.rule_id == match.rule_id:
                continue
            distance = abs(match.start - other.start)
            if distance < proximity_threshold:
                has_neighbor = True
                break

        if has_neighbor:
            new_score = min(1.0, match.score + COOCCURRENCE_BOOST)
            boosted.append(
                DetectorMatch(
                    rule_id = match.rule_id,
                    rule_name = match.rule_name,
                    start = match.start,
                    end = match.end,
                    matched_text = match.matched_text,
                    score = new_score,
                    context_keywords = match.context_keywords,
                    compliance_frameworks = match.compliance_frameworks,
                )
            )
        else:
            boosted.append(match)

    return boosted


def _char_offset_to_token_index(text: str, char_offset: int) -> int:
    """
    Convert a character offset to an approximate token index
    """
    prefix = text[: char_offset]
    return len(prefix.split())
