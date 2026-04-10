"""
©AngelaMos | 2026
test_context.py
"""


from dlp_scanner.detectors.base import DetectorMatch
from dlp_scanner.detectors.context import (
    apply_context_boost,
    _apply_cooccurrence_boost,
)


def _make_match(
    rule_id: str = "PII_SSN",
    start: int = 20,
    end: int = 31,
    score: float = 0.45,
    keywords: list[str] | None = None,
) -> DetectorMatch:
    resolved_keywords = (
        keywords if keywords is not None else ["ssn",
                                               "social security"]
    )
    return DetectorMatch(
        rule_id = rule_id,
        rule_name = "Test Rule",
        start = start,
        end = end,
        matched_text = "234-56-7890",
        score = score,
        context_keywords = resolved_keywords,
        compliance_frameworks = [],
    )


class TestContextBoost:
    def test_boost_with_keyword_present(self) -> None:
        text = "Employee SSN: 234-56-7890 on file"
        match = _make_match(start = 14, end = 25)
        boosted = apply_context_boost(text, [match])
        assert boosted[0].score > match.score

    def test_no_boost_without_keyword(self) -> None:
        text = "Some random number 234-56-7890 here"
        match = _make_match(
            start = 19,
            end = 30,
            keywords = ["nonexistent_keyword"],
        )
        boosted = apply_context_boost(text, [match])
        assert boosted[0].score == match.score

    def test_no_boost_with_empty_keywords(self) -> None:
        text = "SSN: 234-56-7890"
        match = _make_match(start = 5, end = 16, keywords = [])
        boosted = apply_context_boost(text, [match])
        assert boosted[0].score == match.score

    def test_empty_matches_returns_empty(self) -> None:
        result = apply_context_boost("any text", [])
        assert result == []


class TestCooccurrenceBoost:
    def test_nearby_different_rules_boosted(self) -> None:
        matches = [
            _make_match(rule_id = "PII_SSN",
                        start = 10,
                        end = 21),
            _make_match(
                rule_id = "PII_EMAIL",
                start = 30,
                end = 50,
                keywords = ["email"],
            ),
        ]
        boosted = _apply_cooccurrence_boost(matches)
        assert all(
            b.score > m.score
            for b, m in zip(boosted, matches, strict = False)
        )

    def test_same_rule_not_boosted(self) -> None:
        matches = [
            _make_match(rule_id = "PII_SSN",
                        start = 10,
                        end = 21),
            _make_match(rule_id = "PII_SSN",
                        start = 50,
                        end = 61),
        ]
        boosted = _apply_cooccurrence_boost(matches)
        assert all(
            b.score == m.score
            for b, m in zip(boosted, matches, strict = False)
        )

    def test_distant_matches_not_boosted(self) -> None:
        matches = [
            _make_match(rule_id = "PII_SSN",
                        start = 10,
                        end = 21),
            _make_match(
                rule_id = "PII_EMAIL",
                start = 1000,
                end = 1020,
                keywords = ["email"],
            ),
        ]
        boosted = _apply_cooccurrence_boost(matches)
        assert all(
            b.score == m.score
            for b, m in zip(boosted, matches, strict = False)
        )

    def test_single_match_not_boosted(self) -> None:
        matches = [_make_match()]
        boosted = _apply_cooccurrence_boost(matches)
        assert boosted[0].score == matches[0].score
