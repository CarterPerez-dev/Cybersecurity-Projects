"""
©AngelaMos | 2026
test_detection.py
"""

from datetime import datetime, UTC

from app.core.detection.rules import RuleEngine
from app.core.ingestion.parsers import ParsedLogEntry


def _make_entry(
    path: str = "/api/v1/users",
    query_string: str = "",
    method: str = "GET",
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
) -> ParsedLogEntry:
    """
    Build a ParsedLogEntry with sensible defaults for rule engine testing.
    """
    return ParsedLogEntry(
        ip="93.184.216.34",
        timestamp=datetime(2026, 2, 11, 14, 30, 0, tzinfo=UTC),
        method=method,
        path=path,
        query_string=query_string,
        status_code=status_code,
        response_size=1234,
        referer="",
        user_agent=user_agent,
        raw_line="",
    )


def _empty_windowed() -> dict[str, float]:
    """
    Windowed features representing a quiet IP.
    """
    return {
        "req_count_1m": 1.0,
        "req_count_5m": 3.0,
        "req_count_10m": 5.0,
        "error_rate_5m": 0.0,
        "unique_paths_5m": 2.0,
        "unique_uas_10m": 1.0,
        "method_entropy_5m": 0.0,
        "avg_response_size_5m": 1024.0,
        "status_diversity_5m": 1.0,
        "path_depth_variance_5m": 0.0,
        "inter_request_time_mean": 5000.0,
        "inter_request_time_std": 1000.0,
    }


ENGINE = RuleEngine()


def test_normal_request_low_severity() -> None:
    """
    A benign GET request scores below 0.5 with LOW severity.
    """
    result = ENGINE.score_request(_empty_windowed(), _make_entry())
    assert result.threat_score < 0.5
    assert result.severity == "LOW"
    assert result.matched_rules == []


def test_sqli_in_query_string() -> None:
    """
    SQL injection payload triggers HIGH severity with SQL_INJECTION rule.
    """
    entry = _make_entry(
        path="/users",
        query_string="id=1' UNION SELECT username,password FROM users--",
    )
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert result.threat_score >= 0.7
    assert result.severity == "HIGH"
    assert "SQL_INJECTION" in result.matched_rules


def test_xss_in_query_string() -> None:
    """
    XSS payload triggers HIGH severity with XSS rule.
    """
    entry = _make_entry(
        path="/comment",
        query_string="body=<script>alert(document.cookie)</script>",
    )
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert result.threat_score >= 0.7
    assert result.severity == "HIGH"
    assert "XSS" in result.matched_rules


def test_path_traversal() -> None:
    """
    Path traversal triggers at least MEDIUM severity.
    """
    entry = _make_entry(path="/static/../../etc/passwd")
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert result.threat_score >= 0.5
    assert result.severity in {"MEDIUM", "HIGH"}
    assert "PATH_TRAVERSAL" in result.matched_rules


def test_command_injection() -> None:
    """
    Command injection triggers HIGH severity.
    """
    entry = _make_entry(
        path="/ping",
        query_string="host=127.0.0.1;cat /etc/passwd",
    )
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert result.threat_score >= 0.7
    assert result.severity == "HIGH"
    assert "COMMAND_INJECTION" in result.matched_rules


def test_scanner_ua_contributes() -> None:
    """
    Known scanner UA fires the SCANNER_UA rule.
    """
    entry = _make_entry(user_agent="Mozilla/5.00 (Nikto/2.1.6)")
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert "SCANNER_UA" in result.matched_rules
    assert result.threat_score > 0.0


def test_rate_anomaly() -> None:
    """
    High request rate in the 1-minute window fires RATE_ANOMALY.
    """
    windowed = _empty_windowed()
    windowed["req_count_1m"] = 150.0
    result = ENGINE.score_request(windowed, _make_entry())
    assert "RATE_ANOMALY" in result.matched_rules
    assert result.threat_score > 0.0


def test_multiple_rules_aggregate() -> None:
    """
    Multiple triggered rules produce a higher score than any single rule alone.
    """
    entry = _make_entry(
        path="/users",
        query_string="id=1' OR 1=1--",
        user_agent="sqlmap/1.8",
    )
    sqli_only = ENGINE.score_request(
        _empty_windowed(),
        _make_entry(path="/users", query_string="id=1' OR 1=1--"),
    )
    combined = ENGINE.score_request(_empty_windowed(), entry)
    assert combined.threat_score > sqli_only.threat_score
    assert len(combined.matched_rules) > len(sqli_only.matched_rules)


def test_score_clamped_to_unit_range() -> None:
    """
    Score never exceeds 1.0 even with many triggered rules.
    """
    entry = _make_entry(
        path="/static/../../etc/passwd;cat /etc/shadow",
        query_string="id=1' UNION SELECT 1--&x=<script>alert(1)</script>",
        user_agent="sqlmap/1.8",
    )
    windowed = _empty_windowed()
    windowed["req_count_1m"] = 200.0
    windowed["error_rate_5m"] = 0.8
    result = ENGINE.score_request(windowed, entry)
    assert 0.0 <= result.threat_score <= 1.0


def test_severity_thresholds() -> None:
    """
    Severity classification follows the architecture thresholds.
    """
    low = ENGINE.score_request(_empty_windowed(), _make_entry())
    assert low.severity == "LOW"

    medium = ENGINE.score_request(
        _empty_windowed(),
        _make_entry(path="/static/../../etc/passwd"),
    )
    assert medium.severity in {"MEDIUM", "HIGH"}

    high = ENGINE.score_request(
        _empty_windowed(),
        _make_entry(
            path="/users",
            query_string="id=1' UNION SELECT username FROM users--",
        ),
    )
    assert high.severity == "HIGH"


def test_result_has_component_scores() -> None:
    """
    RuleResult includes individual scores per triggered rule.
    """
    entry = _make_entry(
        path="/users",
        query_string="id=1' OR 1=1--",
    )
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert len(result.component_scores) == len(result.matched_rules)
    for rule_name in result.matched_rules:
        assert rule_name in result.component_scores
        assert result.component_scores[rule_name] > 0.0


def test_file_inclusion() -> None:
    """
    PHP stream wrapper in query string triggers FILE_INCLUSION rule.
    """
    entry = _make_entry(
        path="/include",
        query_string="page=php://filter/convert.base64-encode/resource=config",
    )
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert "FILE_INCLUSION" in result.matched_rules
    assert result.threat_score >= 0.5


def test_double_encoding() -> None:
    """
    Double-encoded characters trigger the DOUBLE_ENCODING rule.
    """
    entry = _make_entry(path="/path%2527trick")
    result = ENGINE.score_request(_empty_windowed(), entry)
    assert "DOUBLE_ENCODING" in result.matched_rules
