"""
©AngelaMos | 2026
test_features.py
"""

from datetime import datetime, UTC

from app.core.features.extractor import extract_request_features
from app.core.ingestion.parsers import ParsedLogEntry

FEATURE_KEYS = {
    "http_method",
    "path_depth",
    "path_entropy",
    "path_length",
    "query_string_length",
    "query_param_count",
    "has_encoded_chars",
    "has_double_encoding",
    "status_code",
    "status_class",
    "response_size",
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "ua_length",
    "ua_entropy",
    "is_known_bot",
    "is_known_scanner",
    "has_attack_pattern",
    "special_char_ratio",
    "file_extension",
    "country_code",
    "is_private_ip",
}


def _make_entry(
    ip: str = "93.184.216.34",
    timestamp: datetime | None = None,
    method: str = "GET",
    path: str = "/api/v1/users",
    query_string: str = "",
    status_code: int = 200,
    response_size: int = 1234,
    referer: str = "",
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
) -> ParsedLogEntry:
    """
    Build a ParsedLogEntry with sensible defaults for testing.
    """
    if timestamp is None:
        timestamp = datetime(2026, 2, 11, 14, 30, 0, tzinfo=UTC)

    return ParsedLogEntry(
        ip=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        query_string=query_string,
        status_code=status_code,
        response_size=response_size,
        referer=referer,
        user_agent=user_agent,
        raw_line="",
    )


def test_extract_returns_all_23_feature_keys() -> None:
    """
    Feature dict contains exactly the 23 per-request keys.
    """
    features = extract_request_features(_make_entry())
    assert set(features.keys()) == FEATURE_KEYS


def test_path_depth() -> None:
    """
    Path depth counts non-empty segments between slashes.
    """
    assert extract_request_features(_make_entry(path="/"))["path_depth"] == 0
    assert extract_request_features(_make_entry(path="/api"))["path_depth"] == 1
    assert extract_request_features(_make_entry(path="/api/v1/users"))["path_depth"] == 3


def test_path_entropy_high_vs_low() -> None:
    """
    Random-character paths have higher entropy than simple paths.
    """
    low = extract_request_features(_make_entry(path="/index.html"))["path_entropy"]
    high = extract_request_features(_make_entry(path="/x8Kp2mQz7wR4vL1n"))["path_entropy"]
    assert high > low


def test_query_string_features() -> None:
    """
    Query param count and length are extracted correctly.
    """
    features = extract_request_features(_make_entry(query_string="page=1&sort=name&limit=50"))
    assert features["query_param_count"] == 3
    assert features["query_string_length"] == len("page=1&sort=name&limit=50")

    empty = extract_request_features(_make_entry(query_string=""))
    assert empty["query_param_count"] == 0
    assert empty["query_string_length"] == 0


def test_url_encoding_detection() -> None:
    """
    Percent-encoded sequences are detected in path and query.
    """
    encoded = extract_request_features(
        _make_entry(path="/search", query_string="q=%27OR+1%3D1")
    )
    assert encoded["has_encoded_chars"] is True

    clean = extract_request_features(_make_entry(path="/index.html", query_string=""))
    assert clean["has_encoded_chars"] is False


def test_double_encoding_detection() -> None:
    """
    Double-encoded sequences like %2527 are flagged.
    """
    double = extract_request_features(_make_entry(path="/path%2527trick"))
    assert double["has_double_encoding"] is True

    single = extract_request_features(_make_entry(path="/path%27normal"))
    assert single["has_double_encoding"] is False


def test_status_class() -> None:
    """
    Status class groups status codes into Nxx buckets.
    """
    assert extract_request_features(_make_entry(status_code=200))["status_class"] == "2xx"
    assert extract_request_features(_make_entry(status_code=404))["status_class"] == "4xx"
    assert extract_request_features(_make_entry(status_code=503))["status_class"] == "5xx"


def test_temporal_features() -> None:
    """
    Hour, day of week, and weekend flag derived from timestamp.
    """
    wednesday_2pm = datetime(2026, 2, 11, 14, 0, 0, tzinfo=UTC)
    features = extract_request_features(_make_entry(timestamp=wednesday_2pm))
    assert features["hour_of_day"] == 14
    assert features["day_of_week"] == 2
    assert features["is_weekend"] is False

    saturday_3am = datetime(2026, 2, 14, 3, 0, 0, tzinfo=UTC)
    weekend = extract_request_features(_make_entry(timestamp=saturday_3am))
    assert weekend["hour_of_day"] == 3
    assert weekend["day_of_week"] == 5
    assert weekend["is_weekend"] is True


def test_ua_bot_detection() -> None:
    """
    Known bot user agents are flagged.
    """
    bot = extract_request_features(
        _make_entry(
            user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        )
    )
    assert bot["is_known_bot"] is True

    normal = extract_request_features(
        _make_entry(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    )
    assert normal["is_known_bot"] is False


def test_ua_scanner_detection() -> None:
    """
    Known vulnerability scanner user agents are flagged.
    """
    nikto = extract_request_features(_make_entry(user_agent="Mozilla/5.00 (Nikto/2.1.6)"))
    assert nikto["is_known_scanner"] is True

    sqlmap = extract_request_features(_make_entry(user_agent="sqlmap/1.8"))
    assert sqlmap["is_known_scanner"] is True


def test_attack_pattern_detection() -> None:
    """
    SQLi, XSS, and path traversal patterns in paths are detected.
    """
    sqli = extract_request_features(_make_entry(path="/users", query_string="id=1' OR 1=1--"))
    assert sqli["has_attack_pattern"] is True

    xss = extract_request_features(
        _make_entry(path="/comment", query_string="body=<script>alert(1)</script>")
    )
    assert xss["has_attack_pattern"] is True

    traversal = extract_request_features(_make_entry(path="/static/../../etc/passwd"))
    assert traversal["has_attack_pattern"] is True

    clean = extract_request_features(_make_entry(path="/api/v1/health"))
    assert clean["has_attack_pattern"] is False


def test_special_char_ratio() -> None:
    """
    Paths with many non-alphanumeric characters have higher ratios.
    """
    clean = extract_request_features(_make_entry(path="/api/users"))["special_char_ratio"]

    noisy = extract_request_features(_make_entry(path="/<script>alert('xss')</script>"))[
        "special_char_ratio"
    ]

    assert noisy > clean


def test_private_ip_detection() -> None:
    """
    RFC 1918 and loopback addresses are classified as private.
    """
    assert extract_request_features(_make_entry(ip="192.168.1.1"))["is_private_ip"] is True

    assert extract_request_features(_make_entry(ip="127.0.0.1"))["is_private_ip"] is True

    assert extract_request_features(_make_entry(ip="8.8.8.8"))["is_private_ip"] is False


def test_file_extension() -> None:
    """
    File extension is extracted from the path.
    """
    assert extract_request_features(_make_entry(path="/style.css"))["file_extension"] == ".css"

    assert extract_request_features(_make_entry(path="/api/users"))["file_extension"] == ""


def test_country_code_passthrough() -> None:
    """
    Country code is passed through from the caller.
    """
    features = extract_request_features(_make_entry(), country_code="US")
    assert features["country_code"] == "US"

    features_empty = extract_request_features(_make_entry())
    assert features_empty["country_code"] == ""


import time  # noqa: E402

import fakeredis.aioredis  # noqa: E402
import pytest  # noqa: E402

from app.core.features.aggregator import WindowAggregator  # noqa: E402

AGGREGATOR_KEYS = {
    "req_count_1m",
    "req_count_5m",
    "req_count_10m",
    "error_rate_5m",
    "unique_paths_5m",
    "unique_uas_10m",
    "method_entropy_5m",
    "avg_response_size_5m",
    "status_diversity_5m",
    "path_depth_variance_5m",
    "inter_request_time_mean",
    "inter_request_time_std",
}


@pytest.fixture
async def aggregator():
    """
    WindowAggregator backed by an in-memory fake Redis.
    """
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield WindowAggregator(redis)
    await redis.aclose()


async def _record(
    agg: WindowAggregator,
    ip: str = "10.0.0.1",
    request_id: str = "r-001",
    path: str = "/api/users",
    path_depth: int = 2,
    method: str = "GET",
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0",
    response_size: int = 1024,
    timestamp: float | None = None,
) -> dict[str, float]:
    """
    Shorthand for record_and_aggregate with sensible defaults.
    """
    return await agg.record_and_aggregate(
        ip=ip,
        request_id=request_id,
        path=path,
        path_depth=path_depth,
        method=method,
        status_code=status_code,
        user_agent=user_agent,
        response_size=response_size,
        timestamp=timestamp or time.time(),
    )


@pytest.mark.asyncio
async def test_aggregator_single_request(aggregator) -> None:
    """
    A single request yields count of 1.
    """
    result = await _record(aggregator)
    assert set(result.keys()) == AGGREGATOR_KEYS
    assert result["req_count_1m"] == 1
    assert result["req_count_5m"] == 1
    assert result["req_count_10m"] == 1


@pytest.mark.asyncio
async def test_aggregator_ten_requests(aggregator) -> None:
    """
    Ten requests within 30 seconds all count in the 1-minute window.
    """
    now = time.time()
    result = None
    for i in range(10):
        result = await _record(
            aggregator,
            request_id=f"r-{i:03d}",
            timestamp=now - 30 + i * 3,
        )
    assert result is not None
    assert result["req_count_1m"] == 10


@pytest.mark.asyncio
async def test_aggregator_error_rate(aggregator) -> None:
    """
    Error rate is the ratio of 4xx/5xx responses.
    """
    now = time.time()
    for i in range(8):
        await _record(
            aggregator,
            request_id=f"ok-{i}",
            status_code=200,
            timestamp=now - 60 + i,
        )
    for i in range(2):
        result = await _record(
            aggregator,
            request_id=f"err-{i}",
            status_code=404,
            timestamp=now - 10 + i,
        )
    assert result["error_rate_5m"] == pytest.approx(0.2, abs=0.01)


@pytest.mark.asyncio
async def test_aggregator_unique_paths(aggregator) -> None:
    """
    Unique paths counts distinct URL paths in the window.
    """
    now = time.time()
    paths = ["/api/users", "/api/posts", "/api/users", "/api/health"]
    result = None
    for i, p in enumerate(paths):
        result = await _record(
            aggregator,
            request_id=f"r-{i}",
            path=p,
            timestamp=now - 10 + i,
        )
    assert result is not None
    assert result["unique_paths_5m"] == 3


@pytest.mark.asyncio
async def test_aggregator_unique_uas(aggregator) -> None:
    """
    Unique UAs counts distinct user agents in the 10-minute window.
    """
    now = time.time()
    uas = ["Mozilla/5.0", "curl/8.0", "Mozilla/5.0", "python-httpx/0.28"]
    result = None
    for i, ua in enumerate(uas):
        result = await _record(
            aggregator,
            request_id=f"r-{i}",
            user_agent=ua,
            timestamp=now - 10 + i,
        )
    assert result is not None
    assert result["unique_uas_10m"] == 3


@pytest.mark.asyncio
async def test_aggregator_ttl_set(aggregator) -> None:
    """
    All Redis keys are set with a 900-second TTL.
    """
    await _record(aggregator, ip="5.5.5.5")
    ttl = await aggregator._redis.ttl("ip:5.5.5.5:requests")
    assert 0 < ttl <= 900


@pytest.mark.asyncio
async def test_aggregator_window_boundary(aggregator) -> None:
    """
    Requests outside the 1-minute window are excluded from req_count_1m
    but still counted in req_count_5m.
    """
    now = time.time()
    await _record(
        aggregator,
        request_id="old",
        timestamp=now - 120,
    )
    result = await _record(
        aggregator,
        request_id="new",
        timestamp=now,
    )
    assert result["req_count_1m"] == 1
    assert result["req_count_5m"] == 2


from app.core.features.encoder import encode_for_inference  # noqa: E402
from app.core.features.mappings import FEATURE_ORDER, METHOD_MAP, STATUS_CLASS_MAP  # noqa: E402


def _full_features() -> dict[str, int | float | bool | str]:
    """
    Build a complete 35-key feature dict with realistic values.
    """
    return {
        "http_method": "GET",
        "path_depth": 3,
        "path_entropy": 3.12,
        "path_length": 14,
        "query_string_length": 6,
        "query_param_count": 1,
        "has_encoded_chars": False,
        "has_double_encoding": False,
        "status_code": 200,
        "status_class": "2xx",
        "response_size": 1234,
        "hour_of_day": 14,
        "day_of_week": 2,
        "is_weekend": False,
        "ua_length": 42,
        "ua_entropy": 4.01,
        "is_known_bot": False,
        "is_known_scanner": False,
        "has_attack_pattern": False,
        "special_char_ratio": 0.21,
        "file_extension": ".html",
        "country_code": "US",
        "is_private_ip": False,
        "req_count_1m": 5.0,
        "req_count_5m": 20.0,
        "req_count_10m": 45.0,
        "error_rate_5m": 0.1,
        "unique_paths_5m": 8.0,
        "unique_uas_10m": 2.0,
        "method_entropy_5m": 0.5,
        "avg_response_size_5m": 2048.0,
        "status_diversity_5m": 3.0,
        "path_depth_variance_5m": 1.2,
        "inter_request_time_mean": 250.0,
        "inter_request_time_std": 80.0,
    }


def test_encoder_output_shape_and_type() -> None:
    """
    Encoded vector has exactly 35 float elements.
    """
    result = encode_for_inference(_full_features())
    assert len(result) == 35
    assert all(isinstance(v, float) for v in result)


def test_encoder_method_ordinal() -> None:
    """
    HTTP methods map to deterministic ordinal indices.
    """
    features = _full_features()
    features["http_method"] = "GET"
    vec = encode_for_inference(features)
    assert vec[FEATURE_ORDER.index("http_method")] == float(METHOD_MAP["GET"])

    features["http_method"] = "POST"
    vec = encode_for_inference(features)
    assert vec[FEATURE_ORDER.index("http_method")] == float(METHOD_MAP["POST"])


def test_encoder_status_class_ordinal() -> None:
    """
    Status classes map to deterministic ordinal indices.
    """
    features = _full_features()
    features["status_class"] = "4xx"
    vec = encode_for_inference(features)
    idx = FEATURE_ORDER.index("status_class")
    assert vec[idx] == float(STATUS_CLASS_MAP["4xx"])


def test_encoder_boolean_to_float() -> None:
    """
    Boolean features encode to 0.0 or 1.0.
    """
    features = _full_features()
    features["is_known_bot"] = True
    features["is_weekend"] = False
    vec = encode_for_inference(features)
    assert vec[FEATURE_ORDER.index("is_known_bot")] == 1.0
    assert vec[FEATURE_ORDER.index("is_weekend")] == 0.0


def test_encoder_numerical_passthrough() -> None:
    """
    Numerical features pass through as raw float values.
    """
    features = _full_features()
    vec = encode_for_inference(features)
    assert vec[FEATURE_ORDER.index("path_depth")] == 3.0
    assert vec[FEATURE_ORDER.index("response_size")] == 1234.0
    assert vec[FEATURE_ORDER.index("req_count_1m")] == 5.0


def test_encoder_unknown_categorical() -> None:
    """
    Unknown categorical values fall back to 0.
    """
    features = _full_features()
    features["http_method"] = "BREW"
    features["status_class"] = "9xx"
    vec = encode_for_inference(features)
    assert vec[FEATURE_ORDER.index("http_method")] == 0.0
    assert vec[FEATURE_ORDER.index("status_class")] == 0.0
