"""
©AngelaMos | 2026
mappings.py
"""

METHOD_MAP: dict[str, int] = {
    "GET": 1,
    "POST": 2,
    "PUT": 3,
    "DELETE": 4,
    "PATCH": 5,
    "HEAD": 6,
    "OPTIONS": 7,
}

STATUS_CLASS_MAP: dict[str, int] = {
    "1xx": 1,
    "2xx": 2,
    "3xx": 3,
    "4xx": 4,
    "5xx": 5,
}

EXTENSION_MAP: dict[str, int] = {
    ".html": 1,
    ".htm": 2,
    ".php": 3,
    ".js": 4,
    ".css": 5,
    ".json": 6,
    ".xml": 7,
    ".jpg": 8,
    ".jpeg": 9,
    ".png": 10,
    ".gif": 11,
    ".svg": 12,
    ".ico": 13,
    ".pdf": 14,
    ".zip": 15,
    ".txt": 16,
    ".asp": 17,
    ".aspx": 18,
    ".jsp": 19,
    ".py": 20,
    ".rb": 21,
    ".woff2": 22,
    ".woff": 23,
    ".ttf": 24,
    ".map": 25,
}

FEATURE_ORDER: list[str] = [
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
]

CATEGORICAL_ENCODERS: dict[str, dict[str, int]] = {
    "http_method": METHOD_MAP,
    "status_class": STATUS_CLASS_MAP,
    "file_extension": EXTENSION_MAP,
}

BOOLEAN_FEATURES: frozenset[str] = frozenset(
    {
        "has_encoded_chars",
        "has_double_encoding",
        "is_weekend",
        "is_known_bot",
        "is_known_scanner",
        "has_attack_pattern",
        "is_private_ip",
    }
)
