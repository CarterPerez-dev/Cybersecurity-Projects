"""
©AngelaMos | 2026
aggregator.py
"""

import hashlib
import math
from collections import Counter

import redis.asyncio as aioredis

WINDOW_1M = 60
WINDOW_5M = 300
WINDOW_10M = 600
KEY_TTL = 900


def _hash_member(value: str) -> str:
    """
    Produce a compact 16-char hex digest for sorted set deduplication.
    """
    return hashlib.md5(value.encode()).hexdigest()[:16]


class WindowAggregator:
    """
    Per-IP sliding window feature aggregator backed by Redis sorted sets.
    """

    def __init__(self, redis_client: aioredis.Redis[bytes]) -> None:
        self._redis = redis_client

    async def record_and_aggregate(
        self,
        ip: str,
        request_id: str,
        path: str,
        path_depth: int,
        method: str,
        status_code: int,
        user_agent: str,
        response_size: int,
        timestamp: float,
    ) -> dict[str, float]:
        """
        Record a request into Redis sorted sets and return all 12
        per-IP windowed features.
        """
        prefix = f"ip:{ip}"
        keys = {
            "requests": f"{prefix}:requests",
            "paths": f"{prefix}:paths",
            "statuses": f"{prefix}:statuses",
            "uas": f"{prefix}:uas",
            "sizes": f"{prefix}:sizes",
            "methods": f"{prefix}:methods",
            "depths": f"{prefix}:depths",
        }

        trim_boundary = timestamp - KEY_TTL
        w1m = timestamp - WINDOW_1M
        w5m = timestamp - WINDOW_5M
        w10m = timestamp - WINDOW_10M

        pipe = self._redis.pipeline()

        pipe.zadd(keys["requests"], {request_id: timestamp})
        pipe.zadd(keys["paths"], {_hash_member(path): timestamp})
        pipe.zadd(keys["statuses"], {f"{status_code}:{request_id}": timestamp})
        pipe.zadd(keys["uas"], {_hash_member(user_agent): timestamp})
        pipe.zadd(keys["sizes"], {f"{response_size}:{request_id}": timestamp})
        pipe.zadd(keys["methods"], {f"{method}:{request_id}": timestamp})
        pipe.zadd(keys["depths"], {f"{path_depth}:{request_id}": timestamp})

        for key in keys.values():
            pipe.zremrangebyscore(key, "-inf", trim_boundary)

        pipe.zcount(keys["requests"], w1m, "+inf")
        pipe.zcount(keys["requests"], w5m, "+inf")
        pipe.zcount(keys["requests"], w10m, "+inf")
        pipe.zcount(keys["paths"], w5m, "+inf")
        pipe.zcount(keys["uas"], w10m, "+inf")
        pipe.zrangebyscore(keys["statuses"], w5m, "+inf")
        pipe.zrangebyscore(keys["sizes"], w5m, "+inf")
        pipe.zrangebyscore(keys["methods"], w5m, "+inf")
        pipe.zrangebyscore(keys["depths"], w5m, "+inf")
        pipe.zrangebyscore(keys["requests"], w10m, "+inf", withscores=True)

        for key in keys.values():
            pipe.expire(key, KEY_TTL)

        results = await pipe.execute()

        read_start = 14
        req_count_1m = results[read_start]
        req_count_5m = results[read_start + 1]
        req_count_10m = results[read_start + 2]
        unique_paths_5m = results[read_start + 3]
        unique_uas_10m = results[read_start + 4]
        statuses_5m = results[read_start + 5]
        sizes_5m = results[read_start + 6]
        methods_5m = results[read_start + 7]
        depths_5m = results[read_start + 8]
        requests_with_scores = results[read_start + 9]

        irt_mean, irt_std = _inter_request_time_stats(requests_with_scores)

        return {
            "req_count_1m": float(req_count_1m),
            "req_count_5m": float(req_count_5m),
            "req_count_10m": float(req_count_10m),
            "error_rate_5m": _error_rate(statuses_5m),
            "unique_paths_5m": float(unique_paths_5m),
            "unique_uas_10m": float(unique_uas_10m),
            "method_entropy_5m": _method_entropy(methods_5m),
            "avg_response_size_5m": _avg_response_size(sizes_5m),
            "status_diversity_5m": _status_diversity(statuses_5m),
            "path_depth_variance_5m": _path_depth_variance(depths_5m),
            "inter_request_time_mean": irt_mean,
            "inter_request_time_std": irt_std,
        }


def _error_rate(status_members: list[str]) -> float:
    """
    Ratio of 4xx/5xx responses to total responses.
    """
    if not status_members:
        return 0.0
    errors = sum(1 for m in status_members if int(m.split(":")[0]) >= 400)
    return errors / len(status_members)


def _avg_response_size(size_members: list[str]) -> float:
    """
    Mean response body size from size:request_id members.
    """
    if not size_members:
        return 0.0
    sizes = [int(m.split(":")[0]) for m in size_members]
    return sum(sizes) / len(sizes)


def _method_entropy(method_members: list[str]) -> float:
    """
    Shannon entropy of HTTP method distribution.
    """
    if not method_members:
        return 0.0
    methods = [m.split(":")[0] for m in method_members]
    counts = Counter(methods)
    total = len(methods)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _status_diversity(status_members: list[str]) -> float:
    """
    Count of distinct HTTP status codes.
    """
    if not status_members:
        return 0.0
    codes = {m.split(":")[0] for m in status_members}
    return float(len(codes))


def _path_depth_variance(depth_members: list[str]) -> float:
    """
    Population variance of path depth values.
    """
    if len(depth_members) < 2:
        return 0.0
    depths = [int(m.split(":")[0]) for m in depth_members]
    mean = sum(depths) / len(depths)
    return sum((d - mean) ** 2 for d in depths) / len(depths)


def _inter_request_time_stats(
    entries: list[tuple[str, float]],
) -> tuple[float, float]:
    """
    Mean and standard deviation of inter-request intervals in milliseconds.
    """
    if len(entries) < 2:
        return 0.0, 0.0
    timestamps = sorted(score for _, score in entries)
    deltas = [(timestamps[i + 1] - timestamps[i]) * 1000 for i in range(len(timestamps) - 1)]
    mean = sum(deltas) / len(deltas)
    if len(deltas) < 2:
        return mean, 0.0
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    return mean, math.sqrt(variance)
