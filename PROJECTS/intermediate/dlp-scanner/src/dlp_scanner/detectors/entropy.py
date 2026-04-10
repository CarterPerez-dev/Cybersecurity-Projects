"""
©AngelaMos | 2026
entropy.py
"""


import math
from collections import Counter

from dlp_scanner.constants import DEFAULT_ENTROPY_THRESHOLD
from dlp_scanner.detectors.base import DetectorMatch


WINDOW_SIZE: int = 256
WINDOW_STEP: int = 128


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy in bits per byte
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values()
    )


def shannon_entropy_str(text: str) -> float:
    """
    Calculate Shannon entropy for a string
    """
    return shannon_entropy(text.encode("utf-8"))


def detect_high_entropy_regions(
    data: bytes,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    window_size: int = WINDOW_SIZE,
    step: int = WINDOW_STEP,
) -> list[tuple[int,
                int,
                float]]:
    """
    Find regions of high entropy using a sliding window

    Returns list of (start_offset, end_offset, entropy_value)
    """
    if len(data) < window_size:
        h = shannon_entropy(data)
        if h >= threshold:
            return [(0, len(data), h)]
        return []

    regions: list[tuple[int, int, float]] = []
    i = 0

    while i + window_size <= len(data):
        window = data[i : i + window_size]
        h = shannon_entropy(window)

        if h >= threshold:
            end = i + window_size
            while end + step <= len(data):
                next_window = data[end - window_size + step : end + step]
                next_h = shannon_entropy(next_window)
                if next_h < threshold:
                    break
                h = max(h, next_h)
                end += step

            regions.append((i, end, h))
            i = end
        else:
            i += step

    return regions


class EntropyDetector:
    """
    Detects high-entropy data that may indicate encrypted
    or compressed content
    """
    def __init__(
        self,
        threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    ) -> None:
        self._threshold = threshold

    def detect(self, text: str) -> list[DetectorMatch]:
        """
        Scan text for high-entropy regions
        """
        data = text.encode("utf-8")
        regions = detect_high_entropy_regions(
            data,
            threshold = self._threshold,
        )

        matches: list[DetectorMatch] = []
        for start, end, entropy_val in regions:
            score = min(
                1.0,
                (entropy_val - self._threshold) /
                (8.0 - self._threshold) * 0.5 + 0.5,
            )

            matches.append(
                DetectorMatch(
                    rule_id = "NET_HIGH_ENTROPY",
                    rule_name = "High Entropy Data",
                    start = start,
                    end = end,
                    matched_text =
                    f"[{end - start} bytes, H={entropy_val:.2f}]",
                    score = score,
                    context_keywords = [],
                    compliance_frameworks = [],
                )
            )

        return matches
