"""
©AngelaMos | 2026
test_entropy.py
"""


import os

from dlp_scanner.detectors.entropy import (
    shannon_entropy,
    shannon_entropy_str,
    detect_high_entropy_regions,
    EntropyDetector,
)


class TestShannonEntropy:
    def test_all_same_bytes_is_zero(self) -> None:
        data = b"\x00" * 100
        assert shannon_entropy(data) == 0.0

    def test_empty_data_is_zero(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_english_text_in_expected_range(self) -> None:
        text = b"the quick brown fox jumps over the lazy dog"
        h = shannon_entropy(text)
        assert 3.5 <= h <= 5.0

    def test_random_bytes_near_maximum(self) -> None:
        data = os.urandom(10000)
        h = shannon_entropy(data)
        assert h > 7.5

    def test_two_byte_values_is_one_bit(self) -> None:
        data = b"\x00\x01" * 50
        h = shannon_entropy(data)
        assert abs(h - 1.0) < 0.01

    def test_string_entropy_matches_bytes(self) -> None:
        text = "hello world"
        h_str = shannon_entropy_str(text)
        h_bytes = shannon_entropy(text.encode("utf-8"))
        assert abs(h_str - h_bytes) < 0.001


class TestHighEntropyRegions:
    def test_random_data_detected(self) -> None:
        data = os.urandom(1024)
        regions = detect_high_entropy_regions(data, threshold = 7.0)
        assert len(regions) > 0

    def test_plaintext_not_detected(self) -> None:
        data = b"the quick brown fox " * 100
        regions = detect_high_entropy_regions(data, threshold = 7.0)
        assert len(regions) == 0

    def test_short_data_below_window(self) -> None:
        data = os.urandom(100)
        regions = detect_high_entropy_regions(
            data,
            threshold = 7.0,
            window_size = 256
        )
        assert len(regions) <= 1


class TestEntropyDetector:
    def test_detect_high_entropy_text(self) -> None:
        import base64

        detector = EntropyDetector(threshold = 5.5)
        raw = os.urandom(2048)
        high_entropy_text = base64.b85encode(raw).decode("ascii")
        matches = detector.detect(high_entropy_text)
        assert len(matches) > 0
        assert all(m.rule_id == "NET_HIGH_ENTROPY" for m in matches)

    def test_no_detection_in_normal_text(self) -> None:
        detector = EntropyDetector(threshold = 7.0)
        text = "This is a normal text document with nothing suspicious."
        matches = detector.detect(text)
        assert len(matches) == 0
