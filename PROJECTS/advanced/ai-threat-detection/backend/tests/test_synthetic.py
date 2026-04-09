"""
©AngelaMos | 2026
test_synthetic.py

Tests synthetic HTTP traffic generators and mixed dataset
assembly for ML training

TestGenerators validates all 7 per-type generators (SQLi,
XSS, traversal, Log4Shell, SSRF, scanner, normal) return
correct counts, contain expected payload patterns (OR/UNION
for SQLi, script/alert for XSS, ../ for traversal), return
ParsedLogEntry instances, and pass through feature
extraction and encoding to 35-dim vectors. TestMixedDataset
verifies correct X shape (n, 35), dual-label y, matching
label counts, and finite feature values

Connects to:
  ml/synthetic            - all generate_* functions,
                            generate_mixed_dataset
  core/features/extractor - extract_request_features
  core/features/encoder   - encode_for_inference
"""

import numpy as np

from app.core.features.encoder import encode_for_inference
from app.core.features.extractor import extract_request_features
from app.core.features.mappings import WINDOWED_FEATURE_NAMES
from app.core.ingestion.parsers import ParsedLogEntry
from ml.synthetic import (
    generate_log4shell_requests,
    generate_mixed_dataset,
    generate_normal_requests,
    generate_scanner_requests,
    generate_sqli_requests,
    generate_ssrf_requests,
    generate_traversal_requests,
    generate_xss_requests,
)

class TestGenerators:
    """
    Test individual attack and normal traffic generators
    """

    def test_sqli_returns_correct_count(self, ) -> None:
        """
        generate_sqli_requests returns the requested count
        """
        results = generate_sqli_requests(10)
        assert len(results) == 10

    def test_xss_returns_correct_count(self, ) -> None:
        """
        generate_xss_requests returns the requested count
        """
        results = generate_xss_requests(10)
        assert len(results) == 10

    def test_traversal_returns_correct_count(self, ) -> None:
        """
        generate_traversal_requests returns the requested count
        """
        results = generate_traversal_requests(10)
        assert len(results) == 10

    def test_log4shell_returns_correct_count(self, ) -> None:
        """
        generate_log4shell_requests returns the requested count
        """
        results = generate_log4shell_requests(10)
        assert len(results) == 10

    def test_ssrf_returns_correct_count(self, ) -> None:
        """
        generate_ssrf_requests returns the requested count
        """
        results = generate_ssrf_requests(10)
        assert len(results) == 10

    def test_scanner_returns_correct_count(self, ) -> None:
        """
        generate_scanner_requests returns the requested count
        """
        results = generate_scanner_requests(10)
        assert len(results) == 10

    def test_normal_returns_correct_count(self, ) -> None:
        """
        generate_normal_requests returns the requested count
        """
        results = generate_normal_requests(20)
        assert len(results) == 20

    def test_sqli_has_attack_payloads(self, ) -> None:
        """
        SQLi entries contain injection patterns in query string
        """
        results = generate_sqli_requests(20)
        has_sqli = any("OR" in e.query_string or "UNION" in e.query_string
                       or "DROP" in e.query_string or "SLEEP" in e.query_string
                       for e in results)
        assert has_sqli

    def test_xss_has_script_patterns(self, ) -> None:
        """
        XSS entries contain script-related patterns
        """
        results = generate_xss_requests(20)
        has_xss = any(
            "script" in e.query_string.lower() or "alert" in
            e.query_string.lower() or "onerror" in e.query_string.lower()
            for e in results)
        assert has_xss

    def test_traversal_has_dotdot(self) -> None:
        """
        Traversal entries contain ../ in path
        """
        results = generate_traversal_requests(20)
        has_traversal = any(".." in e.path or "%2e" in e.path.lower()
                            for e in results)
        assert has_traversal

    def test_all_entries_are_parsed_log_entry(self, ) -> None:
        """
        All generators return ParsedLogEntry instances
        """
        generators = [
            generate_sqli_requests,
            generate_xss_requests,
            generate_traversal_requests,
            generate_log4shell_requests,
            generate_ssrf_requests,
            generate_scanner_requests,
            generate_normal_requests,
        ]
        for gen in generators:
            results = gen(5)
            assert all(isinstance(e, ParsedLogEntry) for e in results)

    def test_entries_pass_feature_extraction(self, ) -> None:
        """
        All generated entries extract and encode without error
        """
        generators = [
            generate_sqli_requests,
            generate_xss_requests,
            generate_traversal_requests,
            generate_log4shell_requests,
            generate_ssrf_requests,
            generate_scanner_requests,
            generate_normal_requests,
        ]
        for gen in generators:
            for entry in gen(5):
                features = extract_request_features(entry)
                for name in WINDOWED_FEATURE_NAMES:
                    features[name] = 0.0
                vector = encode_for_inference(features)
                assert len(vector) == 35


class TestMixedDataset:
    """
    Test end-to-end mixed dataset generation
    """

    def test_returns_correct_shape(self) -> None:
        """
        generate_mixed_dataset returns X with 35 columns
        """
        X, y = generate_mixed_dataset(100, 60)
        assert X.shape == (160, 35)

    def test_contains_both_labels(self) -> None:
        """
        y array contains both 0 and 1
        """
        _, y = generate_mixed_dataset(100, 60)
        assert 0 in y
        assert 1 in y

    def test_label_counts_match(self) -> None:
        """
        Label counts match requested normal and attack counts
        """
        _, y = generate_mixed_dataset(100, 60)
        assert np.sum(y == 0) == 100
        assert np.sum(y == 1) == 60

    def test_values_are_finite(self) -> None:
        """
        All feature values are finite
        """
        X, _ = generate_mixed_dataset(50, 30)
        assert np.all(np.isfinite(X))
