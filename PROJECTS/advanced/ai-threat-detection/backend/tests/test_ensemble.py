"""
©AngelaMos | 2026
test_ensemble.py

Tests ensemble score normalization, weighted fusion, ML/rule
blending, and severity classification functions

TestScoreNormalization validates AE error below threshold
maps below 0.5, 3x threshold caps at 1.0, zero error maps
to 0.0, negative IF score maps above 0.5, positive below
0.5, and zero maps to 0.5. TestEnsembleFusion validates
weighted average computation, all-zero scores fuse to 0.0,
all-one scores fuse to 1.0, and partial model support.
TestBlendScores validates ML/rule blending at various
weights and clamping. TestClassifySeverity validates HIGH
at >= 0.7, MEDIUM at [0.5, 0.7), LOW below 0.5

Connects to:
  core/detection/ensemble - normalize_ae_score,
                            normalize_if_score, fuse_scores,
                            blend_scores, classify_severity
"""

from app.core.detection.ensemble import (
    blend_scores,
    classify_severity,
    fuse_scores,
    normalize_ae_score,
    normalize_if_score,
)


class TestScoreNormalization:

    def test_ae_score_below_threshold(self) -> None:
        """
        AE error below threshold maps to a score below 0.5.
        """
        result = normalize_ae_score(0.05, threshold=0.10)
        assert abs(result - 0.25) < 1e-6

    def test_ae_score_above_double_threshold_caps_at_one(self) -> None:
        """
        AE error at 3x threshold is capped at 1.0.
        """
        result = normalize_ae_score(0.30, threshold=0.10)
        assert result == 1.0

    def test_ae_score_zero_error(self) -> None:
        """
        Zero reconstruction error maps to a score of 0.0.
        """
        result = normalize_ae_score(0.0, threshold=0.10)
        assert result == 0.0

    def test_if_score_negative(self) -> None:
        """
        Negative IF score (anomalous region) maps above 0.5.
        """
        result = normalize_if_score(-0.5)
        assert abs(result - 0.75) < 1e-6

    def test_if_score_positive(self) -> None:
        """
        Positive IF score (normal region) maps below 0.5.
        """
        result = normalize_if_score(0.5)
        assert abs(result - 0.25) < 1e-6

    def test_if_score_zero(self) -> None:
        """
        Zero IF score maps to exactly 0.5.
        """
        result = normalize_if_score(0.0)
        assert abs(result - 0.5) < 1e-6


class TestEnsembleFusion:

    def test_weighted_average(self) -> None:
        """
        Fused score is the weighted average of AE, RF, and IF scores.
        """
        scores = {"ae": 0.8, "rf": 0.6, "if": 0.5}
        weights = {"ae": 0.4, "rf": 0.4, "if": 0.2}
        result = fuse_scores(scores, weights)
        expected = 0.8 * 0.4 + 0.6 * 0.4 + 0.5 * 0.2
        assert abs(result - expected) < 1e-6

    def test_all_zero_scores(self) -> None:
        """
        All-zero model scores fuse to 0.0.
        """
        scores = {"ae": 0.0, "rf": 0.0, "if": 0.0}
        weights = {"ae": 0.4, "rf": 0.4, "if": 0.2}
        assert fuse_scores(scores, weights) == 0.0

    def test_all_max_scores(self) -> None:
        """
        All-one model scores fuse to 1.0.
        """
        scores = {"ae": 1.0, "rf": 1.0, "if": 1.0}
        weights = {"ae": 0.4, "rf": 0.4, "if": 0.2}
        assert abs(fuse_scores(scores, weights) - 1.0) < 1e-6

    def test_partial_models(self) -> None:
        """
        Fusion works correctly with only two models present.
        """
        scores = {"ae": 0.9, "rf": 0.7}
        weights = {"ae": 0.5, "rf": 0.5}
        expected = 0.9 * 0.5 + 0.7 * 0.5
        assert abs(fuse_scores(scores, weights) - expected) < 1e-6


class TestBlendScores:

    def test_blend_with_rule_score(self) -> None:
        """
        ML and rule scores blend according to the specified ml_weight.
        """
        result = blend_scores(ml_score=0.7, rule_score=0.9, ml_weight=0.7)
        expected = 0.7 * 0.7 + 0.9 * 0.3
        assert abs(result - expected) < 1e-6

    def test_blend_full_ml_weight(self) -> None:
        """
        ml_weight of 1.0 returns the pure ML score.
        """
        result = blend_scores(ml_score=0.8, rule_score=0.2, ml_weight=1.0)
        assert abs(result - 0.8) < 1e-6

    def test_blend_full_rule_weight(self) -> None:
        """
        ml_weight of 0.0 returns the pure rule score.
        """
        result = blend_scores(ml_score=0.8, rule_score=0.2, ml_weight=0.0)
        assert abs(result - 0.2) < 1e-6

    def test_blend_clamped_to_one(self) -> None:
        """
        Blended score is clamped to 1.0 even when both inputs are 1.0.
        """
        result = blend_scores(ml_score=1.0, rule_score=1.0, ml_weight=0.5)
        assert result <= 1.0


class TestClassifySeverity:

    def test_high(self) -> None:
        """
        Scores >= 0.7 classify as HIGH.
        """
        assert classify_severity(0.8) == "HIGH"
        assert classify_severity(0.7) == "HIGH"
        assert classify_severity(1.0) == "HIGH"

    def test_medium(self) -> None:
        """
        Scores in [0.5, 0.7) classify as MEDIUM.
        """
        assert classify_severity(0.55) == "MEDIUM"
        assert classify_severity(0.5) == "MEDIUM"
        assert classify_severity(0.69) == "MEDIUM"

    def test_low(self) -> None:
        """
        Scores below 0.5 classify as LOW.
        """
        assert classify_severity(0.3) == "LOW"
        assert classify_severity(0.0) == "LOW"
        assert classify_severity(0.49) == "LOW"
