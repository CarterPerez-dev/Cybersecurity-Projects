"""Known-answer tests for the detection engine.

Every domain used here is either a documentation-reserved name or a
crafted lookalike, never a real brand's actual production domain, so
these tests stay meaningful without pointing detection logic at a real
company by name.
"""

from __future__ import annotations

import pytest

from glasswatch.confusables import decode_and_skeletonize, skeletonize
from glasswatch.detect import (
    Finding,
    is_legitimate,
    levenshtein,
    score_domain,
)
from glasswatch.watchlist import Brand

BRAND = Brand(name="Acme Pay", domain="acmepay.com", core_name="acmepay")


class TestLevenshtein:
    def test_identical_strings(self):
        assert levenshtein("acmepay", "acmepay") == 0

    def test_empty_strings(self):
        assert levenshtein("", "") == 0
        assert levenshtein("acme", "") == 4
        assert levenshtein("", "acme") == 4

    def test_classic_kitten_sitting(self):
        # the textbook example, verifiable by hand: kitten -> sitting is 3 edits
        assert levenshtein("kitten", "sitting") == 3

    def test_single_insertion(self):
        assert levenshtein("acmepay", "acmeepay") == 1

    def test_single_substitution(self):
        assert levenshtein("acmepay", "acmepay".replace("c", "k")) == 1


class TestSkeletonize:
    def test_ascii_passthrough_is_casefolded(self):
        assert skeletonize("AcmePay") == "acmepay"

    def test_cyrillic_a_collapses_to_latin_a(self):
        # U+0430 CYRILLIC SMALL LETTER A, visually identical to "a" in most fonts
        cyrillic_label = "аcmepay"
        assert cyrillic_label != "acmepay"
        assert skeletonize(cyrillic_label) == "acmepay"


class TestPunycode:
    def test_decodes_known_vector(self):
        # xn--pypal-4ve is the real IDNA encoding of "pаypal" (Cyrillic а),
        # verified by round-tripping through Python's own idna codec.
        unicode_label, skeleton, was_punycode = decode_and_skeletonize("xn--pypal-4ve")
        assert was_punycode is True
        assert unicode_label == "pаypal"
        assert skeleton == "paypal"

    def test_plain_label_is_not_punycode(self):
        unicode_label, skeleton, was_punycode = decode_and_skeletonize("acmepay")
        assert was_punycode is False
        assert unicode_label == "acmepay"
        assert skeleton == "acmepay"


class TestIsLegitimate:
    def test_exact_apex_match(self):
        assert is_legitimate("acmepay.com", "acmepay.com") is True

    def test_real_subdomain(self):
        assert is_legitimate("api.acmepay.com", "acmepay.com") is True

    def test_apex_used_as_someone_elses_subdomain(self):
        # "acmepay.com" is not a suffix of this string, "evil.io" is
        assert is_legitimate("acmepay.com.evil.io", "acmepay.com") is False

    def test_unrelated_domain(self):
        assert is_legitimate("unrelated.example", "acmepay.com") is False


class TestScoreDomain:
    def test_legitimate_apex_produces_no_finding(self):
        assert score_domain("acmepay.com", BRAND) is None

    def test_legitimate_subdomain_produces_no_finding(self):
        assert score_domain("login.acmepay.com", BRAND) is None

    def test_unrelated_domain_produces_no_finding(self):
        assert score_domain("totally-unrelated-example.net", BRAND) is None

    def test_homoglyph_exact_match(self):
        finding = score_domain("аcmepay.com", BRAND)
        assert isinstance(finding, Finding)
        assert finding.score == 60
        assert finding.severity == "high"
        assert any(r.startswith("homoglyph-exact") for r in finding.reasons)

    def test_punycode_homoglyph_scores_higher_than_plain_homoglyph(self):
        # xn--cmepay-nявный isn't real punycode; build a real one instead
        # by encoding the same homoglyph label glasswatch would decode.
        label = ("аcmepay").encode("idna").decode("ascii")
        finding = score_domain(f"{label}.com", BRAND)
        assert finding is not None
        assert finding.score == 75  # 60 homoglyph + 15 punycode bonus
        assert finding.severity == "critical"
        assert "punycode-encoded" in finding.reasons

    def test_typosquat_distance_one(self):
        finding = score_domain("acmeepay.com", BRAND)
        assert finding is not None
        assert finding.score == 45
        assert finding.severity == "high"
        assert any("typosquat-distance-1" in r for r in finding.reasons)

    def test_combosquat_with_keyword(self):
        finding = score_domain("acmepay-login-secure.net", BRAND)
        assert finding is not None
        assert finding.score == 25
        assert finding.severity == "medium"
        assert any(r.startswith("combosquat:") for r in finding.reasons)

    def test_brand_substring_without_keyword_scores_low(self):
        finding = score_domain("acmepaystore.com", BRAND)
        assert finding is not None
        assert finding.score == 12
        assert finding.severity == "low"
        assert any(r.startswith("brand-substring:") for r in finding.reasons)

    def test_apex_domain_used_as_prefix_under_another_domain(self):
        finding = score_domain("acmepay.com.account-verify.net", BRAND)
        assert finding is not None
        assert finding.severity == "high"
        assert any(r.startswith("apex-domain-as-prefix:") for r in finding.reasons)

    @pytest.mark.parametrize("domain", ["", "."])
    def test_degenerate_input_does_not_crash(self, domain):
        assert score_domain(domain, BRAND) is None
