"""
ⒸAngelaMos | 2026
test_analyzer.py
"""

from caesar_cipher.analyzer import FrequencyAnalyzer
from caesar_cipher.cipher import CaesarCipher


class TestFrequencyAnalyzer:
    def test_calculate_chi_squared_english_text(self) -> None:
        analyzer = FrequencyAnalyzer()
        english_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        score = analyzer.calculate_chi_squared(english_text)
        assert score < 150

    def test_calculate_chi_squared_gibberish(self) -> None:
        analyzer = FrequencyAnalyzer()
        gibberish = "ZZZZZ QQQQQ XXXXX"
        score = analyzer.calculate_chi_squared(gibberish)
        assert score > 100

    def test_calculate_chi_squared_empty_string(self) -> None:
        analyzer = FrequencyAnalyzer()
        assert analyzer.calculate_chi_squared("") == float("inf")

    def test_score_text_lowercase(self) -> None:
        analyzer = FrequencyAnalyzer()
        score = analyzer.score_text("hello world")
        assert isinstance(score, float)
        assert score >= 0

    def test_rank_candidates_orders_by_score(self) -> None:
        analyzer = FrequencyAnalyzer()
        candidates = [
            (0,
             "gibberish zzz"),
            (1,
             "the quick brown fox"),
            (2,
             "qqq xxx zzz"),
        ]
        ranked = analyzer.rank_candidates(candidates)

        assert len(ranked) == 3
        assert ranked[0][1] == "the quick brown fox"
        assert ranked[0][2] < ranked[1][2]
        assert ranked[1][2] < ranked[2][2]

    def test_rank_candidates_with_actual_cipher(self) -> None:
        cipher = CaesarCipher(key = 3)
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        ciphertext = cipher.encrypt(plaintext)

        candidates = CaesarCipher.crack(ciphertext)
        analyzer = FrequencyAnalyzer()
        ranked = analyzer.rank_candidates(candidates)

        best_shift, best_text, _best_score = ranked[0]
        assert best_shift == 3
        assert best_text == plaintext

    def test_rank_candidates_empty_list(self) -> None:
        analyzer = FrequencyAnalyzer()
        ranked = analyzer.rank_candidates([])
        assert ranked == []
