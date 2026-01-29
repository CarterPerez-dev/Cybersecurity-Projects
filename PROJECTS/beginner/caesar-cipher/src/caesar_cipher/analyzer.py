"""
ⒸAngelaMos | 2026
analyzer.py
"""

from collections import Counter

from caesar_cipher.constants import ENGLISH_LETTER_FREQUENCIES


class FrequencyAnalyzer:
    """
    Analyzes text for English language patterns using letter frequency distribution
    """
    def __init__(self) -> None:
        """
        Initialize analyzer with English letter frequency reference data
        """
        self.reference_frequencies = ENGLISH_LETTER_FREQUENCIES

    def calculate_chi_squared(self, text: str) -> float:
        """
        Calculate chi-squared statistic comparing text to expected English frequencies
        """
        text_upper = text.upper()
        letter_counts = Counter(char for char in text_upper if char.isalpha())

        if not letter_counts:
            return float("inf")

        total_letters = sum(letter_counts.values())
        chi_squared = 0.0

        for letter, expected_freq in self.reference_frequencies.items():
            observed_count = letter_counts.get(letter, 0)
            expected_count = (expected_freq / 100) * total_letters

            if expected_count > 0:
                chi_squared += (
                    (observed_count - expected_count)**2
                ) / expected_count

        return chi_squared

    def score_text(self, text: str) -> float:
        """
        Score text likelihood of being valid English (lower is better)
        """
        return self.calculate_chi_squared(text)

    def rank_candidates(self,
                        candidates: list[tuple[int,
                                               str]]) -> list[tuple[int,
                                                                    str,
                                                                    float]]:
        """
        Rank decryption candidates by their English frequency score
        """
        scored = [
            (shift,
             text,
             self.score_text(text)) for shift, text in candidates
        ]
        return sorted(scored, key = lambda x: x[2])
