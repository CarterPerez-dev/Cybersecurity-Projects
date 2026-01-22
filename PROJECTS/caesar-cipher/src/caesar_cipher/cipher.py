"""
ⒸAngelaMos | 2026
cipher.py
"""

from caesar_cipher.constants import (
    ALPHABET_SIZE,
    LOWERCASE_LETTERS,
    UPPERCASE_LETTERS,
)


class CaesarCipher:
    """
    Caesar cipher implementation with configurable shift key and alphabet support
    """
    def __init__(self, key: int, alphabet: str | None = None) -> None:
        """
        Initialize Caesar cipher with shift key and optional custom alphabet
        """
        if not -25 <= key <= 26:
            msg = "Key must be between -25 and 26"
            raise ValueError(msg)

        self.key = key % ALPHABET_SIZE
        self.alphabet = alphabet or (UPPERCASE_LETTERS + LOWERCASE_LETTERS)

        if alphabet and len(set(alphabet)) != len(alphabet):
            msg = "Alphabet must not contain duplicate characters"
            raise ValueError(msg)

    def _shift_char(self, char: str, shift: int) -> str:
        """
        Shift a single character by the specified amount while preserving case
        """
        if char in UPPERCASE_LETTERS:
            idx = UPPERCASE_LETTERS.index(char)
            return UPPERCASE_LETTERS[(idx + shift) % ALPHABET_SIZE]
        if char in LOWERCASE_LETTERS:
            idx = LOWERCASE_LETTERS.index(char)
            return LOWERCASE_LETTERS[(idx + shift) % ALPHABET_SIZE]
        return char

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the configured shift key
        """
        return "".join(self._shift_char(char, self.key) for char in plaintext)

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using the configured shift key
        """
        return "".join(self._shift_char(char, -self.key) for char in ciphertext)

    @staticmethod
    def crack(ciphertext: str) -> list[tuple[int, str]]:
        """
        Attempt all possible shifts to decrypt ciphertext without knowing the key
        """
        results = []
        for shift in range(ALPHABET_SIZE):
            cipher = CaesarCipher(key = shift)
            decrypted = cipher.decrypt(ciphertext)
            results.append((shift, decrypted))
        return results
