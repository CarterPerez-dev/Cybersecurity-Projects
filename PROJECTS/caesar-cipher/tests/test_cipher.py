"""
ⒸAngelaMos | 2026
test_cipher.py
"""

import pytest

from caesar_cipher.cipher import CaesarCipher


class TestCaesarCipher:
    def test_encrypt_basic(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("HELLO") == "KHOOR"

    def test_encrypt_lowercase(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("hello") == "khoor"

    def test_encrypt_mixed_case(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("Hello World") == "Khoor Zruog"

    def test_encrypt_preserves_spaces(self) -> None:
        cipher = CaesarCipher(key = 5)
        assert cipher.encrypt("ABC XYZ") == "FGH CDE"

    def test_encrypt_preserves_punctuation(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("Hello, World!") == "Khoor, Zruog!"

    def test_encrypt_preserves_numbers(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("Test123") == "Whvw123"

    def test_decrypt_basic(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.decrypt("KHOOR") == "HELLO"

    def test_decrypt_lowercase(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.decrypt("khoor") == "hello"

    def test_encrypt_decrypt_roundtrip(self) -> None:
        cipher = CaesarCipher(key = 13)
        original = "The Quick Brown Fox Jumps Over The Lazy Dog!"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == original

    def test_key_wrapping(self) -> None:
        cipher = CaesarCipher(key = 26)
        assert cipher.encrypt("ABC") == "ABC"

    def test_negative_key(self) -> None:
        cipher = CaesarCipher(key = -3)
        assert cipher.encrypt("HELLO") == "EBIIL"

    def test_zero_key(self) -> None:
        cipher = CaesarCipher(key = 0)
        assert cipher.encrypt("HELLO") == "HELLO"

    def test_key_validation_too_large(self) -> None:
        with pytest.raises(ValueError, match = "Key must be between -25 and 26"):
            CaesarCipher(key = 30)

    def test_key_validation_too_small(self) -> None:
        with pytest.raises(ValueError, match = "Key must be between -25 and 26"):
            CaesarCipher(key = -30)

    def test_crack_returns_all_shifts(self) -> None:
        results = CaesarCipher.crack("KHOOR")
        assert len(results) == 26

    def test_crack_finds_correct_shift(self) -> None:
        cipher = CaesarCipher(key = 3)
        encrypted = cipher.encrypt("HELLO")
        results = CaesarCipher.crack(encrypted)
        shifts_dict = dict(results)
        assert shifts_dict[3] == "HELLO"

    def test_empty_string(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("") == ""
        assert cipher.decrypt("") == ""

    def test_alphabet_wraparound_uppercase(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("XYZ") == "ABC"

    def test_alphabet_wraparound_lowercase(self) -> None:
        cipher = CaesarCipher(key = 3)
        assert cipher.encrypt("xyz") == "abc"
