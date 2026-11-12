"""
©AngelaMos | 2026
test_challenge.py
"""

import pytest

from rveng.engine import challenge as ch
from rveng.engine import patch


JNE_FILE_OFFSET = 0x1154
NOP_NOP = b"\x90\x90"

SOURCE = "int check(int n){ return n == 1337; }"


def _challenge(answer, binary = b"") -> ch.Challenge:
    return ch.Challenge(
        id = "t",
        module = "m",
        title = "t",
        mission = "find it",
        binary = binary,
        source = SOURCE,
        answer = answer
    )


def test_normalize_int_accepts_hex_dec_and_h():
    assert ch.normalize_int("0x539") == 1337
    assert ch.normalize_int("539h") == 1337
    assert ch.normalize_int(" 1337 ") == 1337


def test_found_value_numeric_correct_reveals_source():
    c = _challenge(ch.FoundValue(1337))
    result = ch.grade(c, "0x539")
    assert result.correct
    assert result.revealed_source == SOURCE


def test_found_value_wrong_hides_source():
    c = _challenge(ch.FoundValue(1337))
    result = ch.grade(c, "1234")
    assert not result.correct
    assert result.revealed_source is None


def test_found_value_string():
    c = _challenge(ch.FoundValue("the_flag_is_here"))
    assert ch.grade(c, "the_flag_is_here").correct
    assert not ch.grade(c, "nope").correct


def test_identified_symbol_case_insensitive():
    c = _challenge(ch.IdentifiedSymbol("check"))
    assert ch.grade(c, "Check").correct
    assert not ch.grade(c, "main").correct


def test_category_property():
    assert _challenge(ch.FoundValue(1)).category == ch.FOUND_VALUE
    assert _challenge(ch.IdentifiedSymbol("x")).category == ch.IDENTIFIED_SYMBOL
    assert _challenge(ch.PatchedBytes(0, b"")).category == ch.PATCHED_BYTES


def test_patched_bytes_graded_by_static_diff(gate_bytes: bytes):
    known_good = patch.apply(gate_bytes, JNE_FILE_OFFSET, NOP_NOP)
    c = _challenge(ch.PatchedBytes(JNE_FILE_OFFSET, known_good), binary = gate_bytes)
    assert ch.grade(c, NOP_NOP).correct
    assert ch.grade(c, "9090").correct
    assert not ch.grade(c, b"\x75\x07").correct
