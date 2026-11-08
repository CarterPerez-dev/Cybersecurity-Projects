"""
©AngelaMos | 2026
test_strings.py
"""

from rveng.engine import elf, strings


def test_extract_basic_runs():
    data = b"\x00\x01hello\x00\xffworld!!\x00"
    got = strings.extract(data, min_length = 4)
    assert [s.text for s in got] == ["hello", "world!!"]


def test_min_length_filters_short_runs():
    data = b"ab\x00abcd\x00"
    got = strings.extract(data, min_length = 4)
    assert [s.text for s in got] == ["abcd"]


def test_secret_found_in_rodata_at_known_offset(gate_bytes: bytes):
    image = elf.ElfImage(gate_bytes)
    rodata = image.section(".rodata")
    got = strings.extract_in_section(image, rodata)
    texts = [s.text for s in got]
    assert "the_flag_is_here" in texts
    secret = next(s for s in got if s.text == "the_flag_is_here")
    assert secret.offset == 0x2004


def test_find_returns_offset(gate_bytes: bytes):
    hit = strings.find(gate_bytes, "wrong number")
    assert hit is not None
    assert hit.text == "wrong number"
