"""
©AngelaMos | 2026
test_hex.py
"""

from rveng.engine import hex as hexmod


ELF_MAGIC_LINE = (
    "00000000  7f 45 4c 46 02 01 01 00  "
    "00 00 00 00 00 00 00 00  |.ELF............|"
)


def test_first_line_matches_known_elf_header(gate_bytes: bytes):
    first = hexmod.hexdump(gate_bytes[: 16])
    assert first == ELF_MAGIC_LINE


def test_ascii_gutter_marks_non_printable():
    line = hexmod.HexLine(offset = 0, data = b"\x7fELF\x00")
    assert line.ascii_gutter() == ".ELF."


def test_base_offset_is_applied():
    line = next(hexmod.iter_lines(b"\x90", base = 0x401060))
    assert line.render().startswith("00401060  90")


def test_short_final_line_pads_hex_but_not_ascii():
    dump = hexmod.hexdump(b"\x41\x42")
    assert dump.startswith("00000000  41 42 ")
    assert dump.endswith("|AB|")


def test_full_and_partial_line_count():
    data = bytes(range(20))
    lines = list(hexmod.iter_lines(data))
    assert len(lines) == 2
    assert lines[0].offset == 0
    assert lines[1].offset == 16
