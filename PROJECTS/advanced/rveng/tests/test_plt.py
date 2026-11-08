"""
©AngelaMos | 2026
test_plt.py
"""

from rveng.engine.elf import ElfImage
from rveng.engine.plt import _stub_got_slot, plt_map, resolve_call


PUTS = 0x401030
PRINTF = 0x401040
ATOI = 0x401050


def test_plt_map_names_the_three_imports(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    assert plt_map(image) == {PUTS: "puts", PRINTF: "printf", ATOI: "atoi"}


def test_plt0_stub_is_not_treated_as_an_import(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    assert 0x401020 not in plt_map(image)


def test_resolve_call_maps_target_to_name(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    assert resolve_call(image, ATOI) == "atoi"
    assert resolve_call(image, PUTS) == "puts"


def test_resolve_call_returns_none_for_local_target(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    assert resolve_call(image, 0x401146) is None


def test_plt_resolution_survives_stripping(gate_stripped_bytes: bytes):
    image = ElfImage(gate_stripped_bytes)
    assert plt_map(image) == {PUTS: "puts", PRINTF: "printf", ATOI: "atoi"}


def test_stub_decode_of_classic_entry():
    entry = bytes.fromhex("ff25ca2f0000") + b"\x00" * 10
    assert _stub_got_slot(entry, 0x401030, "<") == 0x404000


def test_stub_decode_tolerates_truncated_jmp_pattern():
    entry = b"\x90" * 11 + b"\xff\x25\x00\x00\x00"
    assert _stub_got_slot(entry, 0x401030, "<") is None


def test_stub_decode_returns_none_without_jmp():
    assert _stub_got_slot(b"\x90" * 16, 0x401030, "<") is None
