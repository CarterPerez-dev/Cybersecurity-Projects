"""
©AngelaMos | 2026
test_robustness.py
"""

import struct

import pytest

from rveng.engine import challenge as ch
from rveng.engine import disasm, elf, patch


JNE_FILE_OFFSET = 0x1154
NOP_NOP = b"\x90\x90"
E_SHOFF = 0x28
E_SHNUM = 0x3C
E_SHSTRNDX = 0x3E


def _corrupt(data: bytes, offset: int, fmt: str, value: int) -> bytes:
    buf = bytearray(data)
    struct.pack_into("<" + fmt, buf, offset, value)
    return bytes(buf)


def test_bad_shstrndx_raises_notanelf(gate_bytes: bytes):
    bad = _corrupt(gate_bytes, E_SHSTRNDX, "H", 0xFFFF)
    with pytest.raises(elf.NotAnElf):
        elf.ElfImage(bad)


def test_section_table_past_eof_raises_notanelf(gate_bytes: bytes):
    bad = _corrupt(gate_bytes, E_SHOFF, "Q", len(gate_bytes) + 0x1000)
    with pytest.raises(elf.NotAnElf):
        elf.ElfImage(bad)


def test_huge_shnum_raises_notanelf(gate_bytes: bytes):
    bad = _corrupt(gate_bytes, E_SHNUM, "H", 0xFFFF)
    with pytest.raises(elf.NotAnElf):
        elf.ElfImage(bad)


def test_truncated_file_raises_notanelf(gate_bytes: bytes):
    with pytest.raises(elf.NotAnElf):
        elf.ElfImage(gate_bytes[: 0x1000])


@pytest.mark.parametrize("bad_hex", ["zz", "909", "0xff", "not hex"])
def test_bad_hex_patch_submission_does_not_crash(gate_bytes: bytes, bad_hex: str):
    known_good = patch.apply(gate_bytes, JNE_FILE_OFFSET, NOP_NOP)
    c = ch.Challenge(
        id = "t",
        module = "m",
        title = "t",
        mission = "m",
        binary = gate_bytes,
        source = "src",
        answer = ch.PatchedBytes(JNE_FILE_OFFSET,
                                 known_good)
    )
    result = ch.grade(c, bad_hex)
    assert result.correct is False
    assert result.revealed_source is None


def test_disassemble_symbol_rejects_undefined_symbol(gate_bytes: bytes):
    image = elf.ElfImage(gate_bytes)
    undefined = elf.Symbol(
        name = "imported",
        value = 0x401146,
        size = 30,
        type = elf.STT_FUNC,
        bind = elf.STB_GLOBAL,
        shndx = 0
    )
    with pytest.raises(ValueError):
        disasm.disassemble_symbol(image, undefined)


def test_disassemble_symbol_rejects_out_of_range_shndx(gate_bytes: bytes):
    image = elf.ElfImage(gate_bytes)
    weird = elf.Symbol(
        name = "weird",
        value = 0x401146,
        size = 30,
        type = elf.STT_FUNC,
        bind = elf.STB_GLOBAL,
        shndx = 0xFFF1
    )
    with pytest.raises(ValueError):
        disasm.disassemble_symbol(image, weird)


def test_interior_space_is_not_concatenated_into_a_match():
    c = ch.Challenge(
        id = "t",
        module = "m",
        title = "t",
        mission = "m",
        binary = b"",
        source = "src",
        answer = ch.FoundValue(1337)
    )
    assert ch.grade(c, "13 37").correct is False
    assert ch.grade(c, "1337").correct is True


def test_flow_instruction_target_not_labeled_immediate():
    code = bytes.fromhex("817dfc390500007507")
    got = disasm.disassemble(code, 0x40114D)
    cmp_ins = got[0]
    jne_ins = got[1]
    assert cmp_ins.immediate == 0x539
    assert jne_ins.immediate is None
    assert jne_ins.branch_target == 0x40115D
