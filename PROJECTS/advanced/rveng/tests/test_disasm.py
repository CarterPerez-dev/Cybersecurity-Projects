"""
©AngelaMos | 2026
test_disasm.py
"""

import pytest

from rveng.engine import disasm, elf


CHECK_BYTES = bytes.fromhex(
    "554889e5897dfc817dfc390500007507"
    "b80100000 0eb05b80000000 05dc3".replace(" ",
                                             "")
)

EXPECTED = [
    (0x401146,
     "push",
     "rbp"),
    (0x401147,
     "mov",
     "rbp, rsp"),
    (0x40114A,
     "mov",
     "dword ptr [rbp - 4], edi"),
    (0x40114D,
     "cmp",
     "dword ptr [rbp - 4], 0x539"),
    (0x401154,
     "jne",
     "0x40115d"),
    (0x401156,
     "mov",
     "eax, 1"),
    (0x40115B,
     "jmp",
     "0x401162"),
    (0x40115D,
     "mov",
     "eax, 0"),
    (0x401162,
     "pop",
     "rbp"),
    (0x401163,
     "ret",
     ""),
]


def test_matches_objdump_instruction_for_instruction():
    got = disasm.disassemble(CHECK_BYTES, 0x401146)
    assert [(i.address, i.mnemonic, i.op_str) for i in got] == EXPECTED


def test_gate_immediate_is_1337():
    got = disasm.disassemble(CHECK_BYTES, 0x401146)
    gate = disasm.find_gate(got)
    assert gate.mnemonic == "cmp"
    assert gate.immediate == 1337
    assert gate.address == 0x40114D


def test_conditional_branch_flagged():
    got = disasm.disassemble(CHECK_BYTES, 0x401146)
    jne = next(i for i in got if i.mnemonic == "jne")
    assert jne.is_conditional_branch
    assert jne.is_flow


def test_disassemble_symbol_from_image(gate_bytes: bytes):
    image = elf.ElfImage(gate_bytes)
    check = image.symbol("check")
    got = disasm.disassemble_symbol(image, check)
    assert got[0].address == 0x401146
    assert disasm.find_gate(got).immediate == 1337
    assert got[-1].mnemonic == "ret"
