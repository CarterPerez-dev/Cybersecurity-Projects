"""
©AngelaMos | 2026
test_xref.py
"""

from rveng.engine.disasm import disassemble_text
from rveng.engine.elf import ElfImage
from rveng.engine.xref import build_xrefs, xrefs_to


CHECK = 0x401146
FLAG = 0x402004
MAIN_CALLS_CHECK = 0x4011A6
MAIN_LEA_FLAG = 0x401173


def test_rip_relative_resolves_to_flag_string(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    by_addr = {i.address: i for i in disassemble_text(image)}
    assert by_addr[MAIN_LEA_FLAG].rip_target == FLAG


def test_xref_finds_caller_of_check(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    refs = xrefs_to(disassemble_text(image), CHECK)
    assert any(r.from_addr == MAIN_CALLS_CHECK and r.kind == "call" for r in refs)


def test_xref_finds_data_reference_to_flag(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    refs = xrefs_to(disassemble_text(image), FLAG)
    assert any(r.from_addr == MAIN_LEA_FLAG and r.kind == "data" for r in refs)


def test_build_xrefs_groups_by_target(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    table = build_xrefs(disassemble_text(image))
    assert CHECK in table
    assert FLAG in table
