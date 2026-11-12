"""
©AngelaMos | 2026
test_discover.py
"""

from rveng.engine.disasm import disassemble_at, find_gate
from rveng.engine.discover import discover_functions
from rveng.engine.elf import ElfImage


CHECK = 0x401146
MAIN = 0x401164
START = 0x401060


def test_prologue_scan_finds_check_and_main(gate_stripped_bytes: bytes):
    image = ElfImage(gate_stripped_bytes)
    addrs = {f.address for f in discover_functions(image)}
    assert CHECK in addrs
    assert MAIN in addrs


def test_prologue_scan_skips_the_runtime_start(gate_stripped_bytes: bytes):
    image = ElfImage(gate_stripped_bytes)
    addrs = {f.address for f in discover_functions(image)}
    assert START not in addrs


def test_discovered_function_has_an_address_label(gate_stripped_bytes: bytes):
    image = ElfImage(gate_stripped_bytes)
    functions = discover_functions(image)
    check = next(f for f in functions if f.address == CHECK)
    assert check.label == "sub_401146"


def test_disassemble_at_recovers_the_gate_without_symbols(gate_stripped_bytes: bytes):
    image = ElfImage(gate_stripped_bytes)
    instructions = disassemble_at(image, CHECK)
    assert instructions[-1].mnemonic == "ret"
    gate = find_gate(instructions)
    assert gate is not None
    assert gate.immediate == 1337
