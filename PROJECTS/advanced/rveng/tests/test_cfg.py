"""
©AngelaMos | 2026
test_cfg.py
"""

from rveng.engine.cfg import EDGE_FALLTHROUGH, EDGE_JUMP, EDGE_TAKEN, build_cfg
from rveng.engine.disasm import disassemble_symbol
from rveng.engine.elf import ElfImage


B0 = 0x401146
B1 = 0x401156
B2 = 0x40115D
B3 = 0x401162


def _check_cfg(gate_bytes: bytes):
    image = ElfImage(gate_bytes)
    symbol = image.symbol("check")
    return build_cfg(disassemble_symbol(image, symbol))


def test_check_has_four_basic_blocks(gate_bytes: bytes):
    cfg = _check_cfg(gate_bytes)
    assert [b.start for b in cfg.blocks] == [B0, B1, B2, B3]


def test_check_block_zero_ends_at_the_gate_jne(gate_bytes: bytes):
    cfg = _check_cfg(gate_bytes)
    assert cfg.blocks[0].end == 0x401154


def test_check_cfg_is_a_diamond(gate_bytes: bytes):
    cfg = _check_cfg(gate_bytes)
    edges = {(e.src, e.dst, e.kind) for e in cfg.edges}
    assert edges == {
        (B0,
         B2,
         EDGE_TAKEN),
        (B0,
         B1,
         EDGE_FALLTHROUGH),
        (B1,
         B3,
         EDGE_JUMP),
        (B2,
         B3,
         EDGE_FALLTHROUGH),
    }


def test_terminal_block_has_no_out_edges(gate_bytes: bytes):
    cfg = _check_cfg(gate_bytes)
    assert all(e.src != B3 for e in cfg.edges)
