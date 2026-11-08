"""
©AngelaMos | 2026
test_patch.py
"""

import pytest

from rveng.engine import disasm, elf, patch


JNE_FILE_OFFSET = 0x1154
JNE_BYTES = b"\x75\x07"
NOP_NOP = b"\x90\x90"


def test_diff_finds_changed_bytes():
    diffs = patch.diff(b"\x75\x07\x90", b"\x90\x07\x90")
    assert len(diffs) == 1
    assert diffs[0].offset == 0
    assert diffs[0].before == 0x75
    assert diffs[0].after == 0x90


def test_diff_rejects_length_mismatch():
    with pytest.raises(patch.PatchError):
        patch.diff(b"\x00", b"\x00\x00")


def test_apply_preserves_length():
    out = patch.apply(b"AAAA", 1, b"BB")
    assert out == b"ABBA"


def test_apply_out_of_bounds_raises():
    with pytest.raises(patch.PatchError):
        patch.apply(b"AAAA", 3, b"BB")


def test_gate_byte_is_jne(gate_bytes: bytes):
    assert gate_bytes[JNE_FILE_OFFSET : JNE_FILE_OFFSET + 2] == JNE_BYTES


def test_verify_flip_the_gate(gate_bytes: bytes):
    known_good = patch.apply(gate_bytes, JNE_FILE_OFFSET, NOP_NOP)
    assert patch.verify_patch(gate_bytes, JNE_FILE_OFFSET, NOP_NOP, known_good)
    assert not patch.verify_patch(gate_bytes, JNE_FILE_OFFSET, b"\x75\x07", known_good)


def test_patched_gate_removes_conditional_branch(gate_bytes: bytes):
    known_good = patch.apply(gate_bytes, JNE_FILE_OFFSET, NOP_NOP)
    image = elf.ElfImage(known_good)
    check = image.symbol("check")
    ins = disasm.disassemble_symbol(image, check)
    assert not any(i.is_conditional_branch for i in ins)
