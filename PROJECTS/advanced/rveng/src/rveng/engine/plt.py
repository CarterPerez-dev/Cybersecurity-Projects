"""
©AngelaMos | 2026
plt.py
"""

import struct

from rveng.engine.elf import ElfImage


DYNSYM = ".dynsym"
DYNSTR = ".dynstr"
RELA_PLT = ".rela.plt"
PLT = ".plt"

SYM_ENTRY = 24
SYM_NAME = 0x00

RELA_ENTRY = 24
RELA_OFFSET = 0x00
RELA_INFO = 0x08

PLT_ENTRY = 16
JMP_RIP = b"\xff\x25"
JMP_RIP_LEN = 6


def _cstring(blob: bytes, offset: int) -> str:
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset : end].decode("utf-8", "replace")


def _dynamic_names(image: ElfImage) -> list[str]:
    dynsym = image.section(DYNSYM)
    dynstr = image.section(DYNSTR)
    if dynsym is None or dynstr is None or dynsym.entsize == 0:
        return []
    names = image.data[dynstr.offset : dynstr.offset + dynstr.size]
    body = image.data[dynsym.offset : dynsym.offset + dynsym.size]
    en = image.header.endian
    out = []
    for base in range(0, len(body) - SYM_ENTRY + 1, SYM_ENTRY):
        name_off = struct.unpack_from(en + "I", body, base + SYM_NAME)[0]
        out.append(_cstring(names, name_off))
    return out


def _got_to_name(image: ElfImage, names: list[str]) -> dict[int, str]:
    rela = image.section(RELA_PLT)
    if rela is None or rela.entsize == 0:
        return {}
    body = image.data[rela.offset : rela.offset + rela.size]
    en = image.header.endian
    mapping = {}
    for base in range(0, len(body) - RELA_ENTRY + 1, RELA_ENTRY):
        r_offset = struct.unpack_from(en + "Q", body, base + RELA_OFFSET)[0]
        r_info = struct.unpack_from(en + "Q", body, base + RELA_INFO)[0]
        sym_index = r_info >> 32
        if 0 <= sym_index < len(names):
            mapping[r_offset] = names[sym_index]
    return mapping


def _stub_got_slot(entry: bytes, entry_addr: int, endian: str) -> int | None:
    jmp = entry.find(JMP_RIP)
    if jmp == -1 or jmp + JMP_RIP_LEN > len(entry):
        return None
    disp = struct.unpack_from(endian + "i", entry, jmp + 2)[0]
    return entry_addr + jmp + JMP_RIP_LEN + disp


def plt_map(image: ElfImage) -> dict[int, str]:
    """
    Map each PLT stub address to the imported symbol it jumps to
    """
    plt = image.section(PLT)
    if plt is None:
        return {}
    got_names = _got_to_name(image, _dynamic_names(image))
    if not got_names:
        return {}
    body = image.data[plt.offset : plt.offset + plt.size]
    en = image.header.endian
    result = {}
    for base in range(0, len(body) - PLT_ENTRY + 1, PLT_ENTRY):
        entry = body[base : base + PLT_ENTRY]
        got_slot = _stub_got_slot(entry, plt.addr + base, en)
        if got_slot is None:
            continue
        name = got_names.get(got_slot)
        if name is not None:
            result[plt.addr + base] = name
    return result


def resolve_call(image: ElfImage, target: int) -> str | None:
    """
    Return the import a call target resolves to, or None when it is local
    """
    return plt_map(image).get(target)
