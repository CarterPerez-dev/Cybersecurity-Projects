"""
©AngelaMos | 2026
elf.py
"""

import struct
from dataclasses import dataclass


ELF_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5
ELFCLASS64 = 2
ELFDATA_LSB = 1
ELFDATA_MSB = 2

EHDR_SIZE = 64
E_TYPE = 0x10
E_MACHINE = 0x12
E_ENTRY = 0x18
E_PHOFF = 0x20
E_SHOFF = 0x28
E_SHENTSIZE = 0x3A
E_SHNUM = 0x3C
E_SHSTRNDX = 0x3E

SHDR_SIZE = 64
SH_NAME = 0x00
SH_TYPE = 0x04
SH_FLAGS = 0x08
SH_ADDR = 0x10
SH_OFFSET = 0x18
SH_SIZE = 0x20
SH_LINK = 0x28
SH_ENTSIZE = 0x38

SYM_SIZE = 24
ST_NAME = 0x00
ST_INFO = 0x04
ST_SHNDX = 0x06
ST_VALUE = 0x08
ST_SIZE = 0x10

SHT_SYMTAB = 2
SHT_NOBITS = 8

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STT_FUNC = 2
STB_GLOBAL = 1

SECTION_TYPES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    11: "DYNSYM",
}

SYMBOL_TYPES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION"}
SYMBOL_BINDS = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}


class NotAnElf(ValueError):
    """
    Raised when the bytes are not a supported ELF64 image
    """


def _cstring(blob: bytes, offset: int) -> str:
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset : end].decode("utf-8", "replace")


@dataclass(frozen = True)
class ElfHeader:
    """
    Parsed Elf64 header fields
    """

    endian: str
    e_type: int
    e_machine: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


@dataclass(frozen = True)
class Section:
    """
    One entry of the section header table
    """

    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int

    @property
    def type_name(self) -> str:
        return SECTION_TYPES.get(self.type, f"0x{self.type:x}")

    @property
    def is_nobits(self) -> bool:
        return self.type == SHT_NOBITS

    @property
    def flag_str(self) -> str:
        out = ""
        if self.flags & SHF_WRITE:
            out += "W"
        if self.flags & SHF_ALLOC:
            out += "A"
        if self.flags & SHF_EXECINSTR:
            out += "X"
        return out

    def file_bytes(self, image: bytes) -> bytes:
        if self.is_nobits:
            return b""
        return image[self.offset : self.offset + self.size]


@dataclass(frozen = True)
class Symbol:
    """
    One entry of a symbol table
    """

    name: str
    value: int
    size: int
    type: int
    bind: int
    shndx: int

    @property
    def type_name(self) -> str:
        return SYMBOL_TYPES.get(self.type, f"0x{self.type:x}")

    @property
    def bind_name(self) -> str:
        return SYMBOL_BINDS.get(self.bind, f"0x{self.bind:x}")


class ElfImage:
    """
    A parsed ELF64 image: header, sections, and symbols
    """
    def __init__(self, data: bytes):
        self.data = data
        self.header = parse_header(data)
        self.sections = parse_sections(data, self.header)
        self.symbols = parse_symbols(data, self.sections, self.header.endian)

    def section(self, name: str) -> Section | None:
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def symbol(self, name: str) -> Symbol | None:
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    def functions(self) -> list[Symbol]:
        return [s for s in self.symbols if s.type == STT_FUNC]


def parse_header(data: bytes) -> ElfHeader:
    """
    Parse and validate the Elf64 header
    """
    if len(data) < EHDR_SIZE or not data.startswith(ELF_MAGIC):
        raise NotAnElf("missing ELF magic")
    if data[EI_CLASS] != ELFCLASS64:
        raise NotAnElf("not ELF64")
    endian = "<" if data[EI_DATA] == ELFDATA_LSB else ">"
    read_h = lambda off: struct.unpack_from(endian + "H", data, off)[0]
    read_q = lambda off: struct.unpack_from(endian + "Q", data, off)[0]
    header = ElfHeader(
        endian = endian,
        e_type = read_h(E_TYPE),
        e_machine = read_h(E_MACHINE),
        e_entry = read_q(E_ENTRY),
        e_phoff = read_q(E_PHOFF),
        e_shoff = read_q(E_SHOFF),
        e_shentsize = read_h(E_SHENTSIZE),
        e_shnum = read_h(E_SHNUM),
        e_shstrndx = read_h(E_SHSTRNDX),
    )
    _validate_section_table(data, header)
    return header


def _validate_section_table(data: bytes, hdr: ElfHeader) -> None:
    if hdr.e_shnum == 0:
        return
    if hdr.e_shentsize < SHDR_SIZE:
        raise NotAnElf("section entry size too small")
    table_end = hdr.e_shoff + hdr.e_shnum * hdr.e_shentsize
    if hdr.e_shoff < EHDR_SIZE or table_end > len(data):
        raise NotAnElf("section table out of bounds")
    if hdr.e_shstrndx >= hdr.e_shnum:
        raise NotAnElf("section name table index out of range")


def _raw_sections(data: bytes, hdr: ElfHeader) -> list[dict]:
    en = hdr.endian
    rows = []
    for i in range(hdr.e_shnum):
        base = hdr.e_shoff + i * hdr.e_shentsize
        rows.append(
            {
                "index": i,
                "name_off": struct.unpack_from(en + "I",
                                               data,
                                               base + SH_NAME)[0],
                "type": struct.unpack_from(en + "I",
                                           data,
                                           base + SH_TYPE)[0],
                "flags": struct.unpack_from(en + "Q",
                                            data,
                                            base + SH_FLAGS)[0],
                "addr": struct.unpack_from(en + "Q",
                                           data,
                                           base + SH_ADDR)[0],
                "offset": struct.unpack_from(en + "Q",
                                             data,
                                             base + SH_OFFSET)[0],
                "size": struct.unpack_from(en + "Q",
                                           data,
                                           base + SH_SIZE)[0],
                "link": struct.unpack_from(en + "I",
                                           data,
                                           base + SH_LINK)[0],
                "entsize": struct.unpack_from(en + "Q",
                                              data,
                                              base + SH_ENTSIZE)[0],
            }
        )
    return rows


def parse_sections(data: bytes, hdr: ElfHeader) -> list[Section]:
    """
    Parse the section header table and resolve section names
    """
    rows = _raw_sections(data, hdr)
    if not rows:
        return []
    shstr = rows[hdr.e_shstrndx]
    names = data[shstr["offset"]: shstr["offset"] + shstr["size"]]
    sections = []
    for row in rows:
        sections.append(
            Section(
                index = row["index"],
                name = _cstring(names,
                                row["name_off"]),
                type = row["type"],
                flags = row["flags"],
                addr = row["addr"],
                offset = row["offset"],
                size = row["size"],
                link = row["link"],
                entsize = row["entsize"],
            )
        )
    return sections


def parse_symbols(data: bytes,
                  sections: list[Section],
                  endian: str = "<") -> list[Symbol]:
    """
    Parse the .symtab entries and resolve their names via the linked strtab
    """
    symtab = next((s for s in sections if s.type == SHT_SYMTAB), None)
    if symtab is None or symtab.entsize == 0:
        return []
    if symtab.link >= len(sections):
        return []
    strtab = sections[symtab.link]
    names = data[strtab.offset : strtab.offset + strtab.size]
    body = data[symtab.offset : symtab.offset + symtab.size]
    en = endian
    symbols = []
    for base in range(0, len(body) - SYM_SIZE + 1, SYM_SIZE):
        name_off = struct.unpack_from(en + "I", body, base + ST_NAME)[0]
        info = body[base + ST_INFO]
        symbols.append(
            Symbol(
                name = _cstring(names,
                                name_off),
                value = struct.unpack_from(en + "Q",
                                           body,
                                           base + ST_VALUE)[0],
                size = struct.unpack_from(en + "Q",
                                          body,
                                          base + ST_SIZE)[0],
                type = info & 0xF,
                bind = info >> 4,
                shndx = struct.unpack_from(en + "H",
                                           body,
                                           base + ST_SHNDX)[0],
            )
        )
    return symbols
