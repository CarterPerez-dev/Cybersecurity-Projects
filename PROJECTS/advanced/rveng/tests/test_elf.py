"""
©AngelaMos | 2026
test_elf.py
"""

import pytest

from rveng.engine import elf


@pytest.fixture(scope = "module")
def image(gate_bytes: bytes) -> elf.ElfImage:
    return elf.ElfImage(gate_bytes)


def test_header_matches_readelf(image: elf.ElfImage):
    hdr = image.header
    assert hdr.e_type == 2
    assert hdr.e_machine == 0x3E
    assert hdr.e_entry == 0x401060
    assert hdr.e_shoff == 13984
    assert hdr.e_shentsize == 64
    assert hdr.e_shnum == 30
    assert hdr.e_shstrndx == 29


def test_rejects_non_elf():
    with pytest.raises(elf.NotAnElf):
        elf.ElfImage(b"not an elf at all, definitely not")


def test_text_section(image: elf.ElfImage):
    text = image.section(".text")
    assert text is not None
    assert text.addr == 0x401060
    assert text.offset == 0x1060
    assert text.size == 0x182
    assert text.flag_str == "AX"


def test_rodata_holds_the_secret(image: elf.ElfImage):
    rodata = image.section(".rodata")
    assert rodata.addr == 0x402000
    assert b"the_flag_is_here" in rodata.file_bytes(image.data)


def test_bss_is_nobits_no_file_bytes(image: elf.ElfImage):
    bss = image.section(".bss")
    assert bss.is_nobits
    assert bss.file_bytes(image.data) == b""


def test_check_symbol(image: elf.ElfImage):
    check = image.symbol("check")
    assert check.value == 0x401146
    assert check.size == 30
    assert check.type_name == "FUNC"
    assert check.bind_name == "GLOBAL"


def test_main_symbol(image: elf.ElfImage):
    main = image.symbol("main")
    assert main.value == 0x401164
    assert main.size == 126


def test_matches_pyelftools(gate_bytes: bytes, image: elf.ElfImage):
    from io import BytesIO

    from elftools.elf.elffile import ELFFile

    ref = ELFFile(BytesIO(gate_bytes))
    assert image.header.e_entry == ref.header.e_entry
    assert image.header.e_shnum == ref.num_sections()
    assert image.section(".text"
                         ).addr == ref.get_section_by_name(".text").header.sh_addr
    ref_check = ref.get_section_by_name(".symtab").get_symbol_by_name("check")[0]
    assert image.symbol("check").value == ref_check.entry.st_value
