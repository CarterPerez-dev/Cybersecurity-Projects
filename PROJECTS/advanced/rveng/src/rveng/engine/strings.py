"""
©AngelaMos | 2026
strings.py
"""

from dataclasses import dataclass

from rveng.engine.elf import ElfImage, Section


DEFAULT_MIN_LENGTH = 4
PRINTABLE_LOW = 0x20
PRINTABLE_HIGH = 0x7E


@dataclass(frozen = True)
class FoundString:
    """
    A printable run located at a file offset
    """

    offset: int
    text: str

    @property
    def length(self) -> int:
        return len(self.text)


def _is_printable(byte: int) -> bool:
    return PRINTABLE_LOW <= byte <= PRINTABLE_HIGH


def extract(data: bytes,
            min_length: int = DEFAULT_MIN_LENGTH,
            base: int = 0) -> list[FoundString]:
    """
    Find printable byte runs of at least min_length in data
    """
    found = []
    run = bytearray()
    start = 0
    for index, byte in enumerate(data):
        if _is_printable(byte):
            if not run:
                start = index
            run.append(byte)
            continue
        if len(run) >= min_length:
            found.append(FoundString(base + start, run.decode("ascii")))
        run.clear()
    if len(run) >= min_length:
        found.append(FoundString(base + start, run.decode("ascii")))
    return found


def extract_in_section(
    image: ElfImage,
    section: Section,
    min_length: int = DEFAULT_MIN_LENGTH
) -> list[FoundString]:
    """
    Extract strings from one section, offsets relative to the file
    """
    body = section.file_bytes(image.data)
    return extract(body, min_length, base = section.offset)


def find(data: bytes, needle: str) -> FoundString | None:
    """
    Return the first extracted string equal to needle
    """
    for item in extract(data, min_length = len(needle)):
        if item.text == needle:
            return item
    return None
