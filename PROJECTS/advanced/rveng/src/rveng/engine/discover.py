"""
©AngelaMos | 2026
discover.py
"""

from dataclasses import dataclass

from rveng.engine.elf import SHF_EXECINSTR, ElfImage


PROLOGUE = b"\x55\x48\x89\xe5"


@dataclass(frozen = True)
class DiscoveredFunction:
    """
    A candidate function entry found without a symbol table
    """

    address: int
    section: str

    @property
    def label(self) -> str:
        return f"sub_{self.address:x}"


def discover_functions(image: ElfImage) -> list[DiscoveredFunction]:
    """
    Find function entries by scanning executable sections for the prologue
    """
    found = []
    for section in image.sections:
        if section.is_nobits or not section.flags & SHF_EXECINSTR:
            continue
        blob = image.data[section.offset : section.offset + section.size]
        pos = blob.find(PROLOGUE)
        while pos != -1:
            found.append(
                DiscoveredFunction(
                    address = section.addr + pos,
                    section = section.name
                )
            )
            pos = blob.find(PROLOGUE, pos + 1)
    return sorted(found, key = lambda f: f.address)
