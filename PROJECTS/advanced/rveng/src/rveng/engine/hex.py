"""
©AngelaMos | 2026
hex.py
"""

from dataclasses import dataclass


BYTES_PER_LINE = 16
GROUP_SIZE = 8
NON_PRINTABLE = "."
PRINTABLE_LOW = 0x20
PRINTABLE_HIGH = 0x7E
OFFSET_WIDTH = 8


@dataclass(frozen = True)
class HexLine:
    """
    One rendered line of a hex dump
    """

    offset: int
    data: bytes

    def hex_cells(self) -> str:
        cells = []
        for index in range(BYTES_PER_LINE):
            if index < len(self.data):
                cells.append(f"{self.data[index]:02x}")
            else:
                cells.append("  ")
            if index == GROUP_SIZE - 1:
                cells.append("")
        return " ".join(cells)

    def ascii_gutter(self) -> str:
        chars = []
        for byte in self.data:
            if PRINTABLE_LOW <= byte <= PRINTABLE_HIGH:
                chars.append(chr(byte))
            else:
                chars.append(NON_PRINTABLE)
        return "".join(chars)

    def render(self) -> str:
        offset = f"{self.offset:0{OFFSET_WIDTH}x}"
        return f"{offset}  {self.hex_cells()}  |{self.ascii_gutter()}|"


def iter_lines(data: bytes, base: int = 0):
    """
    Yield HexLine rows for data starting at virtual base
    """
    for start in range(0, len(data), BYTES_PER_LINE):
        chunk = data[start : start + BYTES_PER_LINE]
        yield HexLine(offset = base + start, data = chunk)


def hexdump(data: bytes, base: int = 0) -> str:
    """
    Render data as a canonical offset hex dump with ascii gutter
    """
    return "\n".join(line.render() for line in iter_lines(data, base))
