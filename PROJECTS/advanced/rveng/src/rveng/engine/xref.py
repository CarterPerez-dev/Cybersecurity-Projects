"""
©AngelaMos | 2026
xref.py
"""

from dataclasses import dataclass

from rveng.engine.disasm import Instruction


CALL = "call"
KIND_CALL = "call"
KIND_BRANCH = "branch"
KIND_DATA = "data"


@dataclass(frozen = True)
class Reference:
    """
    One cross reference from an instruction to a target address
    """

    from_addr: int
    to_addr: int
    kind: str


def references(instructions: list[Instruction]) -> list[Reference]:
    """
    Every control-flow and data reference the instructions emit
    """
    out = []
    for ins in instructions:
        if ins.branch_target is not None:
            kind = KIND_CALL if ins.mnemonic == CALL else KIND_BRANCH
            out.append(Reference(ins.address, ins.branch_target, kind))
        if ins.rip_target is not None:
            out.append(Reference(ins.address, ins.rip_target, KIND_DATA))
    return out


def build_xrefs(instructions: list[Instruction]) -> dict[int, list[Reference]]:
    """
    Group every reference by the address it points at
    """
    table: dict[int, list[Reference]] = {}
    for ref in references(instructions):
        table.setdefault(ref.to_addr, []).append(ref)
    return table


def xrefs_to(instructions: list[Instruction], target: int) -> list[Reference]:
    """
    Every reference that points at target
    """
    return [ref for ref in references(instructions) if ref.to_addr == target]
