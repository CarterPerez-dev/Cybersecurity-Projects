"""
©AngelaMos | 2026
cfg.py
"""

from dataclasses import dataclass

from rveng.engine.disasm import Instruction


RET = "ret"
JMP = "jmp"

EDGE_TAKEN = "taken"
EDGE_FALLTHROUGH = "fallthrough"
EDGE_JUMP = "jump"


@dataclass(frozen = True)
class BasicBlock:
    """
    A straight run of instructions with a single entry and single exit
    """

    start: int
    end: int
    instructions: tuple[int, ...]


@dataclass(frozen = True)
class Edge:
    """
    A control-flow edge between two basic blocks, keyed by their starts
    """

    src: int
    dst: int
    kind: str


@dataclass(frozen = True)
class ControlFlowGraph:
    """
    The basic blocks and edges of a single function
    """

    blocks: list[BasicBlock]
    edges: list[Edge]


def _is_terminator(ins: Instruction) -> bool:
    return (ins.is_conditional_branch or ins.mnemonic == JMP or ins.mnemonic == RET)


def _leaders(instructions: list[Instruction], within: set[int]) -> list[int]:
    addrs = [i.address for i in instructions]
    leaders = {addrs[0]}
    for idx, ins in enumerate(instructions):
        if not _is_terminator(ins):
            continue
        if idx + 1 < len(instructions):
            leaders.add(addrs[idx + 1])
        if ins.branch_target is not None and ins.branch_target in within:
            leaders.add(ins.branch_target)
    return sorted(leaders)


def build_cfg(instructions: list[Instruction]) -> ControlFlowGraph:
    """
    Split a function's instructions into basic blocks and connect them
    """
    if not instructions:
        return ControlFlowGraph([], [])

    addrs = [i.address for i in instructions]
    by_addr = {i.address: i for i in instructions}
    within = set(addrs)
    starts = _leaders(instructions, within)

    blocks = []
    for pos, start in enumerate(starts):
        stop = starts[pos + 1] if pos + 1 < len(starts) else None
        body = tuple(a for a in addrs if a >= start and (stop is None or a < stop))
        blocks.append(BasicBlock(start = start, end = body[-1], instructions = body))

    block_starts = [b.start for b in blocks]
    edges = []
    for pos, block in enumerate(blocks):
        last = by_addr[block.end]
        following = block_starts[pos + 1] if pos + 1 < len(blocks) else None
        if last.mnemonic == RET:
            continue
        if last.is_conditional_branch:
            if last.branch_target in within:
                edges.append(Edge(block.start, last.branch_target, EDGE_TAKEN))
            if following is not None:
                edges.append(Edge(block.start, following, EDGE_FALLTHROUGH))
        elif last.mnemonic == JMP:
            if last.branch_target in within:
                edges.append(Edge(block.start, last.branch_target, EDGE_JUMP))
        elif following is not None:
            edges.append(Edge(block.start, following, EDGE_FALLTHROUGH))

    return ControlFlowGraph(blocks, edges)
