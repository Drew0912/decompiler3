"""Where each function's code lies in the file, and the ranges of it no instruction covers"""

from ..disasm import Instruction
from .types_scp import ScpFunctionEntry


def code_order(entries: list[ScpFunctionEntry]) -> list[int]:
    """Table indices sorted by code offset (the table is sorted by name, the code is in source order)"""
    return sorted(range(len(entries)), key = lambda index: entries[index].offset)


def function_extents(entries: list[ScpFunctionEntry], code_end: int) -> dict[int, tuple[int, int]]:
    """table index -> (start, end) physical byte range in code order; the last function ends at code_end"""
    order = code_order(entries)
    starts = [entries[index].offset for index in order]
    ends = starts[1:] + [code_end]
    return dict(zip(order, zip(starts, ends)))


def dropped_ranges(insts: list[Instruction], start: int, end: int) -> list[tuple[int, int, Instruction | None]]:
    """[start, end) not covered by insts, each paired with the instruction right before it (if any)"""
    ranges = []
    cursor = start
    prev = None

    for inst in insts:
        if inst.offset > cursor:
            ranges.append((cursor, inst.offset, prev))

        cursor = max(cursor, inst.offset + inst.size)
        prev = inst

    if cursor < end:
        ranges.append((cursor, end, prev))

    return ranges
