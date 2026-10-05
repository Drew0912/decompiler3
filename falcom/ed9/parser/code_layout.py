"""Where each function's code lies in the file, and the ranges of it no instruction covers"""

from ..disasm import Instruction
from .types_scp import ScpFunctionEntry, ScpGlobalVar, ScpHeader


def code_start(header: ScpHeader) -> int:
    """Where the code starts: right after the global var table, the last table before it"""
    return header.global_var_offset + header.global_var_count * ScpGlobalVar.SIZE


def code_order(entries: list[ScpFunctionEntry]) -> list[int]:
    """Table indices sorted by code offset (the table is sorted by name, the code is in source order)"""
    return sorted(range(len(entries)), key = lambda index: entries[index].offset)


def function_extents(entries: list[ScpFunctionEntry], code_end: int) -> dict[int, tuple[int, int]]:
    """table index -> (start, end) physical byte range, in code order: up to the next function's start or code_end.
    Functions that start at the same offset (an empty one before another) share the range, so a per-function check
    sees it once per function."""
    starts = sorted({entry.offset for entry in entries})
    ends = dict(zip(starts, starts[1:] + [code_end]))
    return {index: (entries[index].offset, ends[entries[index].offset]) for index in code_order(entries)}


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
