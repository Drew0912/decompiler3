#!/usr/bin/env python3
"""IR helpers for hand-built test functions, node-type coverage and source metadata"""

import itertools
import unittest

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILInstruction, MLILConst, MLILGoto, MLILIf, MLILRet,
)

ADDRESS_STEP = 4        # between the addresses given to instructions that have none

# What with_metadata stamps
SOURCE_ADDRESS = 0x1234
SOURCE_INST_INDEX = 7
SOURCE_LLIL_INDEX = 9

_const_values = itertools.count()


def connect(func: MediumLevelILFunction) -> MediumLevelILFunction:
    """Add the edges each block's last instruction implies (fallthrough unless it branches or returns), then number
    the instructions, and give each one with no address its own (the logic check keys effects and branches by it)"""
    blocks = func.basic_blocks
    for idx, block in enumerate(blocks):
        last = block.instructions[-1]

        if isinstance(last, MLILIf):
            block.add_outgoing_edge(last.true_target)
            block.add_outgoing_edge(last.false_target)
        elif isinstance(last, MLILGoto):
            block.add_outgoing_edge(last.target)
        elif not isinstance(last, MLILRet) and idx + 1 < len(blocks):
            block.add_outgoing_edge(blocks[idx + 1])

    func.renumber_instructions()
    for inst in func.iter_instructions():
        if inst.address == 0:
            inst.address = (inst.inst_index + 1) * ADDRESS_STEP

    return func


def concrete_subclasses(base: type) -> set:
    """Every leaf subclass of base, however deep"""
    found = set()
    pending = list(base.__subclasses__())
    while pending:
        cls = pending.pop()
        children = cls.__subclasses__()
        if children:
            pending.extend(children)
        else:
            found.add(cls)

    return found


def c() -> MLILConst:
    """A constant whose value no other c() call returns, so every operand is distinct"""
    return MLILConst(next(_const_values))


def expression_fields(node) -> list:
    """Every MLIL expression a node holds in a field, lists included."""
    found = []
    for value in vars(node).values():
        for item in (value if isinstance(value, (list, tuple)) else [value]):
            if isinstance(item, MediumLevelILInstruction):
                found.append(item)

    return found


def replaced(value, replacements: dict):
    """value with every MLIL expression in it, a list's or tuple's items included, swapped for its
    replacement (keyed by id)"""
    if isinstance(value, MediumLevelILInstruction):
        return replacements[id(value)]

    if isinstance(value, (list, tuple)):
        return type(value)(replaced(item, replacements) for item in value)

    return value


def set_metadata(inst, address: int, inst_index: int, llil_index: int):
    inst.address = address
    inst.inst_index = inst_index
    inst.llil_index = llil_index
    return inst


def with_metadata(inst):
    return set_metadata(inst, SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)


class MetadataTestCase(unittest.TestCase):
    def assert_metadata(self, inst, address: int, inst_index: int, llil_index: int):
        self.assertEqual(inst.address, address)
        self.assertEqual(inst.inst_index, inst_index)
        self.assertEqual(inst.llil_index, llil_index)
