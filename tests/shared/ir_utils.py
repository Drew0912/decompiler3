#!/usr/bin/env python3
"""IR helpers for hand-built test functions and node-type coverage"""

from ir.mlil.mlil import MediumLevelILFunction, MLILGoto, MLILIf, MLILRet

ADDRESS_STEP = 4        # between the addresses given to instructions that have none


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
