#!/usr/bin/env python3
"""The stack translator's checks that its test files share (tests/mlil_tests/test_mlil_stack_*.py,
test_mlil_call_result.py; G3's harness runs the invariants too): every temporary assigned once and read only after that
in its own block, every local or box read only after its store, the translator's own pipeline, and a test case
converting LLIL through it or the decompile path after checking the result; it imports logic_check from tools/, which
the importing test puts on sys.path"""

import re
import unittest
from typing import Callable

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.stack_translator import ED9StackTranslatorPass
from ir.core import reverse_post_order
from ir.llil.llil import LowLevelILFunction
from ir.mlil import BitwiseHexPass, BlockMergePass
from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILAddressOf, MLILSetVar, MLILStoreDeref, MLILVar,
    UNASSIGNED_SLOT_INDEX, walk,
)
from ir.mlil.stack_translator import StackTranslator
from ir.pipeline import Pipeline
import logic_check

TEMPORARY = re.compile(r'^t\d+$')


def written_by(inst):
    """The variable a statement assigns: a SetVar's, a call's output"""
    if isinstance(inst, MLILSetVar):
        return inst.var
    if isinstance(inst, MediumLevelILCall):
        return inst.output
    return None


def temporaries_misused(mlil) -> list[str]:
    """The translator's invariant: each temporary assigned once and read only after that, in its own block; what
    breaks it (G3's harness runs it on every function too)"""
    problems = []
    assigned = {}
    for block in mlil.basic_blocks:
        for index, inst in enumerate(block.instructions):
            var = written_by(inst)
            if var is not None and TEMPORARY.match(var.name):
                if var.name in assigned:
                    problems.append(f'{var.name} assigned twice')
                assigned[var.name] = (block, index)

    for block in mlil.basic_blocks:
        for index, inst in enumerate(block.instructions):
            for operand in inst.operands():
                for node in walk(operand):
                    if isinstance(node, MLILVar) and TEMPORARY.match(node.var.name):
                        where = assigned.get(node.var.name)
                        if where is None or where[0] is not block or where[1] >= index:
                            problems.append(f'{node.var.name} read in {inst}')
    return problems


def stored_variable(inst):
    """The variable a statement stores: a SetVar's, a call's output, v of *(&v) = value"""
    if isinstance(inst, MLILStoreDeref) and isinstance(inst.dest, MLILAddressOf):
        return inst.dest.operand.var if isinstance(inst.dest.operand, MLILVar) else None
    return written_by(inst)


def variables_read(inst) -> list:
    """The variables a statement reads: each MLILVar but an address's (&v reads nothing), v of each *(&v)"""
    found = []
    for operand in inst.operands():
        nodes = list(walk(operand))
        addressed = {id(node.operand) for node in nodes if isinstance(node, MLILAddressOf)}
        for node in nodes:
            if isinstance(node, MLILVar) and id(node) not in addressed:
                found.append(node.var)
            elif (var := StackTranslator.memory_form_var(node)) is not None:
                found.append(var)
    return found


def reads_before_definition(mlil) -> list[str]:
    """The translator's invariant for locals and boxes: each read reached only from a store to the variable; the reads
    some way from the entry reaches with no store since (a must-written dataflow over the blocks; G3's harness runs it
    on every function too)"""
    entry = mlil.basic_blocks[0]
    order = reverse_post_order(entry, lambda block: block.outgoing_edges)
    exits = {}

    def stored_at_entry(block) -> frozenset:
        # A predecessor not reached yet in the iteration counts as storing every variable
        known = [exits[predecessor] for predecessor in block.incoming_edges if predecessor in exits]
        return frozenset.intersection(*known) if block is not entry and known else frozenset()

    def through(block, stored: frozenset, problems: list[str] | None = None) -> frozenset:
        for inst in block.instructions:
            if problems is not None:
                problems += [f'{var.name} read in {inst}' for var in variables_read(inst)
                             if var.slot_index != UNASSIGNED_SLOT_INDEX and var not in stored]
            if (var := stored_variable(inst)) is not None:
                stored |= {var}
        return stored

    changed = True
    while changed:
        changed = False
        for block in order:
            stored = through(block, stored_at_entry(block))
            if exits.get(block) != stored:
                exits[block] = stored
                changed = True

    problems = []
    for block in order:
        through(block, stored_at_entry(block), problems)
    return problems


def statements(mlil) -> list[str]:
    return [str(inst) for block in mlil.basic_blocks for inst in block.instructions]


def translated(llil: LowLevelILFunction) -> MediumLevelILFunction:
    """The translator's own MLIL, its canonical form: convert_falcom_llil_to_mlil_stack's passes without the shaping
    ones (CallResultPass), which take it as their input"""
    mlil = Pipeline([ED9StackTranslatorPass(), BlockMergePass(), BitwiseHexPass()]).run(llil)
    mlil.renumber_instructions()
    return mlil


class StackTranslationTestCase(unittest.TestCase):
    def checked_translation(self, llil: LowLevelILFunction,
                            convert: Callable[[LowLevelILFunction], MediumLevelILFunction] = translated):
        """llil's MLIL through convert (the translator's own pipeline, or the decompile path whole), after checking it:
        both pairs clean, the temporaries' invariant, every local or box read reached only from its store"""
        reference = logic_check.analyze(logic_check.LLILLayer(llil))
        mlil = convert(llil)
        self.assertEqual(temporaries_misused(mlil), [])
        self.assertEqual(reads_before_definition(mlil), [])
        llil_mlil = logic_check.compare_facts(reference, logic_check.analyze(logic_check.MLILLayer(mlil)))
        self.assertEqual({difference.category for difference in llil_mlil}, set(), 'LLIL -> MLIL')
        mlil_hlil = logic_check.compare_mlil_hlil(mlil, convert_falcom_mlil_to_hlil(mlil))
        self.assertEqual({difference.category for difference in mlil_hlil}, set(), 'MLIL -> HLIL')
        return mlil
