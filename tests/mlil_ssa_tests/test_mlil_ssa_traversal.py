#!/usr/bin/env python3
"""Unit tests for the SSA nodes' traversal: operands() and map_operands() over them, iter_ssa_reads(), what an SSA node
reads, and the rule copy propagation keeps on top of the shared traversal"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILInstruction, MediumLevelILBasicBlock, MediumLevelILFunction, MLILVariable, MLILAdd, MLILAddressOf,
    MLILRet, MLILCall, map_operands,
)
from ir.mlil_ssa.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILPhi, iter_ssa_reads
from ir.mlil_ssa.passes.pass_ssa_copy_propagation import CopyPropagationPass
from tests.shared.ir_utils import (
    SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX, c, concrete_subclasses, expression_fields, replaced,
)


def samples() -> list:
    """One instance of every SSA node type, with distinct expression operands"""
    var = MLILVariable('x')
    ssa_var = MLILVariableSSA(var, 1)
    return [MLILVarSSA(ssa_var), MLILSetVarSSA(ssa_var, c()),
            MLILPhi(ssa_var, [(MLILVariableSSA(var, 0), MediumLevelILBasicBlock(0))])]


class TestOperandsCoverEveryExpressionField(unittest.TestCase):
    """operands() on the SSA nodes, as tests/mlil_tests/test_mlil_traversal.py reads every other node. A new SSA node
    type fails here until it has a sample and its own operands()."""

    def test_every_node_type_has_a_sample(self):
        sampled = {type(node) for node in samples()}
        node_types = {cls for cls in concrete_subclasses(MediumLevelILInstruction)
                      if cls.__module__ == MLILVarSSA.__module__}
        missing = node_types - sampled
        self.assertEqual(missing, set(), [cls.__name__ for cls in missing])

    def test_operands_are_exactly_the_expression_fields(self):
        for node in samples():
            with self.subTest(node=type(node).__name__):
                self.assertCountEqual(map(id, node.operands()), map(id, expression_fields(node)))


class TestMapOperands(unittest.TestCase):
    """map_operands() over the SSA nodes: each expression field gets its replacement and every other field, metadata
    included, is kept."""

    def test_unchanged_operands_give_the_node_itself(self):
        for node in samples():
            with self.subTest(node=type(node).__name__):
                self.assertIs(map_operands(node, lambda operand: operand), node)

    def test_each_expression_field_is_replaced_and_every_other_field_kept(self):
        for node in samples():
            if not expression_fields(node):
                continue

            with self.subTest(node=type(node).__name__):
                node.address, node.inst_index, node.llil_index = SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX
                replacements = {id(operand): c() for operand in expression_fields(node)}
                rebuilt = map_operands(node, lambda operand: replacements[id(operand)])

                expected = {name: replaced(value, replacements) for name, value in vars(node).items()}
                self.assertIs(type(rebuilt), type(node))
                self.assertEqual(vars(rebuilt), expected)


class TestIterSSAReads(unittest.TestCase):
    """iter_ssa_reads() gives (variable, reader) in evaluation order: the reader is the
    MLILVarSSA node itself (passes identity-search for it), or the phi for a phi source."""

    def setUp(self):
        self.x = MLILVariable('x')
        self.x1 = MLILVariableSSA(self.x, 1)
        self.x2 = MLILVariableSSA(self.x, 2)

    def test_reader_is_the_variable_node(self):
        first, second = MLILVarSSA(self.x1), MLILVarSSA(self.x2)
        ret = MLILRet(MLILAdd(first, second))

        self.assertEqual(list(iter_ssa_reads(ret)), [(self.x1, first), (self.x2, second)])

    def test_phi_sources_are_read_by_the_phi(self):
        block = MediumLevelILBasicBlock(0)
        phi = MLILPhi(MLILVariableSSA(self.x, 3), [(self.x1, block), (self.x2, block)])

        self.assertEqual(list(iter_ssa_reads(phi)), [(self.x1, phi), (self.x2, phi)])

    def test_skip_excludes_a_read_under_address_of(self):
        plain, taken = MLILVarSSA(self.x1), MLILVarSSA(self.x2)
        call = MLILCall('f', [plain, MLILAddressOf(taken)])

        self.assertEqual([var for var, _ in iter_ssa_reads(call)], [self.x1, self.x2])
        self.assertEqual([var for var, _ in iter_ssa_reads(call, skip=(MLILAddressOf,))], [self.x1])


class TestWalkerRulesKept(unittest.TestCase):
    """Rules individual passes keep on top of the shared traversal."""

    def test_copy_propagation_does_not_count_a_read_under_address_of(self):
        # it never rewrites the operand of &, so that read is not one of its uses
        x1 = MLILVariableSSA(MLILVariable('x'), 1)
        func = MediumLevelILFunction('f')
        func.create_block().add_instruction(MLILCall('f', [MLILVarSSA(x1), MLILAddressOf(MLILVarSSA(x1))]))
        copy_propagation = CopyPropagationPass()
        copy_propagation._count_uses(func)

        self.assertEqual(copy_propagation.use_counts, {x1: 1})


if __name__ == '__main__':
    unittest.main()
