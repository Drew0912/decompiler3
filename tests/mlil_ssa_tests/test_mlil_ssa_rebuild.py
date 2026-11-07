#!/usr/bin/env python3
"""Unit tests for the SSA passes' rebuilds: a rewritten operand keeps its source metadata, and SCCP leaves &x alone"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILVar, MLILAdd, MLILLogicalAnd,
    MLILLogicalNot, MLILAddressOf, MLILDeref,
)
from ir.mlil_ssa.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILRet
from ir.mlil_ssa.passes.pass_ssa_sccp import SCCP
from ir.mlil_ssa.passes.pass_ssa_constant_propagation import ConstantPropagationPass
from ir.mlil_ssa.passes.pass_ssa_nnf import NNFPass
from tests.shared.ir_utils import SOURCE_ADDRESS, SOURCE_INST_INDEX, with_metadata


class TestPassRebuildKeepsMetadata(unittest.TestCase):
    """A pass that rewrites an operand keeps the rewritten expression's source metadata (six of
    the seven old tables dropped it)."""

    def test_constant_propagation_keeps_rebuilt_expression_metadata(self):
        # a = 5; b = a + arg1 -> b = 5 + arg1, and the rebuilt add keeps its address
        func = MediumLevelILFunction('rebuild_metadata_test', 0)
        a = MLILVariable('a')
        b = MLILVariable('b')
        a1 = MLILVariableSSA(a, 1)
        b1 = MLILVariableSSA(b, 1)
        add = with_metadata(MLILAdd(MLILVarSSA(a1), MLILVar(MLILVariable('arg1'))))

        block = MediumLevelILBasicBlock(0)
        block.instructions = [MLILSetVarSSA(a1, MLILConst(5)), MLILSetVarSSA(b1, add), MLILRet(MLILVarSSA(b1))]
        func.basic_blocks = [block]

        ConstantPropagationPass().run(func)

        rebuilt = block.instructions[1].value
        self.assertIsNot(rebuilt, add, 'the add must have been rebuilt with the constant')
        self.assertIsInstance(rebuilt.lhs, MLILConst)
        self.assertEqual(rebuilt.address, SOURCE_ADDRESS)
        self.assertEqual(rebuilt.inst_index, SOURCE_INST_INDEX)

    def test_nnf_keeps_rebuilt_logical_op_metadata(self):
        # y = !!arg1 && arg2 -> y = arg1 && arg2: same operation, new operand, same metadata
        func = MediumLevelILFunction('nnf_metadata_test', 0)
        y1 = MLILVariableSSA(MLILVariable('y'), 1)
        arg1 = MLILVar(MLILVariable('arg1'))
        logical_and = with_metadata(MLILLogicalAnd(MLILLogicalNot(MLILLogicalNot(arg1)), MLILVar(MLILVariable('arg2'))))

        block = MediumLevelILBasicBlock(0)
        block.instructions = [MLILSetVarSSA(y1, logical_and), MLILRet(MLILVarSSA(y1))]
        func.basic_blocks = [block]

        NNFPass().run(func)

        rebuilt = block.instructions[0].value
        self.assertIsInstance(rebuilt, MLILLogicalAnd)
        self.assertIs(rebuilt.lhs, arg1, 'the double negation must have been removed')
        self.assertEqual(rebuilt.address, SOURCE_ADDRESS)
        self.assertEqual(rebuilt.inst_index, SOURCE_INST_INDEX)


class TestSCCPNeverSubstitutesUnderAddressOf(unittest.TestCase):
    """&x names x's storage, not its value: SCCP must leave &x alone even when it knows x's
    value. Before rebuild() existed this held only because SCCP's own table had no AddressOf
    entry; it is now an explicit leaf."""

    def run_sccp(self, make_value):
        # x = 5; y = <make_value(x)>; return y - returns what y's value became
        func = MediumLevelILFunction('sccp_address_of_test', 0)
        x = MLILVariable('x')
        y = MLILVariable('y')
        func.locals['x'] = x
        func.locals['y'] = y
        x1 = MLILVariableSSA(x, 1)
        y1 = MLILVariableSSA(y, 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILConst(5)),
            MLILSetVarSSA(y1, make_value(x1)),
            MLILRet(MLILVarSSA(y1)),
        ]
        func.basic_blocks = [block]

        SCCP(func).run()

        return block.instructions[1].value

    def test_address_of_known_constant_is_kept(self):
        value = self.run_sccp(lambda x1: MLILAddressOf(MLILVarSSA(x1)))

        self.assertIsInstance(value, MLILAddressOf)
        self.assertIsInstance(value.operand, MLILVarSSA, 'SCCP must never rewrite &x into &5')

    def test_deref_operand_is_still_substituted(self):
        # control: a pointer's value is an ordinary operand, so SCCP does substitute under *
        value = self.run_sccp(lambda x1: MLILDeref(MLILVarSSA(x1)))

        self.assertIsInstance(value, MLILDeref)
        self.assertIsInstance(value.operand, MLILConst)


if __name__ == '__main__':
    unittest.main()
