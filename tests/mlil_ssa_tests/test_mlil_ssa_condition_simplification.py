#!/usr/bin/env python3
"""ConditionSimplificationPass and zero: only the int constant 0 turns a comparison into a plain truth test
(docs/falcom/ed9/ED9_VM.md, Truth)"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILEq, MLILNe, MLILLt, MLILLogicalNot,
)
from ir.mlil_ssa.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILIf, MLILRet
from ir.mlil_ssa.passes.pass_ssa_condition_simplification import ConditionSimplificationPass


INT_ZERO = 0
FLOAT_ZERO = 0.0


def read_x() -> MLILVarSSA:
    return MLILVarSSA(MLILVariableSSA(MLILVariable('x'), 0))


def simplify_mlil_condition(condition):
    """if (condition) - runs ConditionSimplificationPass, returns the condition it leaves"""
    func = MediumLevelILFunction('condition_test')
    entry, true_block, false_block = (MediumLevelILBasicBlock(index) for index in range(3))
    entry.instructions = [MLILIf(condition, true_block, false_block)]
    true_block.instructions = [MLILRet()]
    false_block.instructions = [MLILRet()]
    func.basic_blocks = [entry, true_block, false_block]

    ConditionSimplificationPass().run(func)

    return entry.instructions[0].condition


class TestMLILConditionSimplification(unittest.TestCase):
    def test_float_zero_is_left_alone(self):
        for condition in (MLILEq(read_x(), MLILConst(FLOAT_ZERO)),
                          MLILNe(MLILLt(read_x(), MLILConst(1)), MLILConst(FLOAT_ZERO))):
            with self.subTest(condition=str(condition)):
                self.assertIs(simplify_mlil_condition(condition), condition)

    def test_int_zero_still_simplifies(self):
        self.assertIsInstance(simplify_mlil_condition(MLILEq(read_x(), MLILConst(INT_ZERO))), MLILLogicalNot)
        condition = MLILNe(MLILLt(read_x(), MLILConst(1)), MLILConst(INT_ZERO))
        self.assertIsInstance(simplify_mlil_condition(condition), MLILLt)


if __name__ == '__main__':
    unittest.main()
