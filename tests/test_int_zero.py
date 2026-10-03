#!/usr/bin/env python3
'''is_int_zero: only the int constant 0 turns a comparison into a plain truth test. Every place that simplifies a
comparison with zero leaves a float zero as written - a float's truth in the VM is unverified.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from codegen.typescript import TypeScriptGenerator
from ir.core import SourceFloat, is_int_zero
from ir.hlil import (
    BinaryOp, HighLevelILFunction, HLILAssign, HLILBinaryOp, HLILBlock, HLILCall, HLILConst, HLILExprStmt, HLILIf,
    HLILUnaryOp, HLILVar, HLILVariable, UnaryOp,
)
from ir.hlil.passes.pass_control_flow_optimization import ControlFlowOptimizationPass
from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILEq, MLILNe, MLILLt, MLILLogicalNot,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILIf, MLILRet
from ir.mlil.passes.pass_ssa_condition_simplification import ConditionSimplificationPass

INT_ZERO = 0
FLOAT_ZERO = 0.0


class TestIsIntZero(unittest.TestCase):
    def test_only_the_int_zero(self):
        self.assertTrue(is_int_zero(INT_ZERO))
        for value in (FLOAT_ZERO, -0.0, SourceFloat(FLOAT_ZERO, '0.0'), 1, '0'):
            with self.subTest(value = repr(value)):
                self.assertFalse(is_int_zero(value))


def read_x() -> MLILVarSSA:
    return MLILVarSSA(MLILVariableSSA(MLILVariable('x'), 0))


def simplify_mlil_condition(condition):
    '''if (condition) - runs ConditionSimplificationPass, returns the condition it leaves'''
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
            with self.subTest(condition = str(condition)):
                self.assertIs(simplify_mlil_condition(condition), condition)

    def test_int_zero_still_simplifies(self):
        self.assertIsInstance(simplify_mlil_condition(MLILEq(read_x(), MLILConst(INT_ZERO))), MLILLogicalNot)
        condition = MLILNe(MLILLt(read_x(), MLILConst(1)), MLILConst(INT_ZERO))
        self.assertIsInstance(simplify_mlil_condition(condition), MLILLt)


def less_than_one() -> HLILBinaryOp:
    return HLILBinaryOp(BinaryOp.LT, HLILVar(HLILVariable('a')), HLILConst(1))


class TestHLILConditionInlining(unittest.TestCase):
    '''flag = a < 1; if (flag != zero) f() becomes if (a < 1) f() only for an int zero'''

    def statements_after_pass(self, zero) -> list:
        flag = HLILVariable('flag')
        func = HighLevelILFunction('inline_test')
        func.add_statement(HLILAssign(HLILVar(flag), less_than_one()))
        func.add_statement(HLILIf(HLILBinaryOp(BinaryOp.NE, HLILVar(flag), HLILConst(zero)),
                                  HLILBlock([HLILExprStmt(HLILCall('f', []))]), HLILBlock()))
        return ControlFlowOptimizationPass().run(func).body.statements

    def test_float_zero_is_not_inlined(self):
        self.assertEqual([type(stmt) for stmt in self.statements_after_pass(FLOAT_ZERO)], [HLILAssign, HLILIf])

    def test_int_zero_is_inlined(self):
        self.assertEqual([type(stmt) for stmt in self.statements_after_pass(INT_ZERO)], [HLILIf])


class TestTypeScriptZeroComparisons(unittest.TestCase):
    def format(self, expr) -> str:
        return TypeScriptGenerator._format_expr(expr)

    def test_float_zero_is_printed(self):
        self.assertEqual(self.format(HLILBinaryOp(BinaryOp.NE, less_than_one(), HLILConst(FLOAT_ZERO))), 'a < 1 != 0.0')
        self.assertEqual(self.format(HLILUnaryOp(UnaryOp.NOT, HLILBinaryOp(BinaryOp.EQ, HLILVar(HLILVariable('x')),
                                                                           HLILConst(FLOAT_ZERO)))), '!(x == 0.0)')

    def test_int_zero_still_simplifies(self):
        self.assertEqual(self.format(HLILBinaryOp(BinaryOp.NE, less_than_one(), HLILConst(INT_ZERO))), 'a < 1')
        self.assertEqual(self.format(HLILUnaryOp(UnaryOp.NOT, HLILBinaryOp(BinaryOp.EQ, HLILVar(HLILVariable('x')),
                                                                           HLILConst(INT_ZERO)))), 'x')


if __name__ == '__main__':
    unittest.main()
