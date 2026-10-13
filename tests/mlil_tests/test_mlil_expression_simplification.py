#!/usr/bin/env python3
'''Unit tests for ExpressionSimplificationPass: its algebraic identities fire only on int constants. With a float
constant x * 0.0 isn't int 0, and the VM's int/float mixing is unverified. Seen live: mon5047 printed 0.0 * arg4
as 0. All-ones is -1 (script ints are signed, SCCP folds ~0 to -1): x & -1 is x, x | -1 is -1.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILAdd, MLILMul, MLILDiv, MLILAnd, MLILOr,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILRet
from ir.mlil.passes.pass_ssa_expression_simplification import ExpressionSimplificationPass

ALL_BITS_SET = -1


def read_y() -> MLILVarSSA:
    return MLILVarSSA(MLILVariableSSA(MLILVariable('y'), 0))


def simplify(op):
    '''x = op; return - runs the pass, returns what x's value became'''
    func = MediumLevelILFunction('simplification_test', 0)
    block = MediumLevelILBasicBlock(0)
    block.instructions = [
        MLILSetVarSSA(MLILVariableSSA(MLILVariable('x'), 1), op),
        MLILRet(),
    ]
    func.basic_blocks = [block]

    ExpressionSimplificationPass().run(func)

    return block.instructions[0].value


class TestFloatConstants(unittest.TestCase):
    def test_float_identities_do_not_fire(self):
        for op in (MLILMul(MLILConst(0.0), read_y()), MLILMul(read_y(), MLILConst(1.0)),
                   MLILAdd(read_y(), MLILConst(0.0)), MLILAdd(MLILConst(-0.0), read_y()),
                   MLILDiv(read_y(), MLILConst(1.0))):
            with self.subTest(op = str(op)):
                self.assertIs(simplify(op), op)

    def test_int_identities_still_fire(self):
        y = read_y()
        self.assertIs(simplify(MLILMul(y, MLILConst(1))), y)

        y = read_y()
        self.assertIs(simplify(MLILAdd(MLILConst(0), y)), y)

        zero = simplify(MLILMul(MLILConst(0), read_y()))
        self.assertIsInstance(zero, MLILConst)
        self.assertEqual(zero.value, 0)


class TestAllBitsSet(unittest.TestCase):
    '''The constant arrives hex, as SCCP marks every constant under a bitwise operator'''

    def test_and_keeps_the_other_operand(self):
        for side in ('lhs', 'rhs'):
            y, all_bits = read_y(), MLILConst(ALL_BITS_SET, is_hex = True)
            op = MLILAnd(all_bits, y) if side == 'lhs' else MLILAnd(y, all_bits)
            with self.subTest(constant = side):
                self.assertIs(simplify(op), y)

    def test_or_becomes_the_all_ones_constant(self):
        for side in ('lhs', 'rhs'):
            y, all_bits = read_y(), MLILConst(ALL_BITS_SET, is_hex = True)
            op = MLILOr(all_bits, y) if side == 'lhs' else MLILOr(y, all_bits)
            with self.subTest(constant = side):
                self.assertIs(simplify(op), all_bits)


if __name__ == '__main__':
    unittest.main()
