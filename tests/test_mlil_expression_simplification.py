#!/usr/bin/env python3
'''Unit tests for ExpressionSimplificationPass: its algebraic identities fire only on int constants. With a float
constant x * 0.0 isn't int 0, and the VM's int/float mixing is unverified. Seen live: mon5047 printed 0.0 * arg4
as 0.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILAdd, MLILMul, MLILDiv,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILRet
from ir.mlil.passes.pass_ssa_expression_simplification import ExpressionSimplificationPass


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


if __name__ == '__main__':
    unittest.main()
