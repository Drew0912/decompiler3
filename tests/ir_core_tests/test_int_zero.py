#!/usr/bin/env python3
"""is_int_zero: only the int constant 0 turns a comparison into a plain truth test. Every place that simplifies a
comparison with zero leaves a float zero as written: a jump truncates a Float, so 0.5 tests false while 0.5 != 0.0
holds (docs/falcom/ed9/ED9_VM.md, Truth)"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen.typescript import TypeScriptGenerator
from ir.core import SourceFloat, is_int_zero
from ir.hlil import BinaryOp, HLILBinaryOp, HLILConst, HLILUnaryOp, HLILVar, HLILVariable, UnaryOp

INT_ZERO = 0
FLOAT_ZERO = 0.0


class TestIsIntZero(unittest.TestCase):
    def test_only_the_int_zero(self):
        self.assertTrue(is_int_zero(INT_ZERO))
        for value in (FLOAT_ZERO, -0.0, SourceFloat(FLOAT_ZERO, '0.0'), 1, '0'):
            with self.subTest(value=repr(value)):
                self.assertFalse(is_int_zero(value))


def less_than_one() -> HLILBinaryOp:
    return HLILBinaryOp(BinaryOp.LT, HLILVar(HLILVariable('a')), HLILConst(1))


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
