#!/usr/bin/env python3
"""Unit tests for MLILBinaryOp.rebuild()/MLILUnaryOp.rebuild() - the one path for rebuilding a
binary or unary op with new operands (previously 7 per-pass tables that had drifted apart)."""

from pathlib import Path
import inspect
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.core.il_options import ILOptions
from ir.mlil.mlil import MLILConst, MLILBinaryOp, MLILUnaryOp, MLILCall, MLILSyscall, MLILExternCall
from tests.shared.ir_utils import concrete_subclasses, with_metadata


BINARY_OP_COUNT = 18
UNARY_OP_COUNT = 6
OPERAND_FIELDS = {'lhs', 'rhs', 'operand'}
BINARY_OP_PARAMETERS = ['self', 'lhs', 'rhs', 'kwargs']
UNARY_OP_PARAMETERS = ['self', 'operand', 'kwargs']


def non_operand_state(inst) -> dict:
    """Every attribute except the operands. options is compared by content: a rebuilt node gets
    fresh default ILOptions, like every other MLIL rebuild (copy_metadata_from does not copy them),
    and no MLIL code sets them on an expression."""
    state = {key: value for key, value in vars(inst).items() if key not in OPERAND_FIELDS}
    state['options'] = {name: getattr(inst.options, name) for name in ILOptions.__slots__}
    return state


class TestRebuildEveryOp(unittest.TestCase):
    """Every concrete op rebuilds to the same type and operation with the new operands, and keeps
    its metadata and every other attribute. rebuild() calls type(self)(operands), so every
    constructor must take exactly the operands - a subclass with any extra parameter fails here
    instead of silently losing that state."""

    def test_every_op_constructor_takes_only_its_operands(self):
        for base, expected in [(MLILBinaryOp, BINARY_OP_PARAMETERS), (MLILUnaryOp, UNARY_OP_PARAMETERS)]:
            for cls in concrete_subclasses(base):
                with self.subTest(op=cls.__name__):
                    self.assertEqual(list(inspect.signature(cls.__init__).parameters), expected)

    def test_every_binary_op_rebuilds(self):
        classes = concrete_subclasses(MLILBinaryOp)
        self.assertEqual(len(classes), BINARY_OP_COUNT, sorted(cls.__name__ for cls in classes))

        for cls in classes:
            with self.subTest(op=cls.__name__):
                original = with_metadata(cls(MLILConst(1), MLILConst(2)))
                new_lhs, new_rhs = MLILConst(3), MLILConst(4)
                rebuilt = original.rebuild(new_lhs, new_rhs)

                self.assertIsNot(rebuilt, original)
                self.assertIs(type(rebuilt), cls)
                self.assertIs(rebuilt.lhs, new_lhs)
                self.assertIs(rebuilt.rhs, new_rhs)
                self.assertEqual(non_operand_state(rebuilt), non_operand_state(original))

    def test_every_unary_op_rebuilds(self):
        classes = concrete_subclasses(MLILUnaryOp)
        self.assertEqual(len(classes), UNARY_OP_COUNT, sorted(cls.__name__ for cls in classes))

        for cls in classes:
            with self.subTest(op=cls.__name__):
                original = with_metadata(cls(MLILConst(1)))
                new_operand = MLILConst(2)
                rebuilt = original.rebuild(new_operand)

                self.assertIsNot(rebuilt, original)
                self.assertIs(type(rebuilt), cls)
                self.assertIs(rebuilt.operand, new_operand)
                self.assertEqual(non_operand_state(rebuilt), non_operand_state(original))


class TestCallRebuildKeepsTailCall(unittest.TestCase):
    """rebuild() of every call kind keeps the tail-call mark"""

    def test_every_call_kind_keeps_its_tail_call_mark(self):
        calls = [
            MLILCall('f', [MLILConst(1)], tail_call=True),
            MLILSyscall(1, 2, [MLILConst(1)], tail_call=True),
            MLILExternCall('module', 'func', [MLILConst(1)], tail_call=True),
        ]

        for call in calls:
            with self.subTest(call=type(call).__name__):
                rebuilt = call.rebuild(MLILConst(2))

                self.assertIs(type(rebuilt), type(call))
                self.assertTrue(rebuilt.tail_call)


if __name__ == '__main__':
    unittest.main()
