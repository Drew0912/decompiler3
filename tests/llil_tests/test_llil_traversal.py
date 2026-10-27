#!/usr/bin/env python3
"""Unit tests for LLIL operand traversal - operands() and walk(), the one shared answer to "what does this node read"
over the generic nodes (ir/llil/) and the Falcom ones (falcom/ed9/ir/llil/)"""

from pathlib import Path
import itertools
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import (
    LowLevelILInstruction, LowLevelILBasicBlock, LowLevelILStackStore, LowLevelILStackLoad, LowLevelILFrameLoad,
    LowLevelILFrameStore, LowLevelILLoad, LowLevelILStore, LowLevelILSpAdd, LowLevelILStackAddr, LowLevelILFrameAddr,
    LowLevelILRegStore, LowLevelILRegLoad, LowLevelILBinaryOp, LowLevelILUnaryOp, LowLevelILAdd, LowLevelILMul,
    LowLevelILNeg, LowLevelILJmp, LowLevelILIf, LowLevelILCall, LowLevelILRet, LowLevelILConst, LowLevelILDebug,
    LowLevelILSyscall, walk,
)
from falcom.ed9.ir.llil.constants import (
    LowLevelILConstFuncId, LowLevelILConstRetAddrBlock, LowLevelILConstScript, LowLevelILConstScriptName,
)
from falcom.ed9.ir.llil.llil_ext import (
    LowLevelILCallScript, LowLevelILCallScriptNoReturn, LowLevelILDebugLog, LowLevelILGlobalLoad,
    LowLevelILGlobalStore,
)
from tests.shared.ir_utils import concrete_subclasses


_const_values = itertools.count()

# Node types with subclasses of their own, so concrete_subclasses (leaf classes only) leaves them out
INSTANTIATED_BASES = {LowLevelILConst, LowLevelILCall}


def c() -> LowLevelILConst:
    """A constant whose value no other c() call returns, so every operand is distinct"""
    return LowLevelILConst(next(_const_values))


def samples() -> list:
    """One instance of every LLIL node type, generic and Falcom, with distinct expression operands"""
    block = LowLevelILBasicBlock(0)
    other_block = LowLevelILBasicBlock(1)
    nodes = [
        LowLevelILStackStore(c(), 0, 1), LowLevelILStackLoad(0, 1), LowLevelILFrameLoad(0),
        LowLevelILFrameStore(c(), 0), LowLevelILLoad(c()), LowLevelILStore(c(), c()), LowLevelILSpAdd(1),
        LowLevelILStackAddr(0), LowLevelILFrameAddr(0), LowLevelILRegStore(0, c()), LowLevelILRegLoad(0),
        LowLevelILJmp(block), LowLevelILIf(c(), block, other_block), LowLevelILCall('f', block, [c(), c()]),
        LowLevelILRet(), c(), LowLevelILDebug('line', 5), LowLevelILSyscall(1, 2, 2, [c(), c()]),
        LowLevelILCallScript('m', 'f', [c(), c()], block), LowLevelILCallScriptNoReturn('m', 'f', [c(), c()]),
        LowLevelILGlobalLoad(0), LowLevelILGlobalStore(1, c()), LowLevelILDebugLog([c(), c()]),
        LowLevelILConstFuncId(), LowLevelILConstRetAddrBlock(block), LowLevelILConstScript(),
        LowLevelILConstScriptName(),
    ]
    nodes += [cls(c(), c()) for cls in concrete_subclasses(LowLevelILBinaryOp)]
    nodes += [cls(c()) for cls in concrete_subclasses(LowLevelILUnaryOp)]
    return nodes


def expression_fields(node) -> list:
    """Every LLIL expression a node holds in a field, lists included"""
    found = []
    for value in vars(node).values():
        for item in (value if isinstance(value, (list, tuple)) else [value]):
            if isinstance(item, LowLevelILInstruction):
                found.append(item)

    return found


class TestOperandsCoverEveryExpressionField(unittest.TestCase):
    """operands() is the single list of a node's direct child expressions: every node type must return exactly the
    expressions it holds. A new node type fails here until it has a sample and, if it holds an expression, its own
    operands()"""

    def test_every_node_type_has_a_sample(self):
        sampled = {type(node) for node in samples()}
        missing = (concrete_subclasses(LowLevelILInstruction) | INSTANTIATED_BASES) - sampled
        self.assertEqual(missing, set(), [cls.__name__ for cls in missing])

    def test_operands_are_exactly_the_expression_fields(self):
        for node in samples():
            with self.subTest(node=type(node).__name__):
                self.assertCountEqual(map(id, node.operands()), map(id, expression_fields(node)))

    def test_operands_are_in_evaluation_order(self):
        lhs, rhs = c(), c()
        args = [c(), c(), c()]
        dest, value = c(), c()

        self.assertEqual(list(LowLevelILAdd(lhs, rhs).operands()), [lhs, rhs])
        self.assertEqual(list(LowLevelILCall('f', None, args).operands()), args)
        self.assertEqual(list(LowLevelILSyscall(1, 2, len(args), args).operands()), args)
        self.assertEqual(list(LowLevelILDebugLog(args).operands()), args)
        self.assertEqual(list(LowLevelILStore(dest, value).operands()), [dest, value])


class TestWalk(unittest.TestCase):
    """walk() yields a node and everything below it, pre-order in evaluation order"""

    def test_pre_order_left_to_right(self):
        a, b, d = c(), c(), c()
        add = LowLevelILAdd(a, b)
        neg = LowLevelILNeg(d)
        mul = LowLevelILMul(add, neg)
        store = LowLevelILGlobalStore(0, mul)

        self.assertEqual(list(walk(store)), [store, mul, add, a, b, neg, d])

    def test_skip_yields_the_node_but_not_its_operand(self):
        pointer = LowLevelILFrameLoad(0)
        load = LowLevelILLoad(pointer)
        call = LowLevelILCall('f', None, [load])

        self.assertEqual(list(walk(call, skip=(LowLevelILLoad,))), [call, load])


if __name__ == '__main__':
    unittest.main()
