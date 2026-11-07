#!/usr/bin/env python3
"""Unit tests for MLIL operand traversal - operands(), walk() and map_operands(),
the one shared answer to "what does this node read" that every use collector and operand rewrite
is built on."""

from pathlib import Path
import itertools
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILInstruction, MediumLevelILBasicBlock, MediumLevelILCall, MLILVariable, MLILConst, MLILUndef,
    MLILVar, MLILSetVar, MLILBinaryOp, MLILUnaryOp, MLILAdd, MLILMul, MLILNeg, MLILAddressOf, MLILGoto, MLILIf,
    MLILRet, MLILCall, MLILSyscall, MLILCallScript, MLILLoadGlobal, MLILStoreGlobal, MLILLoadReg, MLILStoreReg,
    MLILNop, MLILDebug, MLILIntrinsic, MLILStoreDeref, walk, map_operands,
)
from ir.mlil_ssa.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILPhi
from tests.shared.ir_utils import concrete_subclasses


_const_values = itertools.count()

SOURCE_ADDRESS = 0x1234
SOURCE_INST_INDEX = 7
SOURCE_LLIL_INDEX = 9


def c() -> MLILConst:
    """A constant whose value no other c() call returns, so every operand is distinct"""
    return MLILConst(next(_const_values))


def samples() -> list:
    """One instance of every concrete MLIL node type, with distinct expression operands and telling
    values in the fields a rebuild must keep (branch targets, store indices, a call's output and
    tail-call mark, an intrinsic's name)"""
    block = MediumLevelILBasicBlock(0)
    other_block = MediumLevelILBasicBlock(1)
    var = MLILVariable('x')
    output = MLILVariable('result')
    ssa_var = MLILVariableSSA(var, 1)
    nodes = [
        c(), MLILUndef(), MLILVar(var), MLILSetVar(var, c()),
        MLILGoto(block), MLILIf(c(), block, other_block), MLILRet(c()), MLILRet(),
        MLILCall('f', [c(), c()], output, tail_call=True),
        MLILSyscall(1, 2, [c(), c()], output, tail_call=True),
        MLILCallScript('m', 'f', [c(), c()], output, tail_call=True),
        MLILLoadGlobal(0), MLILStoreGlobal(1, c()), MLILLoadReg(0), MLILStoreReg(2, c()),
        MLILNop(), MLILDebug('line', 5), MLILIntrinsic('POPN', [c(), c()]), MLILStoreDeref(c(), c()),
        MLILVarSSA(ssa_var), MLILSetVarSSA(ssa_var, c()), MLILPhi(ssa_var, [(MLILVariableSSA(var, 0), block)]),
    ]
    nodes += [cls(c(), c()) for cls in concrete_subclasses(MLILBinaryOp)]
    nodes += [cls(c()) for cls in concrete_subclasses(MLILUnaryOp)]
    return nodes


def expression_fields(node) -> list:
    """Every MLIL expression a node holds in a field, lists included."""
    found = []
    for value in vars(node).values():
        for item in (value if isinstance(value, (list, tuple)) else [value]):
            if isinstance(item, MediumLevelILInstruction):
                found.append(item)

    return found


def replaced(value, replacements: dict):
    """value with every MLIL expression in it, a list's or tuple's items included, swapped for its
    replacement (keyed by id)"""
    if isinstance(value, MediumLevelILInstruction):
        return replacements[id(value)]

    if isinstance(value, (list, tuple)):
        return type(value)(replaced(item, replacements) for item in value)

    return value


class TestOperandsCoverEveryExpressionField(unittest.TestCase):
    """operands() is the single list of a node's direct child expressions: every node type must
    return exactly the expressions it holds. A new node type fails here until it has a sample and
    its own operands()."""

    def test_every_node_type_has_a_sample(self):
        sampled = {type(node) for node in samples()}
        missing = concrete_subclasses(MediumLevelILInstruction) - sampled
        self.assertEqual(missing, set(), [cls.__name__ for cls in missing])

    def test_operands_are_exactly_the_expression_fields(self):
        for node in samples():
            with self.subTest(node=type(node).__name__):
                self.assertCountEqual(map(id, node.operands()), map(id, expression_fields(node)))

    def test_operands_are_in_evaluation_order(self):
        lhs, rhs = c(), c()
        args = [c(), c(), c()]
        dest, value = c(), c()

        self.assertEqual(list(MLILAdd(lhs, rhs).operands()), [lhs, rhs])
        self.assertEqual(list(MLILCall('f', args).operands()), args)
        self.assertEqual(list(MLILStoreDeref(dest, value).operands()), [dest, value])


class TestWalk(unittest.TestCase):
    """walk() yields a node and everything below it, pre-order in evaluation order."""

    def test_pre_order_left_to_right(self):
        a, b, d = c(), c(), c()
        add = MLILAdd(a, b)
        neg = MLILNeg(d)
        mul = MLILMul(add, neg)
        store = MLILStoreGlobal(0, mul)

        self.assertEqual(list(walk(store)), [store, mul, add, a, b, neg, d])

    def test_skip_yields_the_node_but_not_its_operand(self):
        var = MLILVar(MLILVariable('x'))
        address = MLILAddressOf(var)
        call = MLILCall('f', [address])

        self.assertEqual(list(walk(call, skip=(MLILAddressOf,))), [call, address])


class TestMapOperands(unittest.TestCase):
    """map_operands() rebuilds a node over new operands: each expression field gets its replacement
    and every other field, metadata included, is kept. A new node type with operands fails here until
    its own rebuild() does the same."""

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


class TestWalkerRulesKept(unittest.TestCase):
    """Rules individual passes keep on top of the shared traversal."""

    def test_call_types_are_exactly_the_three_call_classes(self):
        # passes rely on MediumLevelILCall covering exactly these three call classes
        self.assertEqual(concrete_subclasses(MediumLevelILCall), {MLILCall, MLILSyscall, MLILCallScript})


if __name__ == '__main__':
    unittest.main()
