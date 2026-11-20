#!/usr/bin/env python3
"""The HLIL DSL's own conversion (convert_ed9_mlil_to_hlil_dsl): the arms' code addresses the structurer records, the
branch address order pass on hand-built trees (each hazard the slice A plan reviews named: an unknown position, a test
that is not a truth test, a comparison inside one, a float zero, the guard whose following code does not return), and
a block of nothing but line markers still falling through once they are hidden"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.ir.hlil.hlil_converter import convert_ed9_mlil_to_hlil, convert_ed9_mlil_to_hlil_dsl
from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILConst,
    HLILExprStmt,
    HLILIf,
    HLILReturn,
    HLILVar,
    HLILVariable,
    HLILWhile,
)
from ir.hlil.hlil import iter_tree
from ir.hlil.passes.dsl import BranchAddressOrderPass
from ir.mlil.mlil import MediumLevelILFunction, MLILCall, MLILDebug, MLILIf, MLILRet, MLILVar
from tests.shared.ir_utils import connect

FIRST = 0x20
SECOND = 0x30
THIRD = 0x40
FOURTH = 0x50
LIMIT = 5
LINE = 100


def call(name: str) -> HLILExprStmt:
    return HLILExprStmt(HLILCall(name, []))


def arm(name: str, entry: int | None, returns: bool = False) -> HLILBlock:
    """An arm calling name (then returning), entered at entry"""
    block = HLILBlock([call(name), *([HLILReturn()] if returns else [])])
    block.entry_address = entry
    return block


def truth_test(op: BinaryOp, tested=None) -> HLILBinaryOp:
    """tested == 0 or tested != 0, as the structurer writes a jump's test (tested: a call by default)"""
    return HLILBinaryOp(op, tested if tested is not None else HLILCall('test', []), HLILConst(0))


def guard(op: BinaryOp, name: str, entry: int, following: int | None) -> HLILIf:
    """An early return, if (test op 0) { name(); return }, whose other arm the structurer placed after it"""
    stmt = HLILIf(truth_test(op), arm(name, entry, returns=True))
    stmt.following_address = following
    return stmt


def ordered(*statements) -> list:
    """statements after the pass, as a function's body"""
    func = HighLevelILFunction('ordered')
    func.body.statements = list(statements)
    return BranchAddressOrderPass().run(func).body.statements


def called(block: HLILBlock) -> list[str]:
    """The calls block makes, in order, nested ones included"""
    return [node.func_name for node in iter_tree(block) if isinstance(node, HLILCall) and node.func_name != 'test']


class TestArms(unittest.TestCase):
    def test_else_arm_first_in_the_code_is_swapped_and_the_test_flipped(self):
        [stmt] = ordered(HLILIf(truth_test(BinaryOp.EQ), arm('late', SECOND), arm('early', FIRST)))

        self.assertEqual(called(stmt.true_block), ['early'])
        self.assertEqual(called(stmt.false_block), ['late'])
        self.assertEqual(stmt.condition.op, BinaryOp.NE)

    def test_arms_in_code_order_are_left_alone(self):
        [stmt] = ordered(HLILIf(truth_test(BinaryOp.NE), arm('early', FIRST), arm('late', SECOND)))

        self.assertEqual(called(stmt.true_block), ['early'])
        self.assertEqual(stmt.condition.op, BinaryOp.NE)

    def test_an_unknown_position_is_left_alone(self):
        [stmt] = ordered(HLILIf(truth_test(BinaryOp.EQ), arm('late', SECOND), arm('early', None)))

        self.assertEqual(called(stmt.true_block), ['late'])
        self.assertEqual(stmt.condition.op, BinaryOp.EQ)

    def test_a_test_that_is_not_a_truth_test_is_left_alone(self):
        # x < 0.5 swapped would need x >= 0.5, which a NaN tells apart: the pass never complements a comparison
        test = HLILBinaryOp(BinaryOp.LT, HLILVar(HLILVariable('x')), HLILConst(0.5))
        [stmt] = ordered(HLILIf(test, arm('late', SECOND), arm('early', FIRST)))

        self.assertIs(stmt.condition, test)
        self.assertEqual(called(stmt.true_block), ['late'])

    def test_a_float_zero_is_not_a_truth_test(self):
        test = HLILBinaryOp(BinaryOp.EQ, HLILCall('test', []), HLILConst(0.0))
        [stmt] = ordered(HLILIf(test, arm('late', SECOND), arm('early', FIRST)))

        self.assertIs(stmt.condition, test)

    def test_the_comparison_inside_a_truth_test_is_kept(self):
        compared = HLILBinaryOp(BinaryOp.LT, HLILVar(HLILVariable('x')), HLILConst(LIMIT))
        [stmt] = ordered(HLILIf(truth_test(BinaryOp.EQ, compared), arm('late', SECOND), arm('early', FIRST)))

        self.assertEqual(stmt.condition.op, BinaryOp.NE)
        self.assertIs(stmt.condition.lhs, compared)
        self.assertEqual(compared.op, BinaryOp.LT)

    def test_arms_inside_a_loop_body_are_ordered(self):
        inner = HLILIf(truth_test(BinaryOp.EQ), arm('late', SECOND), arm('early', FIRST))
        [loop] = ordered(HLILWhile(HLILConst(1), HLILBlock([inner])))

        self.assertEqual(called(loop.body.statements[0].true_block), ['early'])


class TestGuards(unittest.TestCase):
    def test_a_guard_whose_following_code_comes_first_is_turned_around(self):
        statements = ordered(guard(BinaryOp.EQ, 'guarded', SECOND, FIRST), call('following'), HLILReturn())

        turned, *after = statements
        self.assertEqual(turned.condition.op, BinaryOp.NE)
        self.assertEqual(called(turned.true_block), ['following'])
        self.assertIsNone(turned.false_block)
        self.assertEqual([type(stmt) for stmt in after], [HLILExprStmt, HLILReturn])
        self.assertEqual(after[0].expr.func_name, 'guarded')

    def test_a_guard_whose_following_code_does_not_return_is_left_alone(self):
        statements = ordered(guard(BinaryOp.EQ, 'guarded', SECOND, FIRST), call('following'))

        self.assertEqual(called(statements[0].true_block), ['guarded'])
        self.assertEqual(statements[0].condition.op, BinaryOp.EQ)

    def test_a_guard_in_code_order_is_left_alone(self):
        statements = ordered(guard(BinaryOp.NE, 'guarded', FIRST, SECOND), call('following'), HLILReturn())

        self.assertEqual(called(statements[0].true_block), ['guarded'])

    def test_two_guards_in_a_row_are_both_turned(self):
        # if (a) { first(); return } if (b) { second(); return } rest(); return, laid out rest, second, first
        statements = ordered(guard(BinaryOp.EQ, 'first', FOURTH, SECOND),
                             guard(BinaryOp.EQ, 'second', THIRD, FIRST),
                             call('rest'), HLILReturn())

        outer, *after_outer = statements
        inner, *after_inner = outer.true_block.statements
        self.assertEqual(called(inner.true_block), ['rest'])
        self.assertEqual([stmt.expr.func_name for stmt in after_inner if isinstance(stmt, HLILExprStmt)], ['second'])
        self.assertEqual([stmt.expr.func_name for stmt in after_outer if isinstance(stmt, HLILExprStmt)], ['first'])


def reversed_arms_mlil() -> MediumLevelILFunction:
    """if (arg1) goto late else early, both returning: the late arm's block at the higher address"""
    func = MediumLevelILFunction('reversed_arms', FIRST)
    entry = func.create_block(start=FIRST, label='entry')
    early = func.create_block(start=SECOND, label='early')
    late = func.create_block(start=THIRD, label='late')
    entry.add_instruction(MLILIf(MLILVar(func.get_or_create_parameter(1, 'arg1')), late, early))
    for block in (early, late):
        block.add_instruction(MLILCall(block.label, []))
        block.add_instruction(MLILRet(None))

    return connect(func)


def marker_only_block_mlil() -> MediumLevelILFunction:
    """if (arg1) goto markers else other; markers: a line marker only, falling through to called; called and other
    each call and return (a targeted marker before another label)"""
    func = MediumLevelILFunction('marker_only', FIRST)
    entry = func.create_block(start=FIRST, label='entry')
    markers = func.create_block(start=SECOND, label='markers')
    reached = func.create_block(start=THIRD, label='called')
    other = func.create_block(start=FOURTH, label='other')
    entry.add_instruction(MLILIf(MLILVar(func.get_or_create_parameter(1, 'arg1')), markers, other))
    markers.add_instruction(MLILDebug('line', LINE, address=SECOND))
    for block in (reached, other):
        block.add_instruction(MLILCall(block.label, []))
        block.add_instruction(MLILRet(None))

    return connect(func)


class TestConversion(unittest.TestCase):
    def test_the_structurer_records_the_arm_and_the_code_it_placed_after(self):
        # Both arms return, so the true one is an early return's if and the other follows it
        hlil = convert_ed9_mlil_to_hlil(reversed_arms_mlil())
        [stmt] = [node for node in iter_tree(hlil.body) if isinstance(node, HLILIf)]

        self.assertEqual(called(stmt.true_block), ['late'])
        self.assertEqual(stmt.true_block.entry_address, THIRD)
        self.assertEqual(stmt.following_address, SECOND)

    def test_a_block_of_markers_only_still_falls_through(self):
        hlil = convert_ed9_mlil_to_hlil_dsl(marker_only_block_mlil())

        self.assertEqual(sorted(called(hlil.body)), ['called', 'other'])

    def test_the_markers_are_back_after_the_conversion(self):
        mlil = marker_only_block_mlil()
        before = [block.instructions for block in mlil.basic_blocks]

        convert_ed9_mlil_to_hlil_dsl(mlil)

        self.assertTrue(all(block.instructions is kept for block, kept in zip(mlil.basic_blocks, before)))


if __name__ == '__main__':
    unittest.main()
