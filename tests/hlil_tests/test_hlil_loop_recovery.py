#!/usr/bin/env python3
"""Unit tests for HLIL loop recovery."""

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILBreak,
    HLILCall,
    HLILComment,
    HLILConst,
    HLILContinue,
    HLILDoWhile,
    HLILExprStmt,
    HLILIf,
    HLILReturn,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
    HLILWhile,
    LoopRecoveryPass,
)
from tests.shared.ir_utils import FrontendInt


EXIT_THRESHOLD = 0
RETURN_VALUE = 1
GUARD_LINE = 'line(782)'
BODY_CALL = 'btl_chr_list_next'
SWITCH_CASE_VALUE = 3
LOOP_LABEL = 'loop_1'
STRING_VALUE = 'abc'
OUTER_LABEL = 'outer'


def make_var() -> HLILVar:
    return HLILVar(HLILVariable('remaining'))


def make_exit_condition() -> HLILBinaryOp:
    """remaining <= 0 - true when the loop should stop"""
    return HLILBinaryOp(BinaryOp.LE, make_var(), HLILConst(EXIT_THRESHOLD))


def make_body_statement() -> HLILExprStmt:
    return HLILExprStmt(HLILCall(BODY_CALL, []))


def make_guard(exit_stmt) -> HLILIf:
    """if (remaining <= 0) { <exit_stmt> }"""
    return HLILIf(make_exit_condition(), HLILBlock([exit_stmt]), None)


def make_flag(name: str) -> HLILVar:
    return HLILVar(HLILVariable(name))


def make_call(name: str) -> HLILExprStmt:
    return HLILExprStmt(HLILCall(name, []))


def call_names(block: HLILBlock) -> list:
    """The called functions among a block's top-level statements, in order"""
    return [stmt.expr.func_name for stmt in block.statements if isinstance(stmt, HLILExprStmt)]


def run_pass(loop: HLILWhile) -> HighLevelILFunction:
    func = HighLevelILFunction('test_loop')
    func.body.add_statement(loop)
    return LoopRecoveryPass().run(func)


class TestLoopRecoveryReturnGuard(unittest.TestCase):
    """while (1) { if (c) return x; body } -> while (!c) { body } return x"""

    def test_return_guard_becomes_loop_condition(self):
        guard = HLILIf(
            make_exit_condition(),
            HLILBlock([HLILComment(GUARD_LINE), HLILReturn(HLILConst(RETURN_VALUE))]),
            None,
        )
        loop = HLILWhile(HLILConst(1), HLILBlock([guard, make_body_statement()]))

        func = run_pass(loop)

        # The loop survives, with the guard negated into its condition
        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)
        self.assertIsInstance(recovered.condition, HLILBinaryOp)
        self.assertEqual(recovered.condition.op, BinaryOp.GT)

        # The guard is gone from the body, the real work stays
        self.assertEqual(len(recovered.body.statements), 1)
        self.assertIsInstance(recovered.body.statements[0], HLILExprStmt)

        # The return follows the loop, still carrying its line comment
        self.assertIsInstance(func.body.statements[1], HLILComment)
        self.assertEqual(func.body.statements[1].text, GUARD_LINE)
        self.assertIsInstance(func.body.statements[2], HLILReturn)
        self.assertEqual(func.body.statements[2].value.value, RETURN_VALUE)

    def test_break_in_body_refuses_the_rotation(self):
        # A break leaves the loop without returning, so the return must not be
        # hoisted past it
        guard = make_guard(HLILReturn(HLILConst(RETURN_VALUE)))
        inner_break = HLILIf(make_exit_condition(), HLILBlock([HLILBreak()]), None)
        loop = HLILWhile(HLILConst(1), HLILBlock([guard, inner_break, make_body_statement()]))

        func = run_pass(loop)

        self.assertEqual(len(func.body.statements), 1)
        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)
        self.assertIsInstance(recovered.condition, HLILConst)
        self.assertEqual(recovered.condition.value, 1)

    def test_break_inside_nested_switch_still_allows_the_rotation(self):
        # That break belongs to the switch, not to this loop
        guard = make_guard(HLILReturn(HLILConst(RETURN_VALUE)))
        nested = HLILSwitch(make_var(), [
            HLILSwitchCase([HLILConst(SWITCH_CASE_VALUE)], HLILBlock([HLILBreak()])),
        ])
        loop = HLILWhile(HLILConst(1), HLILBlock([guard, nested]))

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)
        self.assertEqual(recovered.condition.op, BinaryOp.GT)
        self.assertIsInstance(func.body.statements[1], HLILReturn)

    def test_guard_with_else_is_not_treated_as_a_lone_return(self):
        guard = HLILIf(
            make_exit_condition(),
            HLILBlock([HLILReturn(HLILConst(RETURN_VALUE))]),
            HLILBlock([make_body_statement()]),
        )
        loop = HLILWhile(HLILConst(1), HLILBlock([guard]))

        func = run_pass(loop)

        self.assertEqual(len(func.body.statements), 1)
        self.assertIsInstance(func.body.statements[0], HLILWhile)


class TestLoopRecoveryFloatConditions(unittest.TestCase):
    """A float condition is never folded or taken as always true: its truth depends on what tests it
    (docs/falcom/ed9/ED9_VM.md, Truth)"""

    def test_float_condition_is_left_alone(self):
        for condition in (HLILConst(1.0), HLILBinaryOp(BinaryOp.EQ, HLILConst(0.5), HLILConst(0.5))):
            with self.subTest(condition=str(condition)):
                loop = HLILWhile(condition, HLILBlock([make_guard(HLILBreak()), make_body_statement()]))

                recovered = run_pass(loop).body.statements[0]

                self.assertIs(recovered.condition, condition)
                self.assertEqual(len(recovered.body.statements), 2)

    def test_int_comparison_still_folds_and_rotates(self):
        condition = HLILBinaryOp(BinaryOp.EQ, HLILConst(1), HLILConst(1))
        loop = HLILWhile(condition, HLILBlock([make_guard(HLILBreak()), make_body_statement()]))

        recovered = run_pass(loop).body.statements[0]

        self.assertEqual(recovered.condition.op, BinaryOp.GT)
        self.assertEqual(len(recovered.body.statements), 1)


class TestLoopRecoveryNonIntConditions(unittest.TestCase):
    """A string or a frontend's own int is never folded or taken as always true: its truth and comparisons are the
    VM's (ED9 tests both false, and makes a Raw word and "abc" equal to 0)"""

    def test_non_int_condition_is_left_alone(self):
        for condition in (HLILConst(STRING_VALUE), HLILConst(FrontendInt(1)),
                          HLILBinaryOp(BinaryOp.EQ, HLILConst(STRING_VALUE), HLILConst(0)),
                          HLILBinaryOp(BinaryOp.EQ, HLILConst(FrontendInt(5)), HLILConst(0))):
            with self.subTest(condition=str(condition)):
                loop = HLILWhile(condition, HLILBlock([make_guard(HLILBreak()), make_body_statement()]))

                recovered = run_pass(loop).body.statements[0]

                self.assertIs(recovered.condition, condition)
                self.assertEqual(len(recovered.body.statements), 2)


class TestLoopRecoveryDoWhileRotation(unittest.TestCase):
    """while (1) { body; if (c) break; } -> do { body } while (!c), and the bottom test structuring
    writes, while (1) { body; if (c) continue; else break; } -> do { body } while (c) (45 loops of
    the five games' corpus, menu loops most)."""

    def test_trailing_break_guard_becomes_do_while(self):
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), guard]))

        func = run_pass(loop)

        self.assertEqual(len(func.body.statements), 1)
        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILDoWhile)
        self.assertEqual(recovered.condition.op, BinaryOp.GT)
        self.assertEqual(len(recovered.body.statements), 1)
        self.assertIsInstance(recovered.body.statements[0], HLILExprStmt)

    def test_do_while_rotation_keeps_the_original_address(self):
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), guard]))
        loop.address = 0x1234
        loop.mlil_index = 7

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILDoWhile)
        self.assertEqual(recovered.address, 0x1234)
        self.assertEqual(recovered.mlil_index, 7)

    def test_trailing_continue_test_becomes_do_while(self):
        """The test kept as it is: the loop goes round while it holds"""
        condition = make_exit_condition()
        test = HLILIf(condition, HLILBlock([HLILContinue()]), HLILBlock([HLILBreak()]))
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), test]))

        recovered = run_pass(loop).body.statements[0]

        self.assertIsInstance(recovered, HLILDoWhile)
        self.assertIs(recovered.condition, condition)
        self.assertEqual(call_names(recovered.body), [BODY_CALL])

    def test_mirrored_trailing_test_is_negated(self):
        """if (c) break; else continue; - the loop goes round while c does not hold"""
        test = HLILIf(make_exit_condition(), HLILBlock([HLILBreak()]), HLILBlock([HLILContinue()]))
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), test]))

        recovered = run_pass(loop).body.statements[0]

        self.assertIsInstance(recovered, HLILDoWhile)
        self.assertEqual(recovered.condition.op, BinaryOp.GT)
        self.assertEqual(call_names(recovered.body), [BODY_CALL])

    def test_body_of_only_the_test_stays_a_while(self):
        """Nothing before the test: while (c) { } reads better than an empty do, and runs the same"""
        for name, markers in {'bare': [], 'after a line marker': [HLILComment(GUARD_LINE)]}.items():
            with self.subTest(name):
                condition = make_exit_condition()
                test = HLILIf(condition, HLILBlock([HLILContinue()]), HLILBlock([HLILBreak()]))
                loop = HLILWhile(HLILConst(1), HLILBlock(markers + [test]))

                recovered = run_pass(loop).body.statements[0]

                self.assertIsInstance(recovered, HLILWhile)
                self.assertIs(recovered.condition, condition)
                self.assertEqual(recovered.body.statements, markers)

    def assert_trailing_test_refused(self, true_arm: list, false_arm: list):
        """The loop stays a while (1) with its body and its test as they were"""
        test = HLILIf(make_exit_condition(), HLILBlock(true_arm), HLILBlock(false_arm))
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), test]))

        recovered = run_pass(loop).body.statements[0]

        self.assertIsInstance(recovered, HLILWhile)
        self.assertEqual(recovered.condition.value, 1)
        self.assertEqual(len(recovered.body.statements), 2)
        self.assertIs(recovered.body.statements[-1], test)

    def test_labeled_jump_in_an_arm_refuses_the_trailing_test(self):
        """A labeled jump leaves for another loop: rotating would delete it with the test"""
        arms = {
            'labeled continue, bare break': ([HLILContinue(OUTER_LABEL)], [HLILBreak()]),
            'bare continue, labeled break': ([HLILContinue()], [HLILBreak(OUTER_LABEL)]),
            'labeled break, bare continue': ([HLILBreak(OUTER_LABEL)], [HLILContinue()]),
            'bare break, labeled continue': ([HLILBreak()], [HLILContinue(OUTER_LABEL)]),
        }
        for name, (true_arm, false_arm) in arms.items():
            with self.subTest(name):
                self.assert_trailing_test_refused(true_arm, false_arm)

    def test_comment_in_an_arm_refuses_the_trailing_test(self):
        """The arm is more than the bare jump: rotating would drop the comment"""
        arms = {
            'comment before continue': ([HLILComment(GUARD_LINE), HLILContinue()], [HLILBreak()]),
            'comment before break':    ([HLILContinue()], [HLILComment(GUARD_LINE), HLILBreak()]),
            'comment after continue': ([HLILContinue(), HLILComment(GUARD_LINE)], [HLILBreak()]),
            'comment after break':     ([HLILBreak(), HLILComment(GUARD_LINE)], [HLILContinue()]),
        }
        for name, (true_arm, false_arm) in arms.items():
            with self.subTest(name):
                self.assert_trailing_test_refused(true_arm, false_arm)


class TestLoopRecoveryContinueGuard(unittest.TestCase):
    """continue means something different in while(1) (always jumps to top, never exits) than
    in do-while (jumps to the exit test, can exit) - so the trailing-exit rotation must refuse
    when the body has a continue that targets this loop."""

    def test_continue_in_body_refuses_do_while_rotation(self):
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([HLILContinue(), make_body_statement(), guard]))

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)
        self.assertIsInstance(recovered.condition, HLILConst)
        self.assertEqual(recovered.condition.value, 1)
        # Nothing lost: refusal happens before _trailing_exit_condition would have popped the
        # trailing break-guard, so the body is exactly as it started
        self.assertEqual(len(recovered.body.statements), 3)

    def test_labeled_continue_elsewhere_refuses_the_trailing_continue_test(self):
        # A labeled continue may name this loop or one outside it: either way the test would run in its place
        for label in (LOOP_LABEL, OUTER_LABEL):
            with self.subTest(label):
                early = HLILIf(make_flag('skip'), HLILBlock([HLILContinue(label)]), None)
                test = HLILIf(make_exit_condition(), HLILBlock([HLILContinue()]), HLILBlock([HLILBreak()]))
                loop = HLILWhile(HLILConst(1), HLILBlock([early, make_body_statement(), test]), label=LOOP_LABEL)

                recovered = run_pass(loop).body.statements[0]

                self.assertIsInstance(recovered, HLILWhile)
                self.assertEqual(len(recovered.body.statements), 3)

    def test_continue_inside_nested_loop_does_not_block_rotation(self):
        # That continue belongs to the nested loop, not to this one
        inner_loop = HLILWhile(make_exit_condition(), HLILBlock([HLILContinue()]))
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([inner_loop, make_body_statement(), guard]))

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILDoWhile)

    def test_continue_inside_nested_switch_still_blocks_rotation(self):
        # Unlike break, a switch does not absorb a bare continue - it always targets the
        # nearest enclosing loop, which is this one
        inner_switch = HLILSwitch(make_var(), [
            HLILSwitchCase([HLILConst(SWITCH_CASE_VALUE)], HLILBlock([HLILContinue()])),
        ])
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([inner_switch, make_body_statement(), guard]))

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)

    def test_labelled_continue_from_nested_construct_still_blocks_rotation(self):
        loop_label = 'loop_1'
        inner_switch = HLILSwitch(make_var(), [
            HLILSwitchCase([HLILConst(SWITCH_CASE_VALUE)], HLILBlock([HLILContinue(label=loop_label)])),
        ])
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([inner_switch, make_body_statement(), guard]), label=loop_label)

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)


class TestLoopRecoveryDoWhileLabel(unittest.TestCase):
    """A labelled while(1) loop must keep its label through the do-while rewrite - HLILDoWhile
    previously had no way to carry one at all, leaving any continue/break naming it dangling."""

    def test_labelled_loop_keeps_its_label_after_do_while_rotation(self):
        loop_label = 'loop_1'
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), guard]), label=loop_label)

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILDoWhile)
        self.assertEqual(recovered.label, loop_label)


class TestGuardedLoopKeepsItsBody(unittest.TestCase):
    """while (1) { if (c) { body } else { break } } is while (c) { body }"""

    def test_break_in_the_else_arm(self):
        condition = make_flag('c')
        loop = HLILWhile(HLILConst(1), HLILBlock([
            HLILIf(condition, HLILBlock([make_call('work'), make_call('more')]), HLILBlock([HLILBreak()])),
        ]))

        [recovered] = run_pass(loop).body.statements

        self.assertIsInstance(recovered, HLILWhile)
        self.assertIs(recovered.condition, condition)
        self.assertEqual(call_names(recovered.body), ['work', 'more'])

    def test_break_in_the_then_arm_negates_the_test(self):
        loop = HLILWhile(HLILConst(1), HLILBlock([
            HLILIf(make_flag('c'), HLILBlock([HLILBreak()]), HLILBlock([make_call('work')])),
        ]))

        [recovered] = run_pass(loop).body.statements

        self.assertEqual(str(recovered.condition), '!c')
        self.assertEqual(call_names(recovered.body), ['work'])

    def test_comments_above_the_test_move_into_the_body(self):
        comment = HLILComment(GUARD_LINE)
        loop = HLILWhile(HLILConst(1), HLILBlock([
            comment, HLILIf(make_flag('c'), HLILBlock([make_call('work')]), HLILBlock([HLILBreak()])),
        ]))

        [recovered] = run_pass(loop).body.statements

        self.assertIs(recovered.body.statements[0], comment)
        self.assertEqual(call_names(recovered.body), ['work'])


class TestLeadingExitGuardLeavesTheBody(unittest.TestCase):
    def test_guard_is_removed_from_a_longer_body(self):
        guard = HLILIf(make_flag('done'), HLILBlock([HLILBreak()]), None)
        loop = HLILWhile(HLILConst(1), HLILBlock([guard, make_call('a'), make_call('b'), make_call('c')]))

        [recovered] = run_pass(loop).body.statements

        self.assertEqual(str(recovered.condition), '!done')
        self.assertEqual(call_names(recovered.body), ['a', 'b', 'c'])

    def test_guard_after_a_comment_is_removed_and_the_comment_stays(self):
        comment = HLILComment(GUARD_LINE)
        guard = HLILIf(make_flag('done'), HLILBlock([HLILBreak()]), None)
        loop = HLILWhile(HLILConst(1), HLILBlock([comment, guard, make_call('a'), make_call('b')]))

        [recovered] = run_pass(loop).body.statements

        self.assertEqual(recovered.body.statements[0], comment)
        self.assertEqual(call_names(recovered.body), ['a', 'b'])
        self.assertFalse([stmt for stmt in recovered.body.statements if isinstance(stmt, HLILIf)])


class TestTrailingContinueIsDropped(unittest.TestCase):
    def test_continue_ending_a_loop_with_a_real_condition(self):
        loop = HLILWhile(make_flag('c'), HLILBlock([make_call('work'), HLILContinue()]))

        [recovered] = run_pass(loop).body.statements

        self.assertEqual(call_names(recovered.body), ['work'])
        self.assertEqual(len(recovered.body.statements), 1)


if __name__ == '__main__':
    unittest.main()
