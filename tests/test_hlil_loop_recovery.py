#!/usr/bin/env python3
'''Unit tests for HLIL loop recovery.'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

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


EXIT_THRESHOLD = 0
RETURN_VALUE = 1
GUARD_LINE = 'line(782)'
BODY_CALL = 'btl_chr_list_next'
SWITCH_CASE_VALUE = 3


def make_var() -> HLILVar:
    return HLILVar(HLILVariable('remaining'))


def make_exit_condition() -> HLILBinaryOp:
    '''remaining <= 0 - true when the loop should stop'''
    return HLILBinaryOp(BinaryOp.LE, make_var(), HLILConst(EXIT_THRESHOLD))


def make_body_statement() -> HLILExprStmt:
    return HLILExprStmt(HLILCall(BODY_CALL, []))


def make_guard(exit_stmt) -> HLILIf:
    '''if (remaining <= 0) { <exit_stmt> }'''
    return HLILIf(make_exit_condition(), HLILBlock([exit_stmt]), None)


def run_pass(loop: HLILWhile) -> HighLevelILFunction:
    func = HighLevelILFunction('test_loop')
    func.add_statement(loop)
    return LoopRecoveryPass().run(func)


class TestLoopRecoveryReturnGuard(unittest.TestCase):
    '''while (1) { if (c) return x; body } -> while (!c) { body } return x'''

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


class TestLoopRecoveryBreakGuard(unittest.TestCase):
    '''The pre-existing break-based rotations must keep working'''

    def test_leading_break_guard_becomes_loop_condition(self):
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([guard, make_body_statement()]))

        func = run_pass(loop)

        self.assertEqual(len(func.body.statements), 1)
        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)
        self.assertEqual(recovered.condition.op, BinaryOp.GT)
        self.assertEqual(len(recovered.body.statements), 1)

    def test_loop_with_real_condition_is_left_alone(self):
        loop = HLILWhile(make_exit_condition(), HLILBlock([make_body_statement()]))

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)
        self.assertEqual(recovered.condition.op, BinaryOp.LE)


class TestLoopRecoveryDoWhileRotation(unittest.TestCase):
    '''while (1) { body; if (c) break; } -> do { body } while (!c) - the one recovery shape
    with no existing test coverage before this step (do-whiles are latent in the real corpus).'''

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


class TestLoopRecoveryContinueGuard(unittest.TestCase):
    '''continue means something different in while(1) (always jumps to top, never exits) than
    in do-while (jumps to the exit test, can exit) - so the trailing-exit rotation must refuse
    when the body has a continue that targets this loop.'''

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
            HLILSwitchCase([HLILConst(SWITCH_CASE_VALUE)], HLILBlock([HLILContinue(label = loop_label)])),
        ])
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([inner_switch, make_body_statement(), guard]), label = loop_label)

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILWhile)


class TestLoopRecoveryDoWhileLabel(unittest.TestCase):
    '''A labelled while(1) loop must keep its label through the do-while rewrite - HLILDoWhile
    previously had no way to carry one at all, leaving any continue/break naming it dangling.'''

    def test_labelled_loop_keeps_its_label_after_do_while_rotation(self):
        loop_label = 'loop_1'
        guard = make_guard(HLILBreak())
        loop = HLILWhile(HLILConst(1), HLILBlock([make_body_statement(), guard]), label = loop_label)

        func = run_pass(loop)

        recovered = func.body.statements[0]
        self.assertIsInstance(recovered, HLILDoWhile)
        self.assertEqual(recovered.label, loop_label)


if __name__ == '__main__':
    unittest.main()
