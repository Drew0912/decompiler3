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


if __name__ == '__main__':
    unittest.main()
