#!/usr/bin/env python3
"""Unit tests for HLIL switch recovery."""

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
    HLILCall,
    HLILComment,
    HLILConst,
    HLILExpression,
    HLILExprStmt,
    HLILIf,
    HLILStatement,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
    SwitchRecoveryPass,
    VariableKind,
)
from tests.shared.hlil_cfg_utils import statements_in_two_places


FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
THIRD_CASE_VALUE = 3
TERMINAL_CASE_VALUE = 150
DUPLICATE_CASE_VALUE = FIRST_CASE_VALUE
TERMINAL_MARKER_LINE = 'line(5657)'
TERMINAL_MARKER_CALL = 'party_set_leader'
CASE_MARKER_CALL_PREFIX = 'case_'
TEST_FUNCTION_NAME = 'test_switch_recovery'
EXPECTED_TOP_LEVEL_STATEMENT_COUNT = 1
EXPECTED_TERMINAL_CASE_COUNT = 1
NESTED_CASE_VALUE = 4
FOURTH_CASE_VALUE = 7
DEFAULT_BODY_VALUE = 99
AFTER_CHAIN_LINE = 999


def make_var() -> HLILVar:
    return HLILVar(HLILVariable('selector'))


def make_condition(op: BinaryOp, value: int) -> HLILBinaryOp:
    return HLILBinaryOp(op, make_var(), HLILConst(value))


def make_case_body(value: int) -> HLILBlock:
    return HLILBlock([HLILExprStmt(HLILCall(f'{CASE_MARKER_CALL_PREFIX}{value}', []))])


def make_terminal_body() -> HLILBlock:
    return HLILBlock([
        HLILComment(TERMINAL_MARKER_LINE),
        HLILExprStmt(HLILCall(TERMINAL_MARKER_CALL, [])),
    ])


def make_ne_check(value: int, next_if: HLILIf) -> HLILIf:
    return HLILIf(make_condition(BinaryOp.NE, value), HLILBlock([next_if]), make_case_body(value))


def line_comment(value: int) -> HLILComment:
    """The source-line comment of the test for value (its line number is the value, to tell them apart)"""
    return HLILComment(f'line({value})')


def make_marked_chain(*values: int) -> HLILIf:
    """An == chain on selector; each later test's line comment sits before it in the else arm, as converted"""
    chain = HLILIf(make_condition(BinaryOp.EQ, values[-1]), make_case_body(values[-1]), HLILBlock())
    for value, next_value in reversed(list(zip(values, values[1:]))):
        chain = HLILIf(make_condition(BinaryOp.EQ, value), make_case_body(value),
                       HLILBlock([line_comment(next_value), chain]))

    return chain


def collect_switch_case_values(switch_stmt: HLILSwitch) -> set:
    return {value.value
            for case in switch_stmt.cases if not case.is_default()
            for value in case.values}


def block_contains_call(block: HLILBlock, func_name: str) -> bool:
    for stmt in block.statements:
        if isinstance(stmt, HLILExprStmt) and isinstance(stmt.expr, HLILCall):
            if stmt.expr.func_name == func_name:
                return True
    return False


def recover_switches(*statements: HLILStatement) -> HighLevelILFunction:
    """A function of these statements, after SwitchRecoveryPass"""
    func = HighLevelILFunction(TEST_FUNCTION_NAME)
    for stmt in statements:
        func.body.add_statement(stmt)

    return SwitchRecoveryPass().run(func)


class TestSwitchConversion(unittest.TestCase):
    """Tests for if-chain to switch conversion."""

    def test_ne_chain_terminal_eq_becomes_final_switch_case(self):
        terminal_if = HLILIf(
            make_condition(BinaryOp.EQ, TERMINAL_CASE_VALUE),
            make_terminal_body(),
            HLILBlock(),
        )
        third_if = make_ne_check(THIRD_CASE_VALUE, terminal_if)
        second_if = make_ne_check(SECOND_CASE_VALUE, third_if)
        first_if = make_ne_check(FIRST_CASE_VALUE, second_if)

        func = recover_switches(first_if)

        self.assertEqual(len(func.body.statements), EXPECTED_TOP_LEVEL_STATEMENT_COUNT)
        switch_stmt = func.body.statements[0]
        self.assertIsInstance(switch_stmt, HLILSwitch)
        self.assertEqual(
            collect_switch_case_values(switch_stmt),
            {FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE, TERMINAL_CASE_VALUE},
        )

        terminal_cases = [
            case for case in switch_stmt.cases
            if not case.is_default()
            and any(v.value == TERMINAL_CASE_VALUE for v in case.values)
        ]
        self.assertEqual(len(terminal_cases), EXPECTED_TERMINAL_CASE_COUNT)
        self.assertTrue(block_contains_call(terminal_cases[0].body, TERMINAL_MARKER_CALL))

    def test_eq_chain_on_different_variables_is_not_converted(self):
        other_var = HLILVar(HLILVariable('other'))
        third_if = HLILIf(HLILBinaryOp(BinaryOp.EQ, other_var, HLILConst(THIRD_CASE_VALUE)), make_case_body(THIRD_CASE_VALUE), HLILBlock())
        second_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock([third_if]))
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), HLILBlock([second_if]))

        func = recover_switches(first_if)

        self.assertEqual(len(func.body.statements), EXPECTED_TOP_LEVEL_STATEMENT_COUNT)
        self.assertIsInstance(func.body.statements[0], HLILIf)

    def test_duplicate_case_value_prevents_switch_conversion(self):
        third_if = make_ne_check(DUPLICATE_CASE_VALUE, HLILIf(
            make_condition(BinaryOp.EQ, TERMINAL_CASE_VALUE),
            make_terminal_body(),
            HLILBlock(),
        ))
        second_if = make_ne_check(SECOND_CASE_VALUE, third_if)
        first_if = make_ne_check(FIRST_CASE_VALUE, second_if)

        func = recover_switches(first_if)

        self.assertEqual(len(func.body.statements), EXPECTED_TOP_LEVEL_STATEMENT_COUNT)
        self.assertIsInstance(func.body.statements[0], HLILIf)

    def test_nested_switch_non_const_case_value_is_not_silently_ignored(self):
        nested_switch = HLILSwitch(make_var(), [
            HLILSwitchCase([make_var()], make_case_body(NESTED_CASE_VALUE)),
        ])
        third_if = HLILIf(
            make_condition(BinaryOp.NE, THIRD_CASE_VALUE),
            HLILBlock([nested_switch]),
            make_case_body(THIRD_CASE_VALUE),
        )
        second_if = make_ne_check(SECOND_CASE_VALUE, third_if)
        first_if = make_ne_check(FIRST_CASE_VALUE, second_if)

        # A case label that is not a constant cannot be merged in, so the chain
        # must be left alone rather than converted without it
        func = recover_switches(first_if)

        self.assertIsInstance(func.body.statements[0], HLILIf)

    def test_a_link_with_no_case_body_gets_an_empty_case(self):
        """if (selector != k) { rest } with no else: the case for k does nothing"""
        rest = make_case_body(DEFAULT_BODY_VALUE)
        for value in (THIRD_CASE_VALUE, SECOND_CASE_VALUE, FIRST_CASE_VALUE):
            rest = HLILBlock([HLILIf(make_condition(BinaryOp.NE, value), rest, None)])

        [switch_stmt] = recover_switches(*rest.statements).body.statements

        self.assertIsInstance(switch_stmt, HLILSwitch)
        self.assertEqual([[v.value for v in case.values] for case in switch_stmt.cases[:-1]],
                         [[FIRST_CASE_VALUE], [SECOND_CASE_VALUE], [THIRD_CASE_VALUE]])
        self.assertEqual([case.body.statements for case in switch_stmt.cases[:-1]], [[], [], []])
        self.assertTrue(switch_stmt.cases[-1].is_default())


CHAIN_VALUES = (FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE)


def truth_test(cond: HLILExpression, op: BinaryOp) -> HLILBinaryOp:
    """cond under a truth test, `(cond) != 0` or `(cond) == 0`, as a link reaches HLIL on the stack translator's path"""
    return HLILBinaryOp(op, cond, HLILConst(0))


def make_chain(links: list[tuple[HLILExpression, int, bool]]) -> HLILIf:
    """Nested ifs, one per (condition, value, whether the case body is the then arm), the default body last"""
    continuation = make_case_body(DEFAULT_BODY_VALUE)
    for condition, value, in_then in reversed(links):
        body = make_case_body(value)
        link = HLILIf(condition, body, continuation) if in_then else HLILIf(condition, continuation, body)
        continuation = HLILBlock([link])

    return continuation.statements[0]


class TestTruthTestedChainLinks(unittest.TestCase):
    """Links under a truth test, as the stack translator keeps the LLIL's `(x == k) == 0`: each read as the test it
    makes, the case body the arm that runs when the test holds; the conditions themselves stay as written"""

    def assert_switch(self, chain: HLILIf, labels: list[list[int]]) -> HLILSwitch:
        """chain became one switch with these labels, each case's body the arm made for its first label"""
        [switch_stmt] = recover_switches(chain).body.statements

        self.assertIsInstance(switch_stmt, HLILSwitch)
        cases = [case for case in switch_stmt.cases if not case.is_default()]
        self.assertEqual([[value.value for value in case.values] for case in cases], labels)
        for case in cases:
            self.assertTrue(block_contains_call(case.body, f'{CASE_MARKER_CALL_PREFIX}{case.values[0].value}'))
        [default] = [case for case in switch_stmt.cases if case.is_default()]
        self.assertTrue(block_contains_call(default.body, f'{CASE_MARKER_CALL_PREFIX}{DEFAULT_BODY_VALUE}'))
        return switch_stmt

    def test_each_link_form(self):
        eq = lambda value: make_condition(BinaryOp.EQ, value)
        ne = lambda value: make_condition(BinaryOp.NE, value)
        forms = {           # form -> (its condition for a value, whether the case body is the then arm)
            '(x == k) != 0':        (lambda value: truth_test(eq(value), BinaryOp.NE), True),
            '(x == k) == 0':        (lambda value: truth_test(eq(value), BinaryOp.EQ), False),
            '(x != k) != 0':        (lambda value: truth_test(ne(value), BinaryOp.NE), False),
            '(x != k) == 0':        (lambda value: truth_test(ne(value), BinaryOp.EQ), True),
            '((x == k) == 0) == 0': (lambda value: truth_test(truth_test(eq(value), BinaryOp.EQ), BinaryOp.EQ), True),
        }
        for name, (condition, in_then) in forms.items():
            with self.subTest(form=name):
                chain = make_chain([(condition(value), value, in_then) for value in CHAIN_VALUES])

                self.assert_switch(chain, [[value] for value in CHAIN_VALUES])

    def test_a_chain_mixing_truth_tested_and_bare_links(self):
        chain = make_chain([
            (truth_test(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), BinaryOp.NE), FIRST_CASE_VALUE, True),
            (make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), SECOND_CASE_VALUE, True),
            (make_condition(BinaryOp.NE, THIRD_CASE_VALUE), THIRD_CASE_VALUE, False),
            (truth_test(make_condition(BinaryOp.NE, FOURTH_CASE_VALUE), BinaryOp.EQ), FOURTH_CASE_VALUE, True),
        ])

        self.assert_switch(chain, [[FIRST_CASE_VALUE], [SECOND_CASE_VALUE], [THIRD_CASE_VALUE], [FOURTH_CASE_VALUE]])

    def test_an_or_group_under_truth_tests_is_one_case(self):
        first, second = (make_condition(BinaryOp.EQ, value) for value in (FIRST_CASE_VALUE, SECOND_CASE_VALUE))
        groups = {
            'each test under its own (a funnel)':
                HLILBinaryOp(BinaryOp.OR_ELSE, truth_test(first, BinaryOp.NE), truth_test(second, BinaryOp.NE)),
            'one over the || (an eager ||)': truth_test(HLILBinaryOp(BinaryOp.OR, first, second), BinaryOp.NE),
        }
        for name, group in groups.items():
            with self.subTest(group=name):
                chain = make_chain([(group, FIRST_CASE_VALUE, True)] + [
                    (truth_test(make_condition(BinaryOp.EQ, value), BinaryOp.NE), value, True)
                    for value in (THIRD_CASE_VALUE, FOURTH_CASE_VALUE)])

                self.assert_switch(chain, [[FIRST_CASE_VALUE, SECOND_CASE_VALUE], [THIRD_CASE_VALUE],
                                           [FOURTH_CASE_VALUE]])

    def test_label_zero_stays_a_test_of_the_variable(self):
        values = (0, FIRST_CASE_VALUE, SECOND_CASE_VALUE)
        chain = make_chain([(truth_test(make_condition(BinaryOp.EQ, value), BinaryOp.NE), value, True)
                            for value in values])

        self.assert_switch(chain, [[value] for value in values])

    def test_a_register_scrutinee(self):
        register = HLILVariable(kind=VariableKind.REG, index=0)
        chain = make_chain([
            (truth_test(HLILBinaryOp(BinaryOp.EQ, HLILVar(register), HLILConst(value)), BinaryOp.NE), value, True)
            for value in CHAIN_VALUES])

        switch_stmt = self.assert_switch(chain, [[value] for value in CHAIN_VALUES])
        self.assertEqual(switch_stmt.scrutinee.var, register)

    def test_tests_that_are_no_link_stay_ifs(self):
        tests = {
            '(x < k) == 0':      lambda value: truth_test(make_condition(BinaryOp.LT, value), BinaryOp.EQ),
            '(x == k) == 1':     lambda value: HLILBinaryOp(BinaryOp.EQ, make_condition(BinaryOp.EQ, value),
                                                            HLILConst(1)),
            '(x == k) == 0.0':   lambda value: HLILBinaryOp(BinaryOp.EQ, make_condition(BinaryOp.EQ, value),
                                                            HLILConst(0.0)),
            'x != k || x != j':  lambda value: HLILBinaryOp(BinaryOp.OR, make_condition(BinaryOp.NE, value),
                                                            make_condition(BinaryOp.NE, NESTED_CASE_VALUE)),
        }
        for name, test in tests.items():
            with self.subTest(test=name):
                # Two links after it: read as a link, it would make the third case a switch needs
                condition = test(FIRST_CASE_VALUE)
                chain = make_chain([(condition, FIRST_CASE_VALUE, True)] + [
                    (make_condition(BinaryOp.EQ, value), value, True) for value in CHAIN_VALUES[1:]])

                [first] = recover_switches(chain).body.statements
                self.assertIsInstance(first, HLILIf)
                self.assertIs(first.condition, condition)


class TestChainKeepsTheCommentsBeforeItsLinks(unittest.TestCase):
    def test_comment_before_a_nested_test_starts_that_case(self):
        comment = HLILComment('line(55)')
        third = HLILIf(make_condition(BinaryOp.EQ, THIRD_CASE_VALUE), make_case_body(THIRD_CASE_VALUE), None)
        second = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE),
                        HLILBlock([comment, third]))
        first = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE),
                       HLILBlock([second]))

        [switch] = recover_switches(first).body.statements

        self.assertIsInstance(switch, HLILSwitch)
        self.assertEqual([case.values[0].value for case in switch.cases],
                         [FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE])
        self.assertIs(switch.cases[2].body.statements[0], comment)

    def test_a_chain_left_as_an_if_keeps_each_comment_once(self):
        func = recover_switches(make_marked_chain(FIRST_CASE_VALUE, SECOND_CASE_VALUE))
        [chain] = func.body.statements

        self.assertIsInstance(chain, HLILIf)
        self.assertEqual(statements_in_two_places(func), [])
        self.assertEqual(str(chain.false_block.statements[0]), str(line_comment(SECOND_CASE_VALUE)))

    def test_each_test_line_lands_in_its_case_once(self):
        values = (FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE, FOURTH_CASE_VALUE)
        func = recover_switches(make_marked_chain(*values))
        [switch_stmt] = func.body.statements

        self.assertIsInstance(switch_stmt, HLILSwitch)
        self.assertEqual(statements_in_two_places(func), [])
        first, *later = values
        expected = [[str(stmt) for stmt in make_case_body(first).statements]]
        expected += [[str(line_comment(value)), *(str(stmt) for stmt in make_case_body(value).statements)]
                     for value in later]
        self.assertEqual([[str(stmt) for stmt in case.body.statements] for case in switch_stmt.cases], expected)

    def test_a_comment_after_the_rest_of_the_chain_keeps_it_an_if(self):
        """The rest is still an if (2 more tests) or already a switch (3): either way the comment stays after it"""
        for values in ((FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE),
                       (FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE, FOURTH_CASE_VALUE)):
            with self.subTest(tests=len(values)):
                first, second, *_ = values
                after = line_comment(AFTER_CHAIN_LINE)
                else_arm = HLILBlock([line_comment(second), make_marked_chain(*values[1:]), after])
                func = recover_switches(HLILIf(make_condition(BinaryOp.EQ, first), make_case_body(first), else_arm))
                [chain] = func.body.statements

                self.assertIsInstance(chain, HLILIf)
                self.assertEqual(statements_in_two_places(func), [])
                self.assertEqual(str(chain.false_block.statements[0]), str(line_comment(second)))
                self.assertIs(chain.false_block.statements[-1], after)


if __name__ == '__main__':
    unittest.main()
