#!/usr/bin/env python3
'''Unit tests for HLIL control-flow optimization.'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.hlil import (
    BinaryOp,
    ControlFlowOptimizationPass,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILComment,
    HLILConst,
    HLILExprStmt,
    HLILIf,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
)


FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
THIRD_CASE_VALUE = 3
TERMINAL_CASE_VALUE = 150
DUPLICATE_CASE_VALUE = FIRST_CASE_VALUE
TERMINAL_MARKER_LINE = 'line(5657)'
TERMINAL_MARKER_CALL = 'party_set_leader'
CASE_MARKER_CALL_PREFIX = 'case_'
TEST_FUNCTION_NAME = 'test_switch_tail'
EXPECTED_TOP_LEVEL_STATEMENT_COUNT = 1
EXPECTED_TERMINAL_CASE_COUNT = 1
NESTED_CASE_VALUE = 4
FOURTH_CASE_VALUE = 7
DEFAULT_BODY_VALUE = 99


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


class TestControlFlowOptimizationSwitchConversion(unittest.TestCase):
    '''Tests for if-chain to switch conversion.'''

    def run_pass(self, first_if: HLILIf) -> HighLevelILFunction:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(first_if)
        return ControlFlowOptimizationPass().run(func)

    def test_ne_chain_terminal_eq_becomes_final_switch_case(self):
        terminal_if = HLILIf(
            make_condition(BinaryOp.EQ, TERMINAL_CASE_VALUE),
            make_terminal_body(),
            HLILBlock(),
        )
        third_if = make_ne_check(THIRD_CASE_VALUE, terminal_if)
        second_if = make_ne_check(SECOND_CASE_VALUE, third_if)
        first_if = make_ne_check(FIRST_CASE_VALUE, second_if)

        func = self.run_pass(first_if)

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

    def test_eq_chain_becomes_switch(self):
        third_if = HLILIf(make_condition(BinaryOp.EQ, THIRD_CASE_VALUE), make_case_body(THIRD_CASE_VALUE), HLILBlock())
        second_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock([third_if]))
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), HLILBlock([second_if]))

        func = self.run_pass(first_if)

        self.assertEqual(len(func.body.statements), EXPECTED_TOP_LEVEL_STATEMENT_COUNT)
        switch_stmt = func.body.statements[0]
        self.assertIsInstance(switch_stmt, HLILSwitch)
        self.assertEqual(
            collect_switch_case_values(switch_stmt),
            {FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE},
        )

    def test_short_eq_chain_is_not_converted_to_switch(self):
        second_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock())
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), HLILBlock([second_if]))

        func = self.run_pass(first_if)

        self.assertEqual(len(func.body.statements), EXPECTED_TOP_LEVEL_STATEMENT_COUNT)
        self.assertIsInstance(func.body.statements[0], HLILIf)

    def test_eq_chain_on_different_variables_is_not_converted(self):
        other_var = HLILVar(HLILVariable('other'))
        third_if = HLILIf(HLILBinaryOp(BinaryOp.EQ, other_var, HLILConst(THIRD_CASE_VALUE)), make_case_body(THIRD_CASE_VALUE), HLILBlock())
        second_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock([third_if]))
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), HLILBlock([second_if]))

        func = self.run_pass(first_if)

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

        func = self.run_pass(first_if)

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
        func = self.run_pass(first_if)

        self.assertIsInstance(func.body.statements[0], HLILIf)

    def test_alternating_ne_eq_chain_becomes_one_switch(self):
        # NE, NE, EQ, NE - neither of the two former converters could span this
        fourth_if = HLILIf(
            make_condition(BinaryOp.NE, FOURTH_CASE_VALUE),
            make_case_body(DEFAULT_BODY_VALUE),
            make_case_body(FOURTH_CASE_VALUE),
        )
        third_if = HLILIf(
            make_condition(BinaryOp.EQ, THIRD_CASE_VALUE),
            make_case_body(THIRD_CASE_VALUE),
            HLILBlock([fourth_if]),
        )
        second_if = make_ne_check(SECOND_CASE_VALUE, third_if)
        first_if = make_ne_check(FIRST_CASE_VALUE, second_if)

        func = self.run_pass(first_if)
        switch_stmt = func.body.statements[0]

        self.assertIsInstance(switch_stmt, HLILSwitch)
        self.assertEqual(
            collect_switch_case_values(switch_stmt),
            {FIRST_CASE_VALUE, SECOND_CASE_VALUE, THIRD_CASE_VALUE, FOURTH_CASE_VALUE},
        )

    def test_or_grouped_equalities_become_one_case_with_several_labels(self):
        grouped = HLILBinaryOp(
            BinaryOp.OR,
            make_condition(BinaryOp.EQ, FIRST_CASE_VALUE),
            make_condition(BinaryOp.EQ, SECOND_CASE_VALUE),
        )
        fourth_if = HLILIf(
            make_condition(BinaryOp.EQ, FOURTH_CASE_VALUE),
            make_case_body(FOURTH_CASE_VALUE),
            make_case_body(DEFAULT_BODY_VALUE),
        )
        third_if = HLILIf(
            make_condition(BinaryOp.EQ, THIRD_CASE_VALUE),
            make_case_body(THIRD_CASE_VALUE),
            HLILBlock([fourth_if]),
        )
        grouped_if = HLILIf(grouped, make_case_body(FIRST_CASE_VALUE), HLILBlock([third_if]))

        func = self.run_pass(grouped_if)
        switch_stmt = func.body.statements[0]

        self.assertIsInstance(switch_stmt, HLILSwitch)

        shared = [case for case in switch_stmt.cases
                  if not case.is_default() and len(case.values) > 1]

        self.assertEqual(len(shared), 1)
        self.assertEqual({v.value for v in shared[0].values},
                         {FIRST_CASE_VALUE, SECOND_CASE_VALUE})


if __name__ == '__main__':
    unittest.main()
