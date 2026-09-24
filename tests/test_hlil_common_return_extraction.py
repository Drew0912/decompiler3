#!/usr/bin/env python3
'''Unit tests for CommonReturnExtractionPass: a return shared by every arm is only hoisted when no
path can leave the construct without reaching one of those returns, and constants compare by the
shared constant rule (int and float distinct, NaN equal to itself).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.core import constant_values_equal
from ir.hlil import (
    CommonReturnExtractionPass,
    HighLevelILFunction,
    HLILBlock,
    HLILBreak,
    HLILCall,
    HLILConst,
    HLILDoWhile,
    HLILExprStmt,
    HLILIf,
    HLILReturn,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
    HLILWhile,
    contains_bare_break,
)

FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
RETURN_VALUE = 5
OTHER_RETURN_VALUE = 7
INT_RETURN_VALUE = 1
FLOAT_RETURN_VALUE = 1.0
NAN_RETURN_VALUE = float('nan')
LOOP_CONDITION = 1
LOOP_LABEL = 'outer'


def make_selector() -> HLILVar:
    return HLILVar(HLILVariable('selector'))


def make_call(name: str) -> HLILExprStmt:
    return HLILExprStmt(HLILCall(name, []))


def make_return(value = RETURN_VALUE) -> HLILReturn:
    return HLILReturn(HLILConst(value))


def make_case(value: int, *statements) -> HLILSwitchCase:
    return HLILSwitchCase([HLILConst(value)], HLILBlock(list(statements)))


def make_default(*statements) -> HLILSwitchCase:
    return HLILSwitchCase(None, HLILBlock(list(statements)))


def make_switch(*cases) -> HLILSwitch:
    return HLILSwitch(make_selector(), list(cases))


def make_if_else(true_value, false_value) -> HLILIf:
    return HLILIf(make_selector(), HLILBlock([make_return(true_value)]), HLILBlock([make_return(false_value)]))


def run_pass(*statements) -> HighLevelILFunction:
    func = HighLevelILFunction('f')
    for stmt in statements:
        func.add_statement(stmt)

    CommonReturnExtractionPass().run(func)
    return func


def ends_in_return(block: HLILBlock) -> bool:
    return bool(block.statements) and isinstance(block.statements[-1], HLILReturn)


class TestSwitchCommonReturn(unittest.TestCase):
    def test_switch_without_default_is_not_hoisted(self):
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, make_call('a'), make_return()),
            make_case(SECOND_CASE_VALUE, make_call('b'), make_return()),
        )
        after = make_call('after')

        func = run_pass(switch_stmt, after)

        self.assertEqual(func.body.statements, [switch_stmt, after])
        self.assertTrue(all(ends_in_return(case.body) for case in switch_stmt.cases))

    def test_switch_with_default_is_hoisted(self):
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, make_call('a'), make_return()),
            make_case(SECOND_CASE_VALUE, make_call('b'), make_return()),
            make_default(make_call('c'), make_return()),
        )

        func = run_pass(switch_stmt)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIs(func.body.statements[0], switch_stmt)
        self.assertIsInstance(func.body.statements[1], HLILReturn)
        self.assertEqual(func.body.statements[1].value.value, RETURN_VALUE)
        self.assertFalse(any(ends_in_return(case.body) for case in switch_stmt.cases))

    def test_default_with_different_return_is_not_hoisted(self):
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, make_return()),
            make_case(SECOND_CASE_VALUE, make_return()),
            make_default(make_return(OTHER_RETURN_VALUE)),
        )

        func = run_pass(switch_stmt)

        self.assertEqual(func.body.statements, [switch_stmt])
        self.assertTrue(all(ends_in_return(case.body) for case in switch_stmt.cases))

    def test_default_without_return_is_not_hoisted(self):
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, make_return()),
            make_case(SECOND_CASE_VALUE, make_return()),
            make_default(make_call('c')),
        )

        func = run_pass(switch_stmt)

        self.assertEqual(func.body.statements, [switch_stmt])
        self.assertTrue(ends_in_return(switch_stmt.cases[0].body))

    def test_case_with_bare_break_is_not_hoisted(self):
        early_exit = HLILIf(make_selector(), HLILBlock([HLILBreak()]), None)
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, early_exit, make_return()),
            make_case(SECOND_CASE_VALUE, make_return()),
            make_default(make_return()),
        )
        after = make_call('after')

        func = run_pass(switch_stmt, after)

        self.assertEqual(func.body.statements, [switch_stmt, after])
        self.assertTrue(all(ends_in_return(case.body) for case in switch_stmt.cases))

    def test_break_owned_by_nested_loop_is_still_hoisted(self):
        inner_loop = HLILWhile(HLILConst(LOOP_CONDITION), HLILBlock([HLILBreak()]))
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, inner_loop, make_return()),
            make_case(SECOND_CASE_VALUE, make_return()),
            make_default(make_return()),
        )

        func = run_pass(switch_stmt)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[1], HLILReturn)


class TestReturnConstantEquality(unittest.TestCase):
    def test_equal_if_returns_are_hoisted(self):
        if_stmt = make_if_else(RETURN_VALUE, RETURN_VALUE)

        func = run_pass(if_stmt)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[1], HLILReturn)

    def test_if_int_and_float_returns_are_not_merged(self):
        if_stmt = make_if_else(INT_RETURN_VALUE, FLOAT_RETURN_VALUE)

        func = run_pass(if_stmt)

        self.assertEqual(func.body.statements, [if_stmt])
        self.assertTrue(ends_in_return(if_stmt.true_block))
        self.assertTrue(ends_in_return(if_stmt.false_block))

    def test_switch_int_and_float_returns_are_not_merged(self):
        switch_stmt = make_switch(
            make_case(FIRST_CASE_VALUE, make_return(INT_RETURN_VALUE)),
            make_case(SECOND_CASE_VALUE, make_return(INT_RETURN_VALUE)),
            make_default(make_return(FLOAT_RETURN_VALUE)),
        )

        func = run_pass(switch_stmt)

        self.assertEqual(func.body.statements, [switch_stmt])
        self.assertTrue(all(ends_in_return(case.body) for case in switch_stmt.cases))

    def test_nan_returns_are_merged(self):
        if_stmt = make_if_else(NAN_RETURN_VALUE, NAN_RETURN_VALUE)

        func = run_pass(if_stmt)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[1], HLILReturn)

    def test_if_without_else_is_not_hoisted(self):
        if_stmt = HLILIf(make_selector(), HLILBlock([make_return()]), None)
        after = make_return()

        func = run_pass(if_stmt, after)

        self.assertEqual(func.body.statements, [if_stmt, after])
        self.assertTrue(ends_in_return(if_stmt.true_block))


class TestConstantValuesEqual(unittest.TestCase):
    def test_same_ints_are_equal(self):
        self.assertTrue(constant_values_equal(RETURN_VALUE, RETURN_VALUE))

    def test_int_and_float_are_distinct(self):
        self.assertFalse(constant_values_equal(INT_RETURN_VALUE, FLOAT_RETURN_VALUE))

    def test_bool_and_int_are_distinct(self):
        self.assertFalse(constant_values_equal(True, INT_RETURN_VALUE))

    def test_nan_equals_itself(self):
        self.assertTrue(constant_values_equal(NAN_RETURN_VALUE, float('nan')))

    def test_floats_compare_by_value(self):
        self.assertTrue(constant_values_equal(FLOAT_RETURN_VALUE, float(INT_RETURN_VALUE)))
        self.assertFalse(constant_values_equal(FLOAT_RETURN_VALUE, NAN_RETURN_VALUE))

    def test_strings_compare_by_value(self):
        self.assertTrue(constant_values_equal('abc', 'abc'))
        self.assertFalse(constant_values_equal('abc', 'abd'))


class TestContainsBareBreak(unittest.TestCase):
    def test_empty_or_missing_block_has_none(self):
        self.assertFalse(contains_bare_break(None))
        self.assertFalse(contains_bare_break(HLILBlock()))

    def test_direct_bare_break(self):
        self.assertTrue(contains_bare_break(HLILBlock([make_call('a'), HLILBreak()])))

    def test_bare_break_in_else_arm(self):
        branch = HLILIf(make_selector(), HLILBlock([make_call('a')]), HLILBlock([HLILBreak()]))
        self.assertTrue(contains_bare_break(HLILBlock([branch])))

    def test_labelled_break_does_not_count(self):
        self.assertFalse(contains_bare_break(HLILBlock([HLILBreak(label = LOOP_LABEL)])))

    def test_loops_and_switches_own_their_bare_breaks(self):
        owners = [
            HLILWhile(HLILConst(LOOP_CONDITION), HLILBlock([HLILBreak()])),
            HLILDoWhile(HLILConst(LOOP_CONDITION), HLILBlock([HLILBreak()])),
            make_switch(make_case(FIRST_CASE_VALUE, HLILBreak())),
        ]
        for owner in owners:
            with self.subTest(owner = type(owner).__name__):
                self.assertFalse(contains_bare_break(HLILBlock([owner])))

    def test_bare_break_in_if_inside_loop_belongs_to_loop(self):
        branch = HLILIf(make_selector(), HLILBlock([HLILBreak()]), None)
        loop = HLILWhile(HLILConst(LOOP_CONDITION), HLILBlock([branch]))
        self.assertFalse(contains_bare_break(HLILBlock([loop])))


if __name__ == '__main__':
    unittest.main()
