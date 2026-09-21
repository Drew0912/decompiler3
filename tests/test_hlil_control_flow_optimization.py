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
    HLILAssign,
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
    VariableKind,
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


FLAG_COMPARE_LHS = 10
FLAG_COMPARE_RHS = 20
FIRST_CHECK_CALL = 'on_first_check'
SECOND_CHECK_CALL = 'on_second_check'


def make_flag_var() -> HLILVar:
    return HLILVar(HLILVariable('flag'))


def make_flag_assign() -> HLILAssign:
    condition = HLILBinaryOp(BinaryOp.EQ, HLILConst(FLAG_COMPARE_LHS), HLILConst(FLAG_COMPARE_RHS))
    return HLILAssign(make_flag_var(), condition)


def make_flag_check(call_name: str) -> HLILIf:
    condition = HLILBinaryOp(BinaryOp.NE, make_flag_var(), HLILConst(0))
    return HLILIf(condition, HLILBlock([HLILExprStmt(HLILCall(call_name, []))]), HLILBlock())


class TestBooleanTempInlining(unittest.TestCase):
    '''Tests for the [assign, if] -> [if(bool_expr)] boolean-temp inlining transform.'''

    def run_pass(self, statements: list) -> HighLevelILFunction:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        for stmt in statements:
            func.add_statement(stmt)
        return ControlFlowOptimizationPass().run(func)

    def test_assignment_inlined_and_removed_when_var_is_not_read_again(self):
        func = self.run_pass([make_flag_assign(), make_flag_check(FIRST_CHECK_CALL)])

        # Only the inlined if remains - the temp assignment was safe to delete
        self.assertEqual(len(func.body.statements), 1)
        self.assertIsInstance(func.body.statements[0], HLILIf)

    def test_assignment_survives_when_var_is_read_by_a_later_statement(self):
        assign_stmt = make_flag_assign()
        first_if = make_flag_check(FIRST_CHECK_CALL)
        second_if = make_flag_check(SECOND_CHECK_CALL)

        func = self.run_pass([assign_stmt, first_if, second_if])

        # second_if reads the same flag var again - deleting the assignment would leave
        # it undefined there, so the inline-and-delete transform must not fire at all
        self.assertEqual(len(func.body.statements), 3)
        self.assertIsInstance(func.body.statements[0], HLILAssign)
        self.assertIsInstance(func.body.statements[1], HLILIf)
        self.assertIsInstance(func.body.statements[2], HLILIf)


RELOAD_CALL_NAME = 'reload_discriminant'
SOURCE_REG_NAME = 'source_reg'


class TestRedundantElseAssignSideEffects(unittest.TestCase):
    '''Tests for _remove_redundant_else_assign not discarding side effects.'''

    def run_pass(self, first_if: HLILIf) -> HighLevelILFunction:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(first_if)
        return ControlFlowOptimizationPass().run(func)

    def build_switch_case_if(self, source_expr) -> HLILIf:
        # if (selector == FIRST) { case_1 } else { selector = source_expr; if (selector == SECOND) { case_2 } }
        inner_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock())
        reload_assign = HLILAssign(make_var(), source_expr)
        false_block = HLILBlock([reload_assign, inner_if])
        return HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), false_block)

    def test_call_reload_is_not_removed_even_when_result_looks_redundant(self):
        first_if = self.build_switch_case_if(HLILCall(RELOAD_CALL_NAME, []))

        func = self.run_pass(first_if)

        else_block = func.body.statements[0].false_block
        # The reassignment must survive - deleting it would drop the call's side effect
        self.assertEqual(len(else_block.statements), 2)
        reload_stmt = else_block.statements[0]
        self.assertIsInstance(reload_stmt, HLILAssign)
        self.assertIsInstance(reload_stmt.src, HLILCall)
        self.assertEqual(reload_stmt.src.func_name, RELOAD_CALL_NAME)

    def test_pure_reload_is_still_removed_as_redundant(self):
        first_if = self.build_switch_case_if(HLILVar(HLILVariable(SOURCE_REG_NAME)))

        func = self.run_pass(first_if)

        else_block = func.body.statements[0].false_block
        # The reassignment is gone - only the inner if remains
        self.assertEqual(len(else_block.statements), 1)
        self.assertIsInstance(else_block.statements[0], HLILIf)


class TestBooleanTempInliningPreservesGlobals(unittest.TestCase):
    '''A GLOBAL-kind boolean temp must never be deleted by inlining - unlike a local or
    register temp, the write itself is observable shared state regardless of whether
    anything in this function reads it again.'''

    def test_global_assignment_survives_even_with_no_other_reads(self):
        global_var = HLILVariable(None, kind = VariableKind.GLOBAL, index = 5)
        condition = HLILBinaryOp(BinaryOp.EQ, HLILConst(FLAG_COMPARE_LHS), HLILConst(FLAG_COMPARE_RHS))
        assign_stmt = HLILAssign(HLILVar(global_var), condition)
        if_stmt = HLILIf(
            HLILBinaryOp(BinaryOp.NE, HLILVar(global_var), HLILConst(0)),
            HLILBlock([HLILExprStmt(HLILCall(FIRST_CHECK_CALL, []))]),
            HLILBlock(),
        )

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(assign_stmt)
        func.add_statement(if_stmt)
        func = ControlFlowOptimizationPass().run(func)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[0], HLILAssign)


class TestRedundantElseAssignVariableIdentity(unittest.TestCase):
    '''_remove_redundant_else_assign must compare full variable identity, not just .name -
    REG-kind variables commonly share name=None, distinguished only by index.'''

    def test_distinct_reg_variables_are_not_conflated(self):
        r1 = HLILVariable(None, kind = VariableKind.REG, index = 1)
        r2 = HLILVariable(None, kind = VariableKind.REG, index = 2)
        r3 = HLILVariable(None, kind = VariableKind.REG, index = 3)

        inner_if = HLILIf(HLILBinaryOp(BinaryOp.EQ, HLILVar(r3), HLILConst(SECOND_CASE_VALUE)),
                           make_case_body(SECOND_CASE_VALUE), HLILBlock())
        unrelated_assign = HLILAssign(HLILVar(r2), HLILConst(99))
        false_block = HLILBlock([unrelated_assign, inner_if])
        first_if = HLILIf(HLILBinaryOp(BinaryOp.EQ, HLILVar(r1), HLILConst(FIRST_CASE_VALUE)),
                           make_case_body(FIRST_CASE_VALUE), false_block)

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        else_stmts = func.body.statements[0].false_block.statements
        # r2's assignment is unrelated to r1/r3 - must survive despite sharing name=None
        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)


class TestBooleanTempInliningSwitchCaseLabelIsARead(unittest.TestCase):
    '''A boolean temp referenced as a switch CASE LABEL (not just in a case body) must
    count as a read - the walker has to scan case.values, not just case.body.'''

    def test_var_read_as_a_switch_case_label_blocks_deletion(self):
        assign_stmt = make_flag_assign()
        if_stmt = make_flag_check(FIRST_CHECK_CALL)
        switch_stmt = HLILSwitch(
            HLILVar(HLILVariable('x')),
            [HLILSwitchCase([make_flag_var()], HLILBlock([HLILExprStmt(HLILCall('case_body_call', []))]))],
        )

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(assign_stmt)
        func.add_statement(if_stmt)
        func.add_statement(switch_stmt)
        func = ControlFlowOptimizationPass().run(func)

        # The switch case label reads the same flag var - assignment must survive
        self.assertEqual(len(func.body.statements), 3)
        self.assertIsInstance(func.body.statements[0], HLILAssign)


class TestBooleanTempInliningSwitchWithoutDefaultDoesNotHideAReadingPath(unittest.TestCase):
    '''A switch with no default case has an implicit "nothing matched" path where var keeps
    its original value - a read reachable after such a switch must still count as a read.'''

    def test_read_after_switch_with_no_default_blocks_deletion(self):
        assign_stmt = make_flag_assign()
        switch_stmt = HLILSwitch(HLILVar(HLILVariable('x')), [
            HLILSwitchCase([HLILConst(1)], HLILBlock([HLILAssign(make_flag_var(), HLILConst(0))])),
        ])
        use_after = HLILExprStmt(HLILCall('use', [make_flag_var()]))
        if_stmt = HLILIf(
            HLILBinaryOp(BinaryOp.NE, make_flag_var(), HLILConst(0)),
            HLILBlock([switch_stmt, use_after]),
            HLILBlock(),
        )

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(assign_stmt)
        func.add_statement(if_stmt)
        func = ControlFlowOptimizationPass().run(func)

        # When x != 1, the switch matches nothing and flag keeps its original value, which
        # use_after then reads - the assignment must survive
        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[0], HLILAssign)


class TestBooleanTempInliningCaseLabelInsideTheIfItself(unittest.TestCase):
    '''A switch case LABEL that reads the boolean temp, nested inside the very if being
    considered for inlining, must be seen by _can_read_original_value directly - it is not
    covered by _var_read_elsewhere, which deliberately excludes next_stmt entirely (its
    branches are meant to already be fully checked by _can_read_original_value first).'''

    def test_case_label_read_inside_the_if_blocks_deletion(self):
        assign_stmt = make_flag_assign()
        switch_stmt = HLILSwitch(
            HLILVar(HLILVariable('x')),
            [HLILSwitchCase([make_flag_var()], HLILBlock([HLILExprStmt(HLILCall('case_body', []))]))],
        )
        if_stmt = HLILIf(
            HLILBinaryOp(BinaryOp.NE, make_flag_var(), HLILConst(0)),
            HLILBlock([switch_stmt]),
            HLILBlock(),
        )

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(assign_stmt)
        func.add_statement(if_stmt)
        func = ControlFlowOptimizationPass().run(func)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[0], HLILAssign)


if __name__ == '__main__':
    unittest.main()
