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
    HLILBreak,
    HLILCall,
    HLILComment,
    HLILConst,
    HLILContinue,
    HLILDoWhile,
    HLILExprStmt,
    HLILIf,
    HLILReturn,
    HLILStatement,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
    HLILWhile,
    VariableKind,
)
from ir.hlil.passes.pass_control_flow_optimization import ExitKind


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

    def run_pass(self, *statements: HLILStatement) -> HighLevelILFunction:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        for stmt in statements:
            func.add_statement(stmt)
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
        # A genuine reaching load before the whole chain - required since the fix for the
        # confirmed soundness gap (selector starting unrelated to the reload's source, see
        # test_reload_without_a_reaching_assignment_is_not_removed below): the reload is only
        # provably redundant once something upstream actually proves selector already held
        # source's value.
        source_var = HLILVariable(SOURCE_REG_NAME)
        reaching_load = HLILAssign(make_var(), HLILVar(source_var))
        first_if = self.build_switch_case_if(HLILVar(source_var))

        func = self.run_pass(reaching_load, first_if)

        else_block = func.body.statements[1].false_block
        # The reassignment is gone - only the inner if remains
        self.assertEqual(len(else_block.statements), 1)
        self.assertIsInstance(else_block.statements[0], HLILIf)

    def test_reload_without_a_reaching_assignment_is_not_removed(self):
        # The confirmed soundness gap this fix closes: selector starts at a value unrelated
        # to the reload's source (never proven to already equal it), so deleting the reload
        # would silently change which case body a later match against SECOND_CASE_VALUE runs.
        unrelated_init = HLILAssign(make_var(), HLILConst(999))
        first_if = self.build_switch_case_if(HLILConst(SECOND_CASE_VALUE))

        func = self.run_pass(unrelated_init, first_if)

        else_block = func.body.statements[1].false_block
        self.assertEqual(len(else_block.statements), 2)
        self.assertIsInstance(else_block.statements[0], HLILAssign)


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
    '''Originally: _remove_redundant_else_assign must compare full variable identity, not just
    .name, since REG-kind variables commonly share name=None, distinguished only by index. Now
    moot as a live concern for this function specifically - a REG-kind outer_var is rejected
    outright before any name/identity comparison runs (a register still literally REG-kind at
    this layer means SSA never resolved it to a concrete value, never a safe reload source
    either way) - kept as a regression guard on that rejection, not on identity comparison.'''

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


class TestRedundantElseAssignRejectsSelfReference(unittest.TestCase):
    '''x = x textually matches any earlier x = x, but re-evaluating a self-referential source
    does not prove the same value was ever produced twice - must always refuse, independent
    of any reaching definition.'''

    def test_self_referential_source_is_not_removed(self):
        inner_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock())
        reload_assign = HLILAssign(make_var(), make_var())  # selector = selector
        false_block = HLILBlock([reload_assign, inner_if])
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), false_block)

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        else_stmts = func.body.statements[0].false_block.statements
        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)


class TestRedundantElseAssignRejectsUnstableSourceKinds(unittest.TestCase):
    '''A global can change across a call while still rendering under the identical name at
    this layer; a variable still REG-kind here means SSA never resolved it to a concrete
    value. Neither is a provably-stable reload source, regardless of any reaching assignment
    that would otherwise look sufficient.'''

    def build_with_source(self, source_var: HLILVariable) -> tuple:
        reaching_load = HLILAssign(make_var(), HLILVar(source_var))
        inner_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock())
        reload_assign = HLILAssign(make_var(), HLILVar(source_var))
        false_block = HLILBlock([reload_assign, inner_if])
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), false_block)
        return reaching_load, first_if

    def run_and_get_else_stmts(self, reaching_load, first_if) -> list:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(reaching_load)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)
        return func.body.statements[1].false_block.statements

    def test_global_source_is_not_removed_even_with_a_reaching_assignment(self):
        global_var = HLILVariable(None, kind = VariableKind.GLOBAL, index = 7)
        reaching_load, first_if = self.build_with_source(global_var)

        else_stmts = self.run_and_get_else_stmts(reaching_load, first_if)

        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)

    def test_register_source_is_not_removed_even_with_a_reaching_assignment(self):
        reg_var = HLILVariable(None, kind = VariableKind.REG, index = 3)
        reaching_load, first_if = self.build_with_source(reg_var)

        else_stmts = self.run_and_get_else_stmts(reaching_load, first_if)

        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)


class TestRedundantElseAssignRequiresConstantConditions(unittest.TestCase):
    '''The pattern only ever means something as a literal switch-style discriminant test - a
    call embedded in either condition's RHS (whose side effect could change the reload's
    source between the reaching assignment and the reload itself) must not be silently
    assumed away.'''

    def test_outer_condition_with_non_constant_rhs_is_not_removed(self):
        reaching_load = HLILAssign(make_var(), HLILConst(SECOND_CASE_VALUE))
        inner_if = HLILIf(make_condition(BinaryOp.EQ, SECOND_CASE_VALUE), make_case_body(SECOND_CASE_VALUE), HLILBlock())
        reload_assign = HLILAssign(make_var(), HLILConst(SECOND_CASE_VALUE))
        false_block = HLILBlock([reload_assign, inner_if])
        outer_cond = HLILBinaryOp(BinaryOp.EQ, make_var(), HLILCall('mutate_and_return', []))
        first_if = HLILIf(outer_cond, make_case_body(FIRST_CASE_VALUE), false_block)

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(reaching_load)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        else_stmts = func.body.statements[1].false_block.statements
        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)

    def test_inner_condition_with_non_constant_rhs_is_not_removed(self):
        reaching_load = HLILAssign(make_var(), HLILConst(SECOND_CASE_VALUE))
        inner_cond = HLILBinaryOp(BinaryOp.EQ, make_var(), HLILCall('mutate_and_return', []))
        inner_if = HLILIf(inner_cond, make_case_body(SECOND_CASE_VALUE), HLILBlock())
        reload_assign = HLILAssign(make_var(), HLILConst(SECOND_CASE_VALUE))
        false_block = HLILBlock([reload_assign, inner_if])
        first_if = HLILIf(make_condition(BinaryOp.EQ, FIRST_CASE_VALUE), make_case_body(FIRST_CASE_VALUE), false_block)

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(reaching_load)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        else_stmts = func.body.statements[1].false_block.statements
        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)


class TestReachingAssignmentExistsModificationBarriers(unittest.TestCase):
    '''Direct tests of _reaching_assignment_exists: a reaching candidate only counts if
    nothing between it and the use point modifies the destination or the source.'''

    def test_outer_var_reassigned_after_the_candidate_blocks_the_match(self):
        selector = HLILVariable('selector')
        source_var = HLILVariable(SOURCE_REG_NAME)
        candidate = HLILAssign(HLILVar(selector), HLILVar(source_var))
        clobber = HLILAssign(HLILVar(selector), HLILConst(0))

        result = ControlFlowOptimizationPass()._reaching_assignment_exists(
            selector, HLILVar(source_var), [candidate, clobber])

        self.assertFalse(result)

    def test_source_var_reassigned_after_the_candidate_blocks_the_match(self):
        selector = HLILVariable('selector')
        source_var = HLILVariable(SOURCE_REG_NAME)
        candidate = HLILAssign(HLILVar(selector), HLILVar(source_var))
        clobber = HLILAssign(HLILVar(source_var), HLILConst(0))

        result = ControlFlowOptimizationPass()._reaching_assignment_exists(
            selector, HLILVar(source_var), [candidate, clobber])

        self.assertFalse(result)

    def test_unrelated_statement_in_between_does_not_block_the_match(self):
        selector = HLILVariable('selector')
        source_var = HLILVariable(SOURCE_REG_NAME)
        candidate = HLILAssign(HLILVar(selector), HLILVar(source_var))
        unrelated = HLILAssign(HLILVar(HLILVariable('other')), HLILConst(0))

        result = ControlFlowOptimizationPass()._reaching_assignment_exists(
            selector, HLILVar(source_var), [candidate, unrelated])

        self.assertTrue(result)


class TestSourceMatchesDistinguishesIntFromFloat(unittest.TestCase):
    '''Mirrors pass_reg_global_propagation.py's established _expr_equal contract: int and
    float constants are distinct representations even at equal numeric value, and NaN
    compares equal to itself.'''

    def test_int_and_float_same_value_do_not_match(self):
        self.assertFalse(ControlFlowOptimizationPass()._source_matches(HLILConst(1), HLILConst(1.0)))

    def test_same_type_same_value_matches(self):
        cfo = ControlFlowOptimizationPass()
        self.assertTrue(cfo._source_matches(HLILConst(1), HLILConst(1)))
        self.assertTrue(cfo._source_matches(HLILConst(1.5), HLILConst(1.5)))

    def test_nan_matches_itself(self):
        nan = float('nan')
        self.assertTrue(ControlFlowOptimizationPass()._source_matches(HLILConst(nan), HLILConst(nan)))


SOURCE_MARKER_VALUE = 42


class TestRedundantElseAssignChainInteractionWithSwitchConversion(unittest.TestCase):
    '''A genuine reload chain (each link reloads the scrutinee from the same constant source
    before testing the next value) is the actual motivating shape for this optimization.
    Exactly 3 links is the base case both this function and switch-conversion were designed
    around. A 4th link changes the outcome: _optimize_block recurses into false_block before
    checking the current if's own reload, so by the time the outermost link's reload is
    examined, the inner 3-link suffix has ALREADY been switch-converted (3 alone meets
    SWITCH_MIN_CASES) - the outermost reload's "next statement" is then a HLILSwitch, not a
    HLILIf, so the pattern no longer matches and that one reload survives. This is a real,
    deliberate optimization-coverage tradeoff from scoping the reaching-definition search to
    the current block only (never crossing into an already-restructured continuation) - not a
    correctness bug, but documented here rather than left silently unasserted.'''

    def build_reload_chain(self, num_links: int) -> tuple:
        source = HLILConst(SOURCE_MARKER_VALUE)
        reaching_load = HLILAssign(make_var(), source)

        current_if = HLILIf(make_condition(BinaryOp.EQ, num_links), make_case_body(num_links), HLILBlock())

        for value in range(num_links - 1, 0, -1):
            reload_assign = HLILAssign(make_var(), source)
            current_if = HLILIf(make_condition(BinaryOp.EQ, value), make_case_body(value),
                                HLILBlock([reload_assign, current_if]))

        return reaching_load, current_if

    def test_exactly_three_links_removes_every_reload_and_converts_to_switch(self):
        reaching_load, first_if = self.build_reload_chain(3)

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(reaching_load)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[1], HLILSwitch)

    def test_four_links_the_outermost_reload_survives_once_the_inner_suffix_becomes_a_switch(self):
        reaching_load, first_if = self.build_reload_chain(4)

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(reaching_load)
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        outer_if = func.body.statements[1]
        self.assertIsInstance(outer_if, HLILIf)
        else_stmts = outer_if.false_block.statements
        # [reload (survives - its own "next stmt" is now a switch, not an if), <switch 2-4>]
        self.assertEqual(len(else_stmts), 2)
        self.assertIsInstance(else_stmts[0], HLILAssign)
        self.assertIsInstance(else_stmts[1], HLILSwitch)


TRACKED_VAR_NAME = 'tracked'
GUARD_VAR_NAME = 'guard'
OUTER_LABEL = 'outer'
INNER_LABEL = 'inner'
MIDDLE_LABEL = 'middle'
KILL_VALUE = 0
FIRST_LABEL_VALUE = 0
SECOND_LABEL_VALUE = 1


def make_tracked() -> HLILVariable:
    return HLILVariable(TRACKED_VAR_NAME)


def make_guard() -> HLILVar:
    return HLILVar(HLILVariable(GUARD_VAR_NAME))


def make_kill(var: HLILVariable) -> HLILAssign:
    return HLILAssign(HLILVar(var), HLILConst(KILL_VALUE))


def read_original(var: HLILVariable, node) -> tuple:
    return ControlFlowOptimizationPass()._can_read_original_value(var, node)


class TestExitPathsSurviveAnAsymmetricBranch(unittest.TestCase):
    '''A break/continue on one arm of an if rejoins at a real location further out, so it
    must survive even when the other arm falls through instead. Collapsing the subtree into
    a single "did every path exit" answer discarded it, letting a kill on the falling-through
    arm hide a read that the exiting path genuinely reaches with the original value.'''

    def _conditional_break_then_kill(self, break_stmt: HLILBreak, loop_label) -> HLILBlock:
        var = make_tracked()
        guarded_break = HLILIf(make_guard(), HLILBlock([break_stmt]), None)
        body = HLILBlock([guarded_break, make_kill(var)])
        loop = HLILDoWhile(make_guard(), body, label = loop_label)
        return HLILBlock([loop, HLILReturn(HLILVar(var))])

    def test_bare_conditional_break_past_a_kill_keeps_the_later_read_visible(self):
        block = self._conditional_break_then_kill(HLILBreak(), None)
        reads, _, _ = read_original(make_tracked(), block)
        self.assertTrue(reads)

    def test_labeled_conditional_break_past_a_kill_keeps_the_later_read_visible(self):
        block = self._conditional_break_then_kill(HLILBreak(label = OUTER_LABEL), OUTER_LABEL)
        reads, _, _ = read_original(make_tracked(), block)
        self.assertTrue(reads)

    def test_labeled_conditional_continue_past_a_kill_keeps_the_later_read_visible(self):
        var = make_tracked()
        guarded = HLILIf(make_guard(), HLILBlock([HLILContinue(label = OUTER_LABEL)]), None)
        body = HLILBlock([guarded, make_kill(var)])
        loop = HLILDoWhile(make_guard(), body, label = OUTER_LABEL)

        reads, _, _ = read_original(var, HLILBlock([loop, HLILReturn(HLILVar(var))]))

        # The continue rejoins the bottom check without running the kill, so an iteration
        # that then exits reaches the read with the original value
        self.assertTrue(reads)


class TestExitPathsAreAbsorbedByTheConstructThatOwnsThem(unittest.TestCase):
    '''A bare break belongs to the nearest enclosing loop or switch; a labeled one belongs
    only to the loop carrying that label and passes through everything in between.'''

    def test_labeled_break_passes_through_a_differently_labeled_inner_loop(self):
        var = make_tracked()
        mixed = HLILIf(make_guard(),
                       HLILBlock([HLILBreak(label = OUTER_LABEL)]),
                       HLILBlock([HLILReturn(None)]))
        inner = HLILDoWhile(make_guard(), HLILBlock([mixed]), label = INNER_LABEL)
        outer = HLILDoWhile(make_guard(), HLILBlock([inner, make_kill(var)]), label = OUTER_LABEL)

        reads, _, _ = read_original(var, HLILBlock([outer, HLILReturn(HLILVar(var))]))

        # Every path out of the inner loop is non-local, so the kill after it is dead code
        self.assertTrue(reads)

    def test_labeled_break_passes_through_an_intervening_while(self):
        var = make_tracked()
        inner = HLILWhile(make_guard(), HLILBlock([HLILBreak(label = OUTER_LABEL)]))
        outer = HLILDoWhile(make_guard(), HLILBlock([inner, make_kill(var)]), label = OUTER_LABEL)

        reads, _, _ = read_original(var, HLILBlock([outer, HLILReturn(HLILVar(var))]))

        self.assertTrue(reads)

    def test_labeled_break_crosses_three_nested_loops_to_its_own_owner(self):
        var = make_tracked()
        innermost = HLILDoWhile(make_guard(), HLILBlock([HLILBreak(label = OUTER_LABEL)]),
                                 label = INNER_LABEL)
        middle = HLILDoWhile(make_guard(), HLILBlock([innermost, make_kill(var)]),
                              label = MIDDLE_LABEL)
        outer = HLILDoWhile(make_guard(), HLILBlock([middle, make_kill(var)]), label = OUTER_LABEL)

        reads, _, _ = read_original(var, HLILBlock([outer, HLILReturn(HLILVar(var))]))

        self.assertTrue(reads)

    def test_a_label_matching_nothing_passes_all_the_way_out(self):
        var = make_tracked()
        loop = HLILDoWhile(make_guard(), HLILBlock([HLILBreak(label = 'nowhere')]), label = INNER_LABEL)

        _, fallthrough, exits = read_original(var, loop)

        # Not absorbed here, so it escapes rather than being silently swallowed
        self.assertIsNone(fallthrough)
        self.assertEqual([(e.kind, e.label) for e in exits], [(ExitKind.BREAK, 'nowhere')])

    def test_bare_break_is_absorbed_by_a_switch_not_the_enclosing_loop(self):
        var = make_tracked()
        case = HLILSwitchCase([HLILConst(FIRST_LABEL_VALUE)], HLILBlock([HLILBreak()]))
        switch_stmt = HLILSwitch(make_guard(), [case])

        _, fallthrough, exits = read_original(var, switch_stmt)

        # The switch owns it, so nothing escapes for an outer loop to absorb
        self.assertEqual(exits, ())
        self.assertIsNotNone(fallthrough)

    def test_bare_continue_escapes_a_switch_to_its_enclosing_loop(self):
        var = make_tracked()
        case = HLILSwitchCase([HLILConst(FIRST_LABEL_VALUE)], HLILBlock([HLILContinue()]))
        default = HLILSwitchCase(None, HLILBlock([HLILReturn(None)]))
        switch_stmt = HLILSwitch(make_guard(), [case, default])

        _, _, exits = read_original(var, switch_stmt)

        # A switch never owns continue - only loops do
        self.assertIn(ExitKind.CONTINUE, [e.kind for e in exits])


class TestSwitchFallthroughAccounting(unittest.TestCase):
    '''A case that merely breaks reaches the code after the switch; only a case that
    genuinely returns (or jumps further out) keeps that code unreachable.'''

    def test_switch_of_bare_breaks_does_not_hide_a_following_read(self):
        var = make_tracked()
        cases = [HLILSwitchCase([HLILConst(value)], HLILBlock([HLILBreak()]))
                 for value in (FIRST_LABEL_VALUE, SECOND_LABEL_VALUE)]
        cases.append(HLILSwitchCase(None, HLILBlock([HLILBreak()])))
        switch_stmt = HLILSwitch(make_guard(), cases)

        reads, _, _ = read_original(var, HLILBlock([switch_stmt, HLILReturn(HLILVar(var))]))

        self.assertTrue(reads)

    def test_switch_where_every_case_returns_still_hides_a_following_read(self):
        var = make_tracked()
        cases = [HLILSwitchCase([HLILConst(value)], HLILBlock([HLILReturn(None)]))
                 for value in (FIRST_LABEL_VALUE, SECOND_LABEL_VALUE)]
        cases.append(HLILSwitchCase(None, HLILBlock([HLILReturn(None)])))
        switch_stmt = HLILSwitch(make_guard(), cases)

        reads, fallthrough, _ = read_original(var, HLILBlock([switch_stmt, HLILReturn(HLILVar(var))]))

        self.assertFalse(reads)
        self.assertIsNone(fallthrough)

    def test_escaping_case_survives_alongside_a_killing_case(self):
        var = make_tracked()
        escaping = HLILSwitchCase([HLILConst(FIRST_LABEL_VALUE)],
                                   HLILBlock([HLILBreak(label = OUTER_LABEL)]))
        killing = HLILSwitchCase(None, HLILBlock([make_kill(var), HLILBreak()]))
        switch_stmt = HLILSwitch(make_guard(), [escaping, killing])
        loop = HLILDoWhile(make_guard(), HLILBlock([switch_stmt]), label = OUTER_LABEL)

        reads, _, _ = read_original(var, HLILBlock([loop, HLILReturn(HLILVar(var))]))

        # One case escapes to the loop without killing; the other kills and breaks locally
        self.assertTrue(reads)

    def test_cases_mixing_return_and_continue_keep_following_code_unreachable(self):
        var = make_tracked()
        returning = HLILSwitchCase([HLILConst(FIRST_LABEL_VALUE)], HLILBlock([HLILReturn(None)]))
        continuing = HLILSwitchCase(None, HLILBlock([HLILContinue()]))
        switch_stmt = HLILSwitch(make_guard(), [returning, continuing])

        _, fallthrough, _ = read_original(var, switch_stmt)

        # Neither a return nor a continue reaches the statement after the switch
        self.assertIsNone(fallthrough)


class TestReturnValueIsStillARead(unittest.TestCase):
    '''A return exits, but its value expression is evaluated first - dropping that read
    would let the assignment feeding it be deleted while the reference stayed behind.'''

    def test_returned_variable_counts_as_a_read(self):
        var = make_tracked()

        reads, _, _ = read_original(var, HLILBlock([HLILReturn(HLILVar(var))]))

        self.assertTrue(reads)

    def test_a_kill_before_the_return_still_hides_it(self):
        var = make_tracked()

        reads, _, _ = read_original(var, HLILBlock([make_kill(var), HLILReturn(HLILVar(var))]))

        self.assertFalse(reads)

    def test_boolean_temp_returned_inside_the_if_survives_the_full_pass(self):
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(make_flag_assign())
        func.add_statement(HLILIf(HLILBinaryOp(BinaryOp.NE, make_flag_var(), HLILConst(0)),
                                   HLILBlock([HLILReturn(make_flag_var())]),
                                   HLILBlock()))
        func = ControlFlowOptimizationPass().run(func)

        # _var_read_elsewhere excludes the whole if, so the return's own read is the only
        # thing standing between this assignment and a wrong deletion
        self.assertEqual(len(func.body.statements), 2)
        self.assertIsInstance(func.body.statements[0], HLILAssign)


class TestFallthroughIsThreeValued(unittest.TestCase):
    '''None (structurally cannot fall through), False (falls through, var intact) and True
    (falls through, var killed) are three distinct answers - a truthiness test would
    conflate None with False and silently resurrect the discarding bug.'''

    def test_plain_statements_fall_through_without_killing(self):
        var = make_tracked()
        block = HLILBlock([HLILExprStmt(HLILCall('side_effect', []))])

        _, fallthrough, exits = read_original(var, block)

        self.assertIs(fallthrough, False)
        self.assertEqual(exits, ())

    def test_a_kill_falls_through_as_killed(self):
        var = make_tracked()

        _, fallthrough, _ = read_original(var, HLILBlock([make_kill(var)]))

        self.assertIs(fallthrough, True)

    def test_an_unconditional_return_cannot_fall_through(self):
        var = make_tracked()

        _, fallthrough, _ = read_original(var, HLILBlock([HLILReturn(None)]))

        self.assertIsNone(fallthrough)

    def test_a_loop_whose_every_path_exits_cannot_fall_through(self):
        var = make_tracked()
        loop = HLILDoWhile(make_guard(), HLILBlock([HLILReturn(None)]), label = None)

        _, fallthrough, _ = read_original(var, loop)

        self.assertIsNone(fallthrough)

    def test_statements_after_a_non_falling_through_loop_are_not_scanned(self):
        var = make_tracked()
        loop = HLILDoWhile(make_guard(), HLILBlock([HLILReturn(None)]), label = None)
        block = HLILBlock([loop, HLILReturn(HLILVar(var))])

        reads, _, _ = read_original(var, block)

        # The trailing read is dead code behind a loop that always returns
        self.assertFalse(reads)

    def test_empty_and_absent_nodes_fall_through_untouched(self):
        var = make_tracked()

        for node in (None, HLILBlock(), HLILComment('note')):
            reads, fallthrough, exits = read_original(var, node)
            self.assertFalse(reads)
            self.assertIs(fallthrough, False)
            self.assertEqual(exits, ())


class TestConservativeLoopFallthroughIsIntentional(unittest.TestCase):
    '''Conditions are never interpreted, so a constant-true loop still reports a
    fallthrough it can never really take. That only keeps an assignment alive needlessly -
    it cannot hide a read - and avoiding it would mean proving loop termination here.'''

    def test_constant_true_while_still_reports_a_fallthrough(self):
        var = make_tracked()
        loop = HLILWhile(HLILConst(1), HLILBlock([HLILExprStmt(HLILCall('work', []))]))

        _, fallthrough, _ = read_original(var, loop)

        self.assertIsNotNone(fallthrough)

    def test_constant_true_do_while_still_reports_a_fallthrough(self):
        var = make_tracked()
        loop = HLILDoWhile(HLILConst(1), HLILBlock([HLILExprStmt(HLILCall('work', []))]), label = None)

        _, fallthrough, _ = read_original(var, loop)

        self.assertIsNotNone(fallthrough)

    def test_a_break_skipping_the_condition_is_not_treated_as_reading_it(self):
        var = make_tracked()
        loop = HLILDoWhile(HLILVar(var), HLILBlock([HLILBreak()]), label = None)

        reads, _, _ = read_original(var, loop)

        # A break goes straight to after the loop, never through the bottom check, so this
        # is exact rather than merely conservative: unlike a plain fallthrough or an
        # absorbed continue (which do reach the check), a break contributes nothing here
        self.assertFalse(reads)


class TestLoopConditionSeesEveryArrivingState(unittest.TestCase):
    '''A continue rejoins the bottom check carrying its own killed-state. If only the
    falling-through state were used, a read in the condition reachable solely via the
    continue would be missed.'''

    def test_condition_read_reachable_only_through_a_continue_is_found(self):
        var = make_tracked()
        early_continue = HLILIf(make_guard(), HLILBlock([HLILContinue()]), None)
        body = HLILBlock([early_continue, make_kill(var)])
        loop = HLILDoWhile(HLILVar(var), body, label = None)

        reads, _, _ = read_original(var, loop)

        # The continue reaches the condition before the kill runs, so the condition's own
        # read of var sees the original value on that path
        self.assertTrue(reads)


class TestKilledStateIsMonotonic(unittest.TestCase):
    '''Analyzing any node with killed=True must never produce a surviving killed=False
    state. The loop summary relies on this to close after a bounded number of rounds, so a
    future node type that broke it would silently invalidate that reasoning.'''

    def _representative_nodes(self, var: HLILVariable) -> list:
        guarded_break = HLILIf(make_guard(), HLILBlock([HLILBreak()]), None)
        switch_stmt = HLILSwitch(make_guard(), [
            HLILSwitchCase([HLILConst(FIRST_LABEL_VALUE)], HLILBlock([HLILBreak()])),
            HLILSwitchCase(None, HLILBlock([make_kill(var)])),
        ])
        return [
            HLILBlock([make_kill(var), HLILExprStmt(HLILCall('work', []))]),
            HLILIf(make_guard(), HLILBlock([make_kill(var)]), HLILBlock()),
            HLILWhile(make_guard(), HLILBlock([guarded_break, make_kill(var)])),
            HLILDoWhile(make_guard(), HLILBlock([guarded_break, make_kill(var)]), label = OUTER_LABEL),
            switch_stmt,
            HLILBlock([switch_stmt, HLILReturn(HLILVar(var))]),
        ]

    def test_analyzing_with_killed_true_never_yields_an_unkilled_state(self):
        var = make_tracked()

        for node in self._representative_nodes(var):
            reads, fallthrough, exits = read_original_killed(var, node)
            self.assertFalse(reads, node)
            if fallthrough is not None:
                self.assertIs(fallthrough, True, node)
            for exit_path in exits:
                self.assertIs(exit_path.killed, True, node)


def read_original_killed(var: HLILVariable, node) -> tuple:
    return ControlFlowOptimizationPass()._can_read_original_value(var, node, True)


if __name__ == '__main__':
    unittest.main()
