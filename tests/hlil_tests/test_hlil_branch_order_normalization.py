#!/usr/bin/env python3
'''Unit tests for HLIL branch order normalization.'''

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.hlil import (
    BinaryOp,
    BranchOrderNormalizationPass,
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
    HLILWhile,
)
from ir.mlil.mlil import MediumLevelILFunction, MLILCall, MLILDebug, MLILGoto, MLILIf, MLILRet, MLILVar
from tests.shared.ir_utils import connect


EARLY_LINE = 100
LATE_LINE = 200
THIRD_LINE = 300
THRESHOLD = 2
CASE_VALUE = 1
ENTRY_START = 0x10
LATE_START = 0x20
EARLY_START = 0x30
JOIN_START = 0x40


def make_var(name: str = 'selector') -> HLILVar:
    return HLILVar(HLILVariable(name))


def make_condition(op: BinaryOp = BinaryOp.GT) -> HLILBinaryOp:
    return HLILBinaryOp(op, make_var(), HLILConst(THRESHOLD))


def make_arm(line: int) -> HLILBlock:
    '''A branch whose first printed line number is `line`'''
    return HLILBlock([
        HLILComment(f'line({line})'),
        HLILExprStmt(HLILCall(f'work_{line}', [])),
    ])


def guarded_call(name: str) -> HLILIf:
    '''if (selector > THRESHOLD) name(); - no else, no line number'''
    return HLILIf(make_condition(), HLILBlock([HLILExprStmt(HLILCall(name, []))]), None)


def run_pass(stmt) -> HLILIf:
    '''stmt after BranchOrderNormalizationPass'''
    func = HighLevelILFunction('test_branch_order')
    func.add_statement(stmt)
    return BranchOrderNormalizationPass().run(func).body.statements[0]


def first_comment(block: HLILBlock) -> str:
    return block.statements[0].text


def make_reversed_arms_mlil() -> MediumLevelILFunction:
    '''if (arg1) {line LATE_LINE} else {line EARLY_LINE}, the arms rejoining: structuring keeps the bytecode's order'''
    func = MediumLevelILFunction('reversed_arms', ENTRY_START)
    entry = func.create_block(start = ENTRY_START, label = 'entry')
    late = func.create_block(start = LATE_START, label = 'late')
    early = func.create_block(start = EARLY_START, label = 'early')
    join = func.create_block(start = JOIN_START, label = 'join')
    entry.add_instruction(MLILIf(MLILVar(func.get_or_create_parameter(1, 'arg1')), late, early))
    for block, line in ((late, LATE_LINE), (early, EARLY_LINE)):
        block.add_instruction(MLILDebug('line', line, address = block.start))
        block.add_instruction(MLILCall(f'work_{line}', []))
        block.add_instruction(MLILGoto(join))

    join.add_instruction(MLILRet(None))
    return connect(func)


class TestBranchOrderNormalization(unittest.TestCase):

    def test_reversed_arms_are_swapped_and_condition_negated(self):
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), make_arm(EARLY_LINE))

        result = run_pass(stmt)

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')
        self.assertEqual(first_comment(result.false_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.LE)

    def test_ascending_arms_are_left_alone(self):
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(EARLY_LINE), make_arm(LATE_LINE))

        result = run_pass(stmt)

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_asymmetric_else_if_chain_is_refused(self):
        # Only the false arm is a chain, so swapping would bury the next test
        inner = HLILIf(make_condition(), make_arm(EARLY_LINE), None)
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), HLILBlock([inner]))

        result = run_pass(stmt)

        self.assertEqual(first_comment(result.true_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_symmetric_else_if_chains_are_swapped(self):
        # Both arms are chains, so they simply trade places - nothing gets buried
        late_chain = HLILBlock([HLILIf(make_condition(), make_arm(LATE_LINE), None)])
        early_chain = HLILBlock([HLILIf(make_condition(), make_arm(EARLY_LINE), None)])
        stmt = HLILIf(make_condition(BinaryOp.GT), late_chain, early_chain)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertEqual(first_comment(result.true_block.statements[0].true_block),
                         f'line({EARLY_LINE})')
        self.assertEqual(first_comment(result.false_block.statements[0].true_block),
                         f'line({LATE_LINE})')

    def test_missing_line_info_falls_back_to_nesting_depth(self):
        # No line numbers to compare, so the shallower arm goes first instead -
        # the rule the TypeScript emitter used to apply on its own
        deep = HLILBlock([HLILIf(make_condition(), HLILBlock([
            HLILIf(make_condition(), HLILBlock([HLILExprStmt(HLILCall('deep', []))]), None),
        ]), None)])
        shallow = HLILBlock([HLILExprStmt(HLILCall('shallow', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), deep, shallow)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIsInstance(result.true_block.statements[0], HLILExprStmt)

    def test_equal_depth_without_line_info_is_left_alone(self):
        left = HLILBlock([HLILExprStmt(HLILCall('left', []))])
        right = HLILBlock([HLILExprStmt(HLILCall('right', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), left, right)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.GT)
        self.assertIs(result.true_block, left)

    def test_if_inside_a_loop_counts_toward_nesting_depth(self):
        # A loop is not an else-if chain, so only the depth tie-break can move this arm
        deep = HLILBlock([HLILWhile(make_condition(), HLILBlock([guarded_call('deep')]))])
        shallow = HLILBlock([HLILExprStmt(HLILCall('shallow', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), deep, shallow)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIs(result.true_block, shallow)

    def test_if_inside_a_switch_case_counts_toward_nesting_depth(self):
        case = HLILSwitchCase([HLILConst(CASE_VALUE)], HLILBlock([guarded_call('deep')]))
        deep = HLILBlock([HLILSwitch(make_var(), [case])])
        shallow = HLILBlock([HLILExprStmt(HLILCall('shallow', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), deep, shallow)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIs(result.true_block, shallow)

    def test_loop_without_an_if_adds_no_depth(self):
        # Only ifs are levels: a loop around plain calls ties with a plain arm
        loop = HLILBlock([HLILWhile(make_condition(), HLILBlock([HLILExprStmt(HLILCall('body', []))]))])
        plain = HLILBlock([HLILExprStmt(HLILCall('plain', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), loop, plain)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.GT)
        self.assertIs(result.true_block, loop)

    def test_two_levels_outweigh_one(self):
        two_levels = HLILBlock([HLILWhile(make_condition(), HLILBlock([
            HLILIf(make_condition(), HLILBlock([guarded_call('deep')]), None),
        ]))])
        # after() keeps this arm from being a lone if, which the else-if chain rule would decide first
        one_level = HLILBlock([guarded_call('shallow'), HLILExprStmt(HLILCall('after', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), two_levels, one_level)

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIs(result.true_block, one_level)

    def test_empty_arm_is_refused(self):
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), HLILBlock())

        result = run_pass(stmt)

        self.assertEqual(first_comment(result.true_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_and_condition_is_negated_by_de_morgan(self):
        # NOT(a != 2 && a != 2) would read worse than what it replaced
        condition = HLILBinaryOp(
            BinaryOp.AND,
            HLILBinaryOp(BinaryOp.NE, make_var(), HLILConst(THRESHOLD)),
            HLILBinaryOp(BinaryOp.NE, make_var('other'), HLILConst(THRESHOLD)),
        )
        stmt = HLILIf(condition, make_arm(LATE_LINE), make_arm(EARLY_LINE))

        result = run_pass(stmt)

        self.assertEqual(result.condition.op, BinaryOp.OR)
        self.assertEqual(result.condition.lhs.op, BinaryOp.EQ)
        self.assertEqual(result.condition.rhs.op, BinaryOp.EQ)

    def test_nested_arms_are_normalized_before_the_outer_test(self):
        # The inner swap changes which line the outer arm starts with
        inner = HLILIf(make_condition(BinaryOp.GT), make_arm(THIRD_LINE), make_arm(LATE_LINE))
        outer = HLILIf(make_condition(BinaryOp.GT), HLILBlock([inner]), make_arm(EARLY_LINE))

        result = run_pass(outer)

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')
        self.assertEqual(first_comment(result.false_block.statements[0].true_block),
                         f'line({LATE_LINE})')


class TestNormalizeBranchOrderFlag(unittest.TestCase):
    '''convert_falcom_mlil_to_hlil's normalize_branch_order: on by default, off keeps the bytecode's arm order'''

    def test_on_by_default_puts_the_earlier_line_first(self):
        [result, _] = convert_falcom_mlil_to_hlil(make_reversed_arms_mlil()).body.statements

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')

    def test_off_keeps_the_bytecode_order(self):
        hlil = convert_falcom_mlil_to_hlil(make_reversed_arms_mlil(), normalize_branch_order = False)
        [result, _] = hlil.body.statements

        self.assertEqual(first_comment(result.true_block), f'line({LATE_LINE})')


def compare(operand) -> HLILBinaryOp:
    return HLILBinaryOp(BinaryOp.GT, operand, HLILConst(THRESHOLD))


def lone_if_chain(*arms: HLILBlock) -> HLILBlock:
    '''A block that is only an if whose else holds the next link: one link per arm'''
    result = None
    for arm in reversed(arms):
        result = HLILBlock([HLILIf(make_condition(), arm, result)])

    return result


class TestChainsAndScrutinees(unittest.TestCase):
    '''The longer else-if chain goes in the else whatever the lines say; a chain testing the same variable stays;
    one testing something else, or a test that examines no variable, is ordered by its lines'''

    def test_arm_without_a_line_number_never_fails_the_comparison(self):
        with_line = make_arm(EARLY_LINE)
        without_line = HLILBlock([HLILExprStmt(HLILCall('without_line', []))])

        result = run_pass(HLILIf(make_condition(), with_line, without_line))

        self.assertIs(result.true_block, with_line)
        self.assertIs(result.false_block, without_line)

    def test_the_longer_chain_goes_in_the_else(self):
        # Ascending lines would leave the arms alone; the longer chain still moves to the else
        long_chain = lone_if_chain(make_arm(EARLY_LINE), make_arm(EARLY_LINE + 1))
        short_chain = lone_if_chain(make_arm(LATE_LINE))

        result = run_pass(HLILIf(make_condition(), long_chain, short_chain))

        self.assertIs(result.true_block, short_chain)
        self.assertIs(result.false_block, long_chain)
        self.assertEqual(result.condition.op, BinaryOp.LE)

    def test_the_shorter_chain_stays_first_whatever_the_lines_say(self):
        long_chain = lone_if_chain(make_arm(EARLY_LINE), make_arm(EARLY_LINE + 1))
        short_chain = lone_if_chain(make_arm(LATE_LINE))

        result = run_pass(HLILIf(make_condition(), short_chain, long_chain))

        self.assertIs(result.true_block, short_chain)
        self.assertIs(result.false_block, long_chain)
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_a_chain_testing_something_else_is_swapped_by_line_order(self):
        # The else holds a lone if on an unrelated variable: not a continuation of this test
        chain = HLILBlock([HLILIf(compare(make_var('other')), make_arm(EARLY_LINE), None)])
        late = make_arm(LATE_LINE)

        result = run_pass(HLILIf(make_condition(), late, chain))

        self.assertIs(result.true_block, chain)
        self.assertIs(result.false_block, late)

    def test_a_chain_on_another_bare_variable_is_swapped_by_line_order(self):
        chain = HLILBlock([HLILIf(make_var('other'), make_arm(EARLY_LINE), None)])
        late = make_arm(LATE_LINE)

        result = run_pass(HLILIf(make_var(), late, chain))

        self.assertIs(result.true_block, chain)
        self.assertIs(result.false_block, late)

    def test_a_chain_on_the_same_variable_is_left_alone(self):
        chain = HLILBlock([HLILIf(make_condition(), make_arm(EARLY_LINE), None)])
        late = make_arm(LATE_LINE)

        result = run_pass(HLILIf(make_condition(), late, chain))

        self.assertIs(result.true_block, late)

    def test_a_chain_whose_inner_test_examines_no_variable_is_left_alone(self):
        total = HLILBinaryOp(BinaryOp.ADD, make_var('a'), make_var('b'))
        chain = HLILBlock([HLILIf(compare(total), make_arm(EARLY_LINE), None)])
        late = make_arm(LATE_LINE)

        result = run_pass(HLILIf(make_condition(), late, chain))

        self.assertIs(result.true_block, late)

    def test_a_chain_whose_outer_test_examines_no_variable_is_left_alone(self):
        total = HLILBinaryOp(BinaryOp.ADD, make_var('a'), make_var('b'))
        chain = HLILBlock([HLILIf(make_condition(), make_arm(EARLY_LINE), None)])
        late = make_arm(LATE_LINE)

        result = run_pass(HLILIf(compare(total), late, chain))

        self.assertIs(result.true_block, late)


if __name__ == '__main__':
    unittest.main()
