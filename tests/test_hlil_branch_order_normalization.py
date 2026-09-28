#!/usr/bin/env python3
'''Unit tests for HLIL branch order normalization.'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

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


EARLY_LINE = 100
LATE_LINE = 200
THIRD_LINE = 300
THRESHOLD = 2
CASE_VALUE = 1


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


def run_pass(stmt) -> HighLevelILFunction:
    func = HighLevelILFunction('test_branch_order')
    func.add_statement(stmt)
    return BranchOrderNormalizationPass().run(func)


def first_comment(block: HLILBlock) -> str:
    return block.statements[0].text


class TestBranchOrderNormalization(unittest.TestCase):

    def test_reversed_arms_are_swapped_and_condition_negated(self):
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), make_arm(EARLY_LINE))

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')
        self.assertEqual(first_comment(result.false_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.LE)

    def test_ascending_arms_are_left_alone(self):
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(EARLY_LINE), make_arm(LATE_LINE))

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_asymmetric_else_if_chain_is_refused(self):
        # Only the false arm is a chain, so swapping would bury the next test
        inner = HLILIf(make_condition(), make_arm(EARLY_LINE), None)
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), HLILBlock([inner]))

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(first_comment(result.true_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_symmetric_else_if_chains_are_swapped(self):
        # Both arms are chains, so they simply trade places - nothing gets buried
        late_chain = HLILBlock([HLILIf(make_condition(), make_arm(LATE_LINE), None)])
        early_chain = HLILBlock([HLILIf(make_condition(), make_arm(EARLY_LINE), None)])
        stmt = HLILIf(make_condition(BinaryOp.GT), late_chain, early_chain)

        func = run_pass(stmt)
        result = func.body.statements[0]

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

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIsInstance(result.true_block.statements[0], HLILExprStmt)

    def test_equal_depth_without_line_info_is_left_alone(self):
        left = HLILBlock([HLILExprStmt(HLILCall('left', []))])
        right = HLILBlock([HLILExprStmt(HLILCall('right', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), left, right)

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.GT)
        self.assertIs(result.true_block, left)

    def test_if_inside_a_loop_counts_toward_nesting_depth(self):
        # A loop is not an else-if chain, so only the depth tie-break can move this arm
        deep = HLILBlock([HLILWhile(make_condition(), HLILBlock([guarded_call('deep')]))])
        shallow = HLILBlock([HLILExprStmt(HLILCall('shallow', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), deep, shallow)

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIs(result.true_block, shallow)

    def test_if_inside_a_switch_case_counts_toward_nesting_depth(self):
        case = HLILSwitchCase([HLILConst(CASE_VALUE)], HLILBlock([guarded_call('deep')]))
        deep = HLILBlock([HLILSwitch(make_var(), [case])])
        shallow = HLILBlock([HLILExprStmt(HLILCall('shallow', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), deep, shallow)

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIs(result.true_block, shallow)

    def test_loop_without_an_if_adds_no_depth(self):
        # Only ifs are levels: a loop around plain calls ties with a plain arm
        loop = HLILBlock([HLILWhile(make_condition(), HLILBlock([HLILExprStmt(HLILCall('body', []))]))])
        plain = HLILBlock([HLILExprStmt(HLILCall('plain', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), loop, plain)

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.GT)
        self.assertIs(result.true_block, loop)

    def test_two_levels_outweigh_one(self):
        two_levels = HLILBlock([HLILWhile(make_condition(), HLILBlock([
            HLILIf(make_condition(), HLILBlock([guarded_call('deep')]), None),
        ]))])
        # after() keeps this arm from being a lone if, which the else-if chain rule would decide first
        one_level = HLILBlock([guarded_call('shallow'), HLILExprStmt(HLILCall('after', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), two_levels, one_level)

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.LE)
        self.assertIs(result.true_block, one_level)

    def test_empty_arm_is_refused(self):
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), HLILBlock())

        func = run_pass(stmt)
        result = func.body.statements[0]

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

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(result.condition.op, BinaryOp.OR)
        self.assertEqual(result.condition.lhs.op, BinaryOp.EQ)
        self.assertEqual(result.condition.rhs.op, BinaryOp.EQ)

    def test_nested_arms_are_normalized_before_the_outer_test(self):
        # The inner swap changes which line the outer arm starts with
        inner = HLILIf(make_condition(BinaryOp.GT), make_arm(THIRD_LINE), make_arm(LATE_LINE))
        outer = HLILIf(make_condition(BinaryOp.GT), HLILBlock([inner]), make_arm(EARLY_LINE))

        func = run_pass(outer)
        result = func.body.statements[0]

        self.assertEqual(first_comment(result.true_block), f'line({EARLY_LINE})')
        self.assertEqual(first_comment(result.false_block.statements[0].true_block),
                         f'line({LATE_LINE})')


class TestBranchOrderNormalizationFlag(unittest.TestCase):
    '''The converter flag must control whether the pass runs at all'''

    def pass_names(self, **kwargs) -> list:
        from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
        from ir.pipeline import Pipeline

        captured = []
        original = Pipeline.run

        def capture(self, input_data, debug = False):
            captured.extend(type(p).__name__ for p in self.passes)
            return input_data

        Pipeline.run = capture
        try:
            convert_falcom_mlil_to_hlil(None, None, **kwargs)

        finally:
            Pipeline.run = original

        return captured

    def test_pass_runs_by_default(self):
        self.assertIn('BranchOrderNormalizationPass', self.pass_names())

    def test_pass_is_absent_when_disabled(self):
        self.assertNotIn('BranchOrderNormalizationPass',
                         self.pass_names(normalize_branch_order = False))


if __name__ == '__main__':
    unittest.main()
