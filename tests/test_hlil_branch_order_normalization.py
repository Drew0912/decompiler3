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
    HLILVar,
    HLILVariable,
)


EARLY_LINE = 100
LATE_LINE = 200
THIRD_LINE = 300
THRESHOLD = 2


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

    def test_else_if_chain_is_refused(self):
        # Swapping would bury the next test inside the then-branch
        inner = HLILIf(make_condition(), make_arm(EARLY_LINE), None)
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), HLILBlock([inner]))

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(first_comment(result.true_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

    def test_missing_line_info_is_refused(self):
        bare = HLILBlock([HLILExprStmt(HLILCall('untagged', []))])
        stmt = HLILIf(make_condition(BinaryOp.GT), make_arm(LATE_LINE), bare)

        func = run_pass(stmt)
        result = func.body.statements[0]

        self.assertEqual(first_comment(result.true_block), f'line({LATE_LINE})')
        self.assertEqual(result.condition.op, BinaryOp.GT)

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
        from falcom.ed9.hlil_converter import convert_falcom_mlil_to_hlil
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
