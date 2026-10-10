#!/usr/bin/env python3
'''Unit tests for the shared HLIL tables and helpers in ir/hlil/hlil.py - operator semantics and
C-family syntax - and for HLILFormatter's operators and switch breaks.'''

from pathlib import Path
import operator
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.hlil import (
    BinaryOp,
    UnaryOp,
    COMPARISON_OPS,
    BOOLEAN_BINARY_OPS,
    NEGATED_COMPARISON_OP,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILBreak,
    HLILConst,
    HLILContinue,
    HLILFormatter,
    HLILReturn,
    HLILSwitch,
    HLILSwitchCase,
    HLILUnaryOp,
    HLILVar,
    HLILVariable,
    is_boolean_expr,
    needs_parentheses,
    negate_condition,
    unary_operand_needs_parentheses,
)

MULTIPLIER = 2
NEGATIVE_INT = -5
NEGATIVE_FLOAT = -3.0
FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
SAMPLE_OPERANDS = (-1, 0, 1)

PYTHON_COMPARISON = {
    BinaryOp.EQ : operator.eq,
    BinaryOp.NE : operator.ne,
    BinaryOp.LT : operator.lt,
    BinaryOp.LE : operator.le,
    BinaryOp.GT : operator.gt,
    BinaryOp.GE : operator.ge,
}


def var(name: str) -> HLILVar:
    return HLILVar(HLILVariable(name))


class TestSharedTables(unittest.TestCase):

    def test_negated_comparison_is_the_complement(self):
        self.assertEqual(set(PYTHON_COMPARISON), COMPARISON_OPS)
        self.assertEqual(set(NEGATED_COMPARISON_OP), COMPARISON_OPS)

        for op in COMPARISON_OPS:
            negated = PYTHON_COMPARISON[NEGATED_COMPARISON_OP[op]]
            for lhs in SAMPLE_OPERANDS:
                for rhs in SAMPLE_OPERANDS:
                    with self.subTest(op = op.name, lhs = lhs, rhs = rhs):
                        self.assertEqual(negated(lhs, rhs), not PYTHON_COMPARISON[op](lhs, rhs))


class TestNeedsParentheses(unittest.TestCase):

    def test_lower_precedence_child_is_wrapped(self):
        self.assertTrue(needs_parentheses(BinaryOp.ADD, BinaryOp.MUL, True))
        self.assertTrue(needs_parentheses(BinaryOp.BIT_AND, BinaryOp.EQ, True))

    def test_higher_precedence_child_is_not_wrapped(self):
        self.assertFalse(needs_parentheses(BinaryOp.MUL, BinaryOp.ADD, False))

    def test_equal_precedence_wraps_only_the_rhs_of_a_non_associative_op(self):
        self.assertFalse(needs_parentheses(BinaryOp.SUB, BinaryOp.SUB, True))

        for op in (BinaryOp.SUB, BinaryOp.DIV, BinaryOp.MOD):
            with self.subTest(op = op.name):
                self.assertTrue(needs_parentheses(op, op, False))

        for op in (BinaryOp.ADD, BinaryOp.MUL):
            with self.subTest(op = op.name):
                self.assertFalse(needs_parentheses(op, op, False))


class TestUnaryOperandNeedsParentheses(unittest.TestCase):
    '''Decided on the operand's printed text, which the .hlil.ts and .ts printers write differently for constants'''

    def test_binary_operand_is_wrapped(self):
        operand = HLILBinaryOp(BinaryOp.LT, var('a'), var('b'))
        self.assertTrue(unary_operand_needs_parentheses(UnaryOp.NOT, operand, 'a < b'))

    def test_minus_over_a_leading_minus_is_wrapped(self):
        self.assertTrue(unary_operand_needs_parentheses(UnaryOp.NEG, HLILUnaryOp(UnaryOp.NEG, var('a')), '-a'))
        self.assertTrue(unary_operand_needs_parentheses(UnaryOp.NEG, HLILConst(NEGATIVE_FLOAT), str(NEGATIVE_FLOAT)))

    def test_minus_over_other_text_and_other_operators_are_not(self):
        negated = HLILUnaryOp(UnaryOp.NEG, var('a'))
        self.assertFalse(unary_operand_needs_parentheses(UnaryOp.NEG, var('a'), 'a'))

        for op in (UnaryOp.NOT, UnaryOp.BIT_NOT):
            with self.subTest(op = op.name):
                self.assertFalse(unary_operand_needs_parentheses(op, negated, '-a'))


class TestNegateCondition(unittest.TestCase):

    def test_double_negation_unwraps(self):
        x = var('x')
        self.assertIs(negate_condition(HLILUnaryOp(UnaryOp.NOT, x)), x)

    def test_comparison_flips_its_operator(self):
        a, b = var('a'), var('b')
        negated = negate_condition(HLILBinaryOp(BinaryOp.LT, a, b))

        self.assertEqual(negated.op, BinaryOp.GE)
        self.assertIs(negated.lhs, a)
        self.assertIs(negated.rhs, b)

    def test_de_morgan_distributes_over_logical_ops(self):
        a, b, c, d = var('a'), var('b'), var('c'), var('d')
        cond = HLILBinaryOp(BinaryOp.AND, HLILBinaryOp(BinaryOp.LT, a, b), HLILBinaryOp(BinaryOp.EQ, c, d))
        negated = negate_condition(cond)

        self.assertEqual(negated.op, BinaryOp.OR)
        self.assertEqual((negated.lhs.op, negated.rhs.op), (BinaryOp.GE, BinaryOp.NE))

    def test_anything_else_is_wrapped_in_not(self):
        x = var('x')
        negated = negate_condition(x)

        self.assertIsInstance(negated, HLILUnaryOp)
        self.assertEqual(negated.op, UnaryOp.NOT)
        self.assertIs(negated.operand, x)


class TestIsBooleanExpr(unittest.TestCase):

    def test_comparisons_logical_ops_and_not_are_boolean(self):
        a, b = var('a'), var('b')

        for op in BOOLEAN_BINARY_OPS:
            with self.subTest(op = op.name):
                self.assertTrue(is_boolean_expr(HLILBinaryOp(op, a, b)))

        self.assertTrue(is_boolean_expr(HLILUnaryOp(UnaryOp.NOT, a)))

    def test_arithmetic_negation_and_plain_values_are_not(self):
        a, b = var('a'), var('b')

        self.assertFalse(is_boolean_expr(HLILBinaryOp(BinaryOp.ADD, a, b)))
        self.assertFalse(is_boolean_expr(HLILUnaryOp(UnaryOp.NEG, a)))
        self.assertFalse(is_boolean_expr(a))


class TestFormatterOperators(unittest.TestCase):
    '''The .hlil.ts debug dump prints operator symbols and precedence parentheses - it used to
    print enum names (`a ADD b MUL 2`), and its string-keyed precedence lookup never matched.'''

    def format(self, expr) -> str:
        return HLILFormatter._format_expr(expr)

    def test_binary_ops_print_symbols_with_precedence_parentheses(self):
        a, b, c = var('a'), var('b'), var('c')
        scaled_sum = HLILBinaryOp(BinaryOp.MUL, HLILBinaryOp(BinaryOp.ADD, a, b), HLILConst(MULTIPLIER))
        right_nested = HLILBinaryOp(BinaryOp.SUB, a, HLILBinaryOp(BinaryOp.SUB, b, c))
        left_nested = HLILBinaryOp(BinaryOp.SUB, HLILBinaryOp(BinaryOp.SUB, a, b), c)

        self.assertEqual(self.format(scaled_sum), f'(a + b) * {MULTIPLIER}')
        self.assertEqual(self.format(right_nested), 'a - (b - c)')
        self.assertEqual(self.format(left_nested), 'a - b - c')

    def test_unary_ops_print_symbols(self):
        a, b = var('a'), var('b')

        self.assertEqual(self.format(HLILUnaryOp(UnaryOp.NOT, HLILBinaryOp(BinaryOp.LT, a, b))), '!(a < b)')
        self.assertEqual(self.format(HLILUnaryOp(UnaryOp.NEG, a)), '-a')
        self.assertEqual(self.format(HLILUnaryOp(UnaryOp.BIT_NOT, a)), '~a')

    def test_minus_over_a_leading_minus_keeps_its_parentheses(self):
        a, b = var('a'), var('b')
        negated = HLILUnaryOp(UnaryOp.NEG, a)
        rows = [
            (HLILUnaryOp(UnaryOp.NEG, negated), '-(-a)'),
            (HLILUnaryOp(UnaryOp.NEG, HLILConst(NEGATIVE_INT)), f'-({NEGATIVE_INT})'),
            (HLILUnaryOp(UnaryOp.NEG, HLILConst(NEGATIVE_FLOAT)), f'-({NEGATIVE_FLOAT})'),
            (HLILUnaryOp(UnaryOp.NOT, negated), '!-a'),
            (HLILUnaryOp(UnaryOp.NEG, HLILBinaryOp(BinaryOp.ADD, a, b)), '-(a + b)'),
        ]

        for expr, text in rows:
            with self.subTest(text = text):
                self.assertEqual(self.format(expr), text)


class TestFormatterSwitchBreak(unittest.TestCase):
    '''Every case that can fall through ends in `break;` - an empty case too, which otherwise
    reads as a second label sharing the next case's body.'''

    def format_switch(self, first_body: HLILBlock) -> list:
        func = HighLevelILFunction('f')
        func.add_statement(HLILSwitch(var('x'), [
            HLILSwitchCase([HLILConst(FIRST_CASE_VALUE)], first_body),
            HLILSwitchCase([HLILConst(SECOND_CASE_VALUE)], HLILBlock([HLILReturn()])),
        ]))
        return [line.strip() for line in HLILFormatter.format_function(func)]

    def test_empty_case_gets_a_break(self):
        lines = self.format_switch(HLILBlock())
        first = lines.index(f'case {FIRST_CASE_VALUE}:')

        self.assertEqual(lines[first + 1], 'break;')

    def test_case_ending_in_a_terminal_statement_gets_no_extra_break(self):
        for terminal in (HLILReturn(), HLILBreak(), HLILContinue()):
            with self.subTest(terminal = type(terminal).__name__):
                lines = self.format_switch(HLILBlock([terminal]))
                first = lines.index(f'case {FIRST_CASE_VALUE}:')

                self.assertEqual(lines[first + 2], f'case {SECOND_CASE_VALUE}:')


if __name__ == '__main__':
    unittest.main()
