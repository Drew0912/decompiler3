#!/usr/bin/env python3
'''Unit tests for the shared HLIL tables and helpers in ir/hlil/hlil.py - operator semantics,
C-family syntax and terminal statements - and for HLILFormatter's operators and switch breaks.'''

from pathlib import Path
import operator
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.hlil import (
    BinaryOp,
    UnaryOp,
    COMPARISON_OPS,
    BOOLEAN_BINARY_OPS,
    NEGATED_COMPARISON_OP,
    DE_MORGAN_OP,
    BINARY_OP_STR,
    UNARY_OP_STR,
    BINARY_OP_PRECEDENCE,
    TERMINAL_STATEMENTS,
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
    HLILUnstructured,
    HLILVar,
    HLILVariable,
    is_boolean_expr,
    needs_parentheses,
    negate_condition,
)

MULTIPLIER = 2
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
    '''Each table covers exactly the members it must - a new operator fails here until it has a
    symbol and a precedence.'''

    def test_every_binary_op_has_a_symbol_and_a_precedence(self):
        self.assertEqual(set(BINARY_OP_STR), set(BinaryOp))
        self.assertEqual(set(BINARY_OP_PRECEDENCE), set(BinaryOp))

    def test_every_unary_op_has_a_symbol(self):
        self.assertEqual(set(UNARY_OP_STR), set(UnaryOp))

    def test_boolean_ops_are_the_comparisons_plus_logical_ops(self):
        self.assertEqual(BOOLEAN_BINARY_OPS, COMPARISON_OPS | {BinaryOp.AND, BinaryOp.OR})

    def test_negated_comparison_is_the_complement(self):
        self.assertEqual(set(PYTHON_COMPARISON), COMPARISON_OPS)
        self.assertEqual(set(NEGATED_COMPARISON_OP), COMPARISON_OPS)

        for op in COMPARISON_OPS:
            negated = PYTHON_COMPARISON[NEGATED_COMPARISON_OP[op]]
            for lhs in SAMPLE_OPERANDS:
                for rhs in SAMPLE_OPERANDS:
                    with self.subTest(op = op.name, lhs = lhs, rhs = rhs):
                        self.assertEqual(negated(lhs, rhs), not PYTHON_COMPARISON[op](lhs, rhs))

    def test_de_morgan_swaps_and_with_or(self):
        self.assertEqual(DE_MORGAN_OP, {BinaryOp.AND: BinaryOp.OR, BinaryOp.OR: BinaryOp.AND})

    def test_terminal_statements(self):
        self.assertEqual(set(TERMINAL_STATEMENTS), {HLILReturn, HLILBreak, HLILContinue, HLILUnstructured})


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
