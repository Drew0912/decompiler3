#!/usr/bin/env python3
'''Unit tests for the TypeScript code generator.'''

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen.typescript import TypeScriptGenerator, generate_typescript, generate_typescript_header
from falcom.ed9.parser.types_scp import RawInt
from ir.core import SourceFloat
from ir.core.il_base import IRParameter
from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILAssign,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILConst,
    HLILExpression,
    HLILExprStmt,
    HLILExternCall,
    HLILIf,
    HLILReturn,
    HLILSwitch,
    HLILSwitchCase,
    HLILTypeKind,
    HLILUnaryOp,
    HLILVar,
    HLILVariable,
    UnaryOp,
    VariableKind,
)
from ir.hlil.hlil_formatter import HLILFormatter
from ir.hlil.mlil_to_hlil import MLILToHLILConverter
from ir.mlil.mlil import MediumLevelILFunction, MLILRet
from ir.mlil.mlil_optimizer import optimize_mlil


TEST_FUNCTION_NAME = 'test_func'
FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
SECOND_CASE_CALL = 'second_case_call'
NEGATIVE_INT = -5
NEGATIVE_FLOAT = -3.0
# A quote, a backslash, a newline and a tab, and its TypeScript literal
SPECIAL_TEXT = 'a"b\\c\nd\te'
SPECIAL_TEXT_LITERAL = r'"a\"b\\c\nd\te"'
# A script-call target with a quote and a backslash, and its single-quoted TypeScript literal
SPECIAL_TARGET = "mod:O'Reilly\\entry"
SPECIAL_TARGET_LITERAL = r"'mod:O\'Reilly\\entry'"


def make_scrutinee() -> HLILVar:
    return HLILVar(HLILVariable('selector'))


def render_call(argument, parameters = ()) -> str:
    '''The TypeScript of a function whose body is f(argument)'''
    func = HighLevelILFunction(TEST_FUNCTION_NAME)
    func.parameters = list(parameters)
    func.add_statement(HLILExprStmt(HLILCall('f', [argument])))
    return generate_typescript(func)


def var(name: str) -> HLILVar:
    return HLILVar(HLILVariable(name))


class TestEmptyThenArm(unittest.TestCase):
    '''An if whose then-arm is empty prints its else-arm under the negated condition, negated as the HLIL passes
    negate (negate_condition: De Morgan, no double !), not wrapped in !(...)'''

    def render_if(self, condition) -> str:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILIf(condition, HLILBlock(), HLILBlock([HLILExprStmt(HLILCall('f', []))])))
        return generate_typescript(func)

    def test_condition_is_negated_like_the_hlil_passes(self):
        rows = [
            (HLILBinaryOp(BinaryOp.AND, var('a'), var('b')), 'if (!a || !b) {'),
            (HLILUnaryOp(UnaryOp.NOT, var('a')), 'if (a) {'),
            (HLILBinaryOp(BinaryOp.LT, var('a'), var('b')), 'if (a >= b) {'),
            (HLILBinaryOp(BinaryOp.OR, var('a'), HLILBinaryOp(BinaryOp.AND, var('b'), var('c'))),
             'if (!a && (!b || !c)) {'),
            # Then .ts's own comparison-with-0 simplifications, parenthesized by what they print
            (HLILBinaryOp(BinaryOp.EQ, var('a'), HLILConst(0)), 'if (a != 0) {'),
            (HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.OR, var('a'), var('b')), HLILConst(0)), 'if (a || b) {'),
            (HLILBinaryOp(BinaryOp.OR,
                          HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.OR, var('a'), var('b')), HLILConst(0)),
                          var('c')),
             'if ((a || b) && !c) {'),
        ]

        for condition, line in rows:
            with self.subTest(line = line):
                ts = self.render_if(condition)
                self.assertIn(f'    {line}\n        f();\n    }}', ts)
                self.assertNotIn('else', ts)


class TestZeroComparisonParentheses(unittest.TestCase):
    '''A comparison with 0 that prints as another node's text ((a || b) != 0 prints a || b) is parenthesized by
    that node: it printed f(a || b && c), read as a || (b && c)'''

    def test_operand_is_parenthesized_by_what_it_prints(self):
        a_or_b = HLILBinaryOp(BinaryOp.OR, var('a'), var('b'))
        rows = [
            (HLILBinaryOp(BinaryOp.AND, HLILBinaryOp(BinaryOp.NE, a_or_b, HLILConst(0)), var('c')),
             'f((a || b) && c);'),
            (HLILUnaryOp(UnaryOp.NOT, HLILUnaryOp(UnaryOp.NOT, HLILBinaryOp(BinaryOp.EQ, a_or_b, HLILConst(0)))),
             'f(!(a || b));'),
            # Unchanged: a tighter operand, and the simplification on its own
            (HLILBinaryOp(BinaryOp.AND,
                          HLILBinaryOp(BinaryOp.NE, HLILBinaryOp(BinaryOp.LT, var('a'), var('b')), HLILConst(0)),
                          var('c')),
             'f(a < b && c);'),
            (HLILBinaryOp(BinaryOp.NE, a_or_b, HLILConst(0)), 'f(a || b);'),
        ]

        for expr, text in rows:
            with self.subTest(text = text):
                self.assertIn(text, render_call(expr))


class TestSwitchEmptyCase(unittest.TestCase):
    '''An empty non-default case must not fall through into the next case.'''

    def test_empty_case_gets_a_break(self):
        empty_case = HLILSwitchCase([HLILConst(FIRST_CASE_VALUE)], HLILBlock())
        second_case = HLILSwitchCase(
            [HLILConst(SECOND_CASE_VALUE)],
            HLILBlock([HLILExprStmt(HLILCall(SECOND_CASE_CALL, []))]),
        )
        switch_stmt = HLILSwitch(make_scrutinee(), [empty_case, second_case])

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(switch_stmt)

        ts = generate_typescript(func)
        lines = [line.strip() for line in ts.splitlines()]

        first_case_idx = lines.index(f'case {FIRST_CASE_VALUE}: {{')
        # The very next line must be the closing brace's break, not a fall-through
        # straight into case 2's body
        self.assertEqual(lines[first_case_idx + 1], 'break;')


class TestPointerCodegen(unittest.TestCase):
    '''A Pointer (out-parameter) keeps its own kind through MLIL and HLIL.'''

    def test_pointer_parameter_renders_as_the_alias(self):
        func = MediumLevelILFunction(TEST_FUNCTION_NAME, params = [IRParameter('arg1', 'Pointer')])
        func.get_or_create_parameter(1, 'arg1')
        func.create_block().add_instruction(MLILRet())

        hlil = MLILToHLILConverter(optimize_mlil(func)).convert()

        self.assertEqual(hlil.parameters[0].type_hint, HLILTypeKind.POINTER)
        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: Pointer)', generate_typescript(hlil))
        self.assertIn('type Pointer = number;', generate_typescript_header())

    def test_boolean_assigned_to_a_pointer_gets_int_wrapped(self):
        # Pointer is a number alias, so it takes the same int(...) coercion as a number
        pointer = HLILVariable('arg1', HLILTypeKind.POINTER)
        bool_expr = HLILBinaryOp(BinaryOp.EQ, HLILVar(HLILVariable('a')), HLILVar(HLILVariable('b')))
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(pointer), bool_expr))

        self.assertIn('arg1 = int(', generate_typescript(func))


class TestNumberCodegen(unittest.TestCase):
    '''NUMBER (int or float) renders as number and takes the int(...) coercion.'''

    def test_number_parameter_renders_as_number(self):
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.parameters = [HLILVariable('arg1', HLILTypeKind.NUMBER, kind = VariableKind.PARAM)]

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: number)', generate_typescript(func))

    def test_boolean_assigned_to_a_number_local_gets_int_wrapped(self):
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.variables = [HLILVariable('x', HLILTypeKind.NUMBER)]
        bool_expr = HLILBinaryOp(BinaryOp.EQ, HLILVar(HLILVariable('a')), HLILVar(HLILVariable('b')))
        func.add_statement(HLILAssign(HLILVar(HLILVariable('x')), bool_expr))

        ts = generate_typescript(func)

        self.assertIn('let x: number;', ts)
        self.assertIn('x = int(', ts)


class TestConstantComparisonCodegen(unittest.TestCase):
    '''A comparison of two constants prints its value only for ints: a float comparison in the VM is unverified.
    Seen live: mon5265 printed if (2.0 > 0) as if (true).'''

    def render(self, op: BinaryOp, lhs, rhs) -> str:
        return render_call(HLILBinaryOp(op, HLILConst(lhs), HLILConst(rhs)))

    def test_float_comparison_is_printed(self):
        self.assertIn('f(2.0 > 0);', self.render(BinaryOp.GT, 2.0, 0))
        self.assertIn('f(0 < 0.5);', self.render(BinaryOp.LT, 0, 0.5))

    def test_int_comparison_still_prints_its_value(self):
        self.assertIn('f(true);', self.render(BinaryOp.GT, 2, 0))


class TestUnaryMinusCodegen(unittest.TestCase):
    '''A minus over an operand printed with a leading minus keeps its parentheses: --x is a decrement.
    Reachable from the LLIL DSL: PUSH_FLOAT(-3.0) then NEG() printed f(--3.0).'''

    def test_minus_over_a_leading_minus_keeps_its_parentheses(self):
        rows = [
            (HLILUnaryOp(UnaryOp.NEG, HLILVar(HLILVariable('a'))), 'f(-(-a));'),
            (HLILConst(NEGATIVE_INT), f'f(-({NEGATIVE_INT}));'),
            (HLILConst(NEGATIVE_FLOAT), f'f(-({NEGATIVE_FLOAT}));'),
        ]

        for operand, text in rows:
            with self.subTest(text = text):
                self.assertIn(text, render_call(HLILUnaryOp(UnaryOp.NEG, operand)))


class TestStringCodegen(unittest.TestCase):
    '''An argument and a parameter default print the same quote_string literal (a default used to escape only
    the backslash and the quote).'''

    def test_string_argument_and_default_are_escaped(self):
        parameter = HLILVariable('arg1', HLILTypeKind.STRING, default_value = SPECIAL_TEXT, kind = VariableKind.PARAM)
        ts = render_call(HLILConst(SPECIAL_TEXT), [parameter])

        self.assertIn(f'arg1: string = {SPECIAL_TEXT_LITERAL}', ts)
        self.assertIn(f'f({SPECIAL_TEXT_LITERAL});', ts)


class TestExternCallCodegen(unittest.TestCase):
    '''A script call's target prints as a quote_string literal (it used to be wrapped in quotes unescaped).'''

    def test_target_is_escaped(self):
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILExprStmt(HLILExternCall(SPECIAL_TARGET, [])))

        self.assertIn(f'extern_call({SPECIAL_TARGET_LITERAL});', generate_typescript(func))


CALLEE = 'g'                    # g(arg1, arg2 = 3, arg3 = -1)
ONE_PARAM_CALLEE = 'h'          # h(arg1 = <the row's default>)
LOG_FUNCTION = 'log'
DEFAULT_INT = 3
DEFAULT_NEGATIVE = -1
OTHER_INT = 5
HEX_VALUE = 0xFF
STORED_0_3 = 0.2999999523162842     # what 0.3 decodes to
DEFAULTS = {CALLEE: (None, DEFAULT_INT, DEFAULT_NEGATIVE)}


def call(name: str, *args) -> HLILCall:
    '''A call of name; a plain value argument becomes a constant'''
    return HLILCall(name, [arg if isinstance(arg, HLILExpression) else HLILConst(arg) for arg in args])


class TestTrailingDefaultArguments(unittest.TestCase):
    '''.ts leaves out a local call's longest tail of constants that are the callee's defaults (compared as the IR
    compares constants, constant_values_equal); the HLIL call and every other output keep them'''

    def render(self, statement, defaults = DEFAULTS) -> str:
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(statement)
        return generate_typescript(func, defaults)

    def test_trailing_defaults_left_out(self):
        rows = [
            (call(CALLEE, var('a'), DEFAULT_INT, DEFAULT_NEGATIVE), 'g(a);'),
            (call(CALLEE, var('a'), OTHER_INT, DEFAULT_NEGATIVE), 'g(a, 5);'),
            (call(CALLEE, var('a'), DEFAULT_INT, OTHER_INT), 'g(a, 3, 5);'),
            (call(CALLEE, DEFAULT_INT, DEFAULT_INT, DEFAULT_NEGATIVE), 'g(3);'),
            # Equal in value, but not a literal
            (call(CALLEE, var('a'), HLILBinaryOp(BinaryOp.ADD, HLILConst(1), HLILConst(2)), DEFAULT_NEGATIVE),
             'g(a, 1 + 2);'),
            (call(CALLEE, var('a'), var('three'), DEFAULT_NEGATIVE), 'g(a, three);'),
            (call(CALLEE, call(CALLEE, var('a'), DEFAULT_INT, DEFAULT_NEGATIVE), DEFAULT_INT, DEFAULT_NEGATIVE),
             'g(g(a));'),
        ]
        for expr, expected in rows:
            with self.subTest(expected):
                self.assertIn(expected, self.render(HLILExprStmt(expr)))

    def test_every_argument_left_out(self):
        self.assertIn('h();', self.render(HLILExprStmt(call(ONE_PARAM_CALLEE, DEFAULT_INT)),
                                          {ONE_PARAM_CALLEE: (DEFAULT_INT,)}))

    def test_calls_in_any_statement(self):
        full = call(CALLEE, var('a'), DEFAULT_INT, DEFAULT_NEGATIVE)
        rows = [
            (HLILIf(HLILBinaryOp(BinaryOp.LT, full, HLILConst(OTHER_INT)), HLILBlock([HLILReturn()])),
             'if (g(a) < 5) {'),
            (HLILReturn(full), 'return g(a);'),
            (HLILAssign(var('x'), full), 'x = g(a);'),
            (HLILExprStmt(HLILBinaryOp(BinaryOp.ADD, full, call(CALLEE, var('b'), DEFAULT_INT, DEFAULT_NEGATIVE))),
             'g(a) + g(b);'),
        ]
        for statement, expected in rows:
            with self.subTest(expected):
                self.assertIn(expected, self.render(statement))

    def test_compared_as_the_ir_compares_constants(self):
        rows = [
            # (argument, default, left out)
            (0, 0.0, False),
            (True, 1, False),
            (-0.0, 0.0, False),
            (SourceFloat(STORED_0_3, '0.3'), SourceFloat(STORED_0_3, '0.30'), False),
            (DEFAULT_INT, RawInt(DEFAULT_INT), False),
            (SourceFloat(STORED_0_3, '0.3'), SourceFloat(STORED_0_3, '0.3'), True),
            (SourceFloat(-1.0, '-1.0'), SourceFloat(-1.0, '-1.0'), True),
            (DEFAULT_NEGATIVE, DEFAULT_NEGATIVE, True),
            ('text', 'text', True),
            (HLILConst(HEX_VALUE, is_hex = True), HEX_VALUE, True),
        ]
        for argument, default, left_out in rows:
            with self.subTest(argument = repr(argument), default = repr(default)):
                statement = HLILExprStmt(call(ONE_PARAM_CALLEE, argument))
                with_defaults = self.render(statement, {ONE_PARAM_CALLEE: (default,)})

                self.assertEqual('h();' in with_defaults, left_out)
                if not left_out:
                    self.assertEqual(with_defaults, self.render(statement, None))

    def test_nothing_left_out_without_a_matching_callee(self):
        rows = [
            (call(CALLEE, var('a'), DEFAULT_INT, DEFAULT_NEGATIVE), None, 'g(a, 3, -1);'),
            (call('unknown', var('a'), DEFAULT_INT, DEFAULT_NEGATIVE), DEFAULTS, 'unknown(a, 3, -1);'),
            # Another argument count (never in a lifted call, which pushes every argument): the last argument is the
            # last default, so only the count keeps it
            (call(CALLEE, var('a'), DEFAULT_NEGATIVE), DEFAULTS, 'g(a, -1);'),
            # DEBUG_LOG's call is named debug.log; a script function named log is another callee
            (call('debug.log', DEFAULT_INT), {LOG_FUNCTION: (DEFAULT_INT,)}, 'debug.log(3);'),
        ]
        for expr, defaults, expected in rows:
            with self.subTest(expected):
                self.assertIn(expected, self.render(HLILExprStmt(expr), defaults))

    def test_the_call_keeps_every_argument(self):
        '''.hlil.ts is written from the same tree before .ts, then later outputs and callers see it'''
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        statement = HLILExprStmt(call(CALLEE, var('a'), DEFAULT_INT, DEFAULT_NEGATIVE))
        func.add_statement(statement)

        self.assertIn('g(a);', generate_typescript(func, DEFAULTS))
        # A direct caller (the codegen tests format single expressions) never sees the last render's defaults
        self.assertEqual(TypeScriptGenerator._format_expr(statement.expr), 'g(a, 3, -1)')
        self.assertEqual(len(statement.expr.args), 3)
        self.assertIn('g(a, 3, -1)', '\n'.join(HLILFormatter.format_function(func)))
        self.assertIn('g(a, 3, -1);', generate_typescript(func))


if __name__ == '__main__':
    unittest.main()
