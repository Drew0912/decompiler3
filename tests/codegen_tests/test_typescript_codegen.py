#!/usr/bin/env python3
'''Unit tests for the TypeScript code generator.'''

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen.typescript import generate_typescript, generate_typescript_header
from ir.core.il_base import IRParameter
from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILAssign,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILConst,
    HLILExprStmt,
    HLILSwitch,
    HLILSwitchCase,
    HLILTypeKind,
    HLILUnaryOp,
    HLILVar,
    HLILVariable,
    UnaryOp,
    VariableKind,
)
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


def make_scrutinee() -> HLILVar:
    return HLILVar(HLILVariable('selector'))


def render_call(argument, parameters = ()) -> str:
    '''The TypeScript of a function whose body is f(argument)'''
    func = HighLevelILFunction(TEST_FUNCTION_NAME)
    func.parameters = list(parameters)
    func.add_statement(HLILExprStmt(HLILCall('f', [argument])))
    return generate_typescript(func)


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


if __name__ == '__main__':
    unittest.main()
