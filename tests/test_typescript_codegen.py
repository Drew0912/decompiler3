#!/usr/bin/env python3
'''Unit tests for the TypeScript code generator.'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

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
    HLILVar,
    HLILVariable,
)
from ir.hlil.mlil_to_hlil import MLILToHLILConverter
from ir.mlil.mlil import MediumLevelILFunction, MLILRet
from ir.mlil.mlil_optimizer import optimize_mlil


TEST_FUNCTION_NAME = 'test_func'
FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
SECOND_CASE_CALL = 'second_case_call'


def make_scrutinee() -> HLILVar:
    return HLILVar(HLILVariable('selector'))


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


if __name__ == '__main__':
    unittest.main()
