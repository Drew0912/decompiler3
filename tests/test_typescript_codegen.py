#!/usr/bin/env python3
'''Unit tests for the TypeScript code generator.'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

from codegen.typescript import generate_typescript
from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILConst,
    HLILExprStmt,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
)


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


if __name__ == '__main__':
    unittest.main()
