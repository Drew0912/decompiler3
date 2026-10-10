#!/usr/bin/env python3
'''The .hlil.ts text, line by line: the function header lists its parameters, a syscall and a script call print
their arguments (a string escaped and a hex constant written as the .ts writes them), an if / else-if / else chain
and a nested block indent one level per nesting, and every statement comes back as lines. The future HLIL DSL starts
from this text.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from common import default_indent
from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILAssign,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILComment,
    HLILConst,
    HLILExprStmt,
    HLILExternCall,
    HLILFormatter,
    HLILIf,
    HLILReturn,
    HLILSyscall,
    HLILVar,
    HLILVariable,
    VariableKind,
)

INDENT = default_indent()
SUBSYSTEM = 0
COMMAND = 3
FIRST_VALUE = 1
SECOND_VALUE = 2
ARGUMENT_VALUE = 65535
# A quote, a backslash, a newline and a tab, and the literal the .ts prints for it
SPECIAL_TEXT = 'a"b\\c\nd\te'
SPECIAL_TEXT_LITERAL = r'"a\"b\\c\nd\te"'
# A hex constant holding -1 prints unsigned, as the .ts prints it
ALL_BITS_SET = -1
ALL_BITS_SET_HEX = '0xFFFFFFFF'


def var(name: str) -> HLILVar:
    return HLILVar(HLILVariable(name))


def equals(name: str, value: int) -> HLILBinaryOp:
    return HLILBinaryOp(BinaryOp.EQ, var(name), HLILConst(value))


def call(name: str) -> HLILExprStmt:
    return HLILExprStmt(HLILCall(name, []))


def indented(level: int, text: str) -> str:
    return INDENT * level + text


class TestFunctionText(unittest.TestCase):

    def make_function(self) -> HighLevelILFunction:
        func = HighLevelILFunction('Routine')
        func.parameters = [HLILVariable(name, kind = VariableKind.PARAM) for name in ('arg1', 'arg2')]
        func.variables = [HLILVariable('local')]
        syscall = HLILSyscall(SUBSYSTEM, COMMAND, [HLILConst(ARGUMENT_VALUE), HLILConst('text')])
        func.add_statement(HLILExprStmt(syscall))
        func.add_statement(HLILExprStmt(HLILExternCall('other:Entry', [var('arg1')])))
        func.add_statement(HLILIf(
            equals('arg1', FIRST_VALUE),
            HLILBlock([call('first')]),
            HLILBlock([HLILIf(
                equals('arg2', SECOND_VALUE),
                HLILBlock([call('second')]),
                HLILBlock([call('other')]),
            )]),
        ))
        func.add_statement(HLILBlock([HLILAssign(var('local'), HLILConst(FIRST_VALUE))]))
        func.add_statement(HLILComment('note'))
        func.add_statement(HLILReturn(var('local')))
        return func

    def test_every_line(self):
        lines = HLILFormatter.format_function(self.make_function())

        self.assertEqual(lines, [
            'function Routine(arg1, arg2) {',
            indented(1, 'var local'),
            '',
            indented(1, f'syscall({SUBSYSTEM}, {COMMAND}, {ARGUMENT_VALUE}, "text");'),
            indented(1, 'other:Entry(arg1);'),
            indented(1, f'if (arg1 == {FIRST_VALUE}) {{'),
            indented(2, 'first();'),
            indented(1, f'}} else if (arg2 == {SECOND_VALUE}) {{'),
            indented(2, 'second();'),
            indented(1, '} else {'),
            indented(2, 'other();'),
            indented(1, '}'),
            indented(1, '{'),
            indented(2, f'local = {FIRST_VALUE};'),
            indented(1, '}'),
            indented(1, '// note'),
            indented(1, 'return local;'),
            '}',
        ])

    def test_function_without_parameters_has_an_empty_list(self):
        self.assertEqual(HLILFormatter.format_function(HighLevelILFunction('Init'))[0], 'function Init() {')

    def test_string_argument_is_escaped(self):
        func = HighLevelILFunction('Init')
        func.add_statement(HLILExprStmt(HLILCall('show', [HLILConst(SPECIAL_TEXT)])))

        self.assertIn(indented(1, f'show({SPECIAL_TEXT_LITERAL});'), HLILFormatter.format_function(func))

    def test_hex_constant_prints_unsigned_hex(self):
        func = HighLevelILFunction('Init')
        func.add_statement(HLILExprStmt(HLILCall('show', [HLILConst(ALL_BITS_SET, is_hex = True)])))

        self.assertIn(indented(1, f'show({ALL_BITS_SET_HEX});'), HLILFormatter.format_function(func))


if __name__ == '__main__':
    unittest.main()
