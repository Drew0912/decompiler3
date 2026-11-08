#!/usr/bin/env python3
"""TypeScript prints a tagged constant or a tagged parameter's default by its IdFormatHint's name: the table's, then the
pseudo enum's, else the number; an untagged value, a value without a name and a non-int default stay numbers. The
header declares each table. Hand-built HLIL, a test kind"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen.typescript import IdFormatHint, generate_typescript, generate_typescript_header
from ir.hlil import (HighLevelILFunction, HLILCall, HLILConst, HLILExprStmt, HLILReturn, HLILSyscall, HLILTypeKind,
                     HLILVariable, VariableKind)
from tests.shared.ir_utils import FrontendInt

KIND = 'TestId'
NAMED = 0
APOSTROPHE = 1
PSEUDO = 0xFFFE
UNNAMED = 505
HINT = IdFormatHint(
    'TestIdTable',
    {NAMED: 'Estelle', APOSTROPHE: "Groom's Family"},
    'PseudoTestId',
    {PSEUDO: 'Self'},
    'Test IDs',
)
ID_HINTS = {KIND: HINT}

CALLEE = 'chr_face'
CALL_ADDRESS = 0x40
SUBSYSTEM = 1
CMD = 0


def tagged(value) -> HLILConst:
    const = HLILConst(value)
    const.id_kind = KIND
    return const


def function_of(*statements, parameters: list[HLILVariable] | None = None) -> HighLevelILFunction:
    func = HighLevelILFunction('Main')
    func.parameters = parameters or []
    for stmt in statements:
        func.body.add_statement(stmt)

    return func


def printed_call(*args, **generate) -> str:
    """The TypeScript of Main: chr_face(args)"""
    return generate_typescript(function_of(HLILExprStmt(HLILCall(CALLEE, list(args)))), id_hints=ID_HINTS, **generate)


def id_parameter(default) -> HLILVariable:
    param = HLILVariable('arg1', HLILTypeKind.NUMBER, default, VariableKind.PARAM)
    param.id_kind = KIND
    return param


class TestTaggedConstants(unittest.TestCase):

    def test_each_value_prints_by_its_name_or_its_number(self):
        for const, text in ((tagged(NAMED), "TestIdTable['Estelle']"), (tagged(PSEUDO), 'PseudoTestId.Self'),
                            (tagged(UNNAMED), str(UNNAMED)), (HLILConst(NAMED), str(NAMED)),
                            (tagged(APOSTROPHE), "TestIdTable['Groom\\'s Family']")):
            with self.subTest(text=text):
                self.assertIn(f'{CALLEE}({text});', printed_call(const))

    def test_without_its_hint_a_tagged_value_is_a_number(self):
        ts = generate_typescript(function_of(HLILExprStmt(HLILCall(CALLEE, [tagged(NAMED)]))))

        self.assertIn(f'{CALLEE}({NAMED});', ts)

    def test_a_tagged_value_nested_in_a_call_is_named(self):
        syscall = HLILSyscall(SUBSYSTEM, CMD, [HLILCall(CALLEE, [tagged(NAMED)])])
        ts = generate_typescript(function_of(HLILReturn(syscall)), id_hints=ID_HINTS)

        self.assertIn(f"syscall({SUBSYSTEM}, {CMD}, {CALLEE}(TestIdTable['Estelle']))", ts)

    def test_a_trailing_default_is_dropped_and_kept_named_where_its_author_wrote_it(self):
        call = HLILCall(CALLEE, [tagged(NAMED)])
        call.address = CALL_ADDRESS
        func = function_of(HLILExprStmt(call))
        defaults = {CALLEE: (NAMED,)}

        self.assertIn(f'{CALLEE}();', generate_typescript(func, defaults, id_hints=ID_HINTS))
        self.assertIn(f"{CALLEE}(TestIdTable['Estelle']);",
                      generate_typescript(func, defaults, {CALL_ADDRESS: 1}, ID_HINTS))


class TestTaggedParameterDefaults(unittest.TestCase):

    def test_an_int_default_prints_by_name(self):
        ts = generate_typescript(function_of(HLILReturn(), parameters=[id_parameter(NAMED)]), id_hints=ID_HINTS)

        self.assertIn("function Main(arg1: number = TestIdTable['Estelle'])", ts)

    def test_a_frontend_int_default_prints_as_a_number(self):
        # A Raw word's default (ED9's RawInt) is no ID: its value only looks like one
        ts = generate_typescript(function_of(HLILReturn(), parameters=[id_parameter(FrontendInt(NAMED))]),
                                 id_hints=ID_HINTS)

        self.assertIn(f'function Main(arg1: number = {NAMED})', ts)


class TestHeader(unittest.TestCase):

    def test_the_header_declares_each_hints_table_only_when_given(self):
        declarations = ['// Test IDs', 'const TestIdTable: Record<string, number> = {};',
                        f'enum PseudoTestId {{ Self = {PSEUDO} }}']

        self.assertEqual([line for line in declarations if line in generate_typescript_header()], [])
        self.assertTrue(all(line in generate_typescript_header(ID_HINTS).splitlines() for line in declarations))


if __name__ == '__main__':
    unittest.main()
