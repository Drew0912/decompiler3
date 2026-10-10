#!/usr/bin/env python3
'''Unit tests for ScpWriter.CommonImports, a common function called by its name, the duplicate-name guard, and
genLabel()'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer import scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import WriterTestCase


class CompileTestCase(WriterTestCase):
    def compile_dsl(self, build) -> scp_writer.ScpWriter:
        '''Run build(scena) against the test's fresh writer; returns the writer'''
        build(self.writer)
        self.writer.run(globals())
        return self.writer


class TestCommonImportsRegistrationOrder(CompileTestCase):
    '''CommonImports (library imports) registers before any @LLILCommonCode fallback or @LLILCode
    source function textually below it, since all three register at decoration time and Python
    decorators run top-to-bottom.'''

    def test_manifest_then_fallback_then_source(self):
        def imported_common(arg1: Value32):
            LOAD_STACK(-4)
            SET_REG(0)
            POP(4)
            RETURN()

        def build(scena):
            @scena.CommonImports()
            def commonImports():
                return [imported_common]

            @scena.LLILCommonCode()
            def fallback_common():
                RETURN()

            @scena.LLILCode()
            def SourceFunc():
                RETURN()

        writer = self.compile_dsl(build)
        names = [f.name for f in writer.functions]

        self.assertEqual(names, ['imported_common', 'fallback_common', 'SourceFunc'])
        self.assertEqual(writer.functions_by_name['imported_common'].entry.is_common_func, 1)
        self.assertEqual(writer.functions_by_name['fallback_common'].entry.is_common_func, 1)
        self.assertEqual(writer.functions_by_name['SourceFunc'].entry.is_common_func, 0)

    def test_commonImports_can_list_more_than_one_function(self):
        def imported_a(arg1: Value32):
            LOAD_STACK(-4)
            SET_REG(0)
            POP(4)
            RETURN()

        def imported_b():
            RETURN()

        def build(scena):
            @scena.CommonImports()
            def commonImports():
                return [imported_a, imported_b]

        writer = self.compile_dsl(build)

        self.assertEqual([f.name for f in writer.functions], ['imported_a', 'imported_b'])


class TestCallByName(WriterTestCase):
    '''The decompiler emits @scena.LLILCommonCode() for a common function the library didn't match, and other
    functions CALL it by its name: the decorator must give the name back'''

    def test_common_function_is_called_by_its_name(self):
        @self.writer.LLILCommonCode()
        def Common():
            RETURN()

        @self.writer.LLILCode()
        def Caller():
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            CALL(Common)
            label('ret')
            RETURN()

        self.assertIsNotNone(Common)
        _, functions = ScpParser.load_bytes(self.writer.build({}), 'test.dat', round_trip = False,
                                            keep_unreachable_code = False, quiet = True)

        self.assertEqual({func.name: func.is_common_func for func in functions}, {'Common': 1, 'Caller': 0})


class TestDuplicateNameGuard(WriterTestCase):
    def test_duplicate_name_raises(self):
        @self.writer.LLILCode()
        def Dup():
            RETURN()

        with self.assertRaisesRegex(ValueError, 'duplicate function name'):
            @self.writer.LLILCode()
            def Dup():
                RETURN()

    def test_duplicate_name_across_common_and_source_raises(self):
        def imported_shared():
            RETURN()

        @self.writer.CommonImports()
        def commonImports():
            return [imported_shared]

        with self.assertRaisesRegex(ValueError, 'duplicate function name'):
            @self.writer.LLILCode()
            def imported_shared():
                RETURN()


class TestGenLabel(CompileTestCase):
    '''genLabel() names must never collide with a decompiled loc_XXXX label, and must let a
    hand-written or generated function body resolve ordinary forward/backward jumps.'''

    def test_name_never_matches_the_decompiled_label_pattern(self):
        name = genLabel()

        self.assertNotRegex(name, r'^loc_[0-9A-Fa-f]+$')

    def test_resolves_a_forward_jump(self):
        def build(scena):
            @scena.LLILCommonCode()
            def WithForwardJump():
                target = genLabel()
                JMP(target)
                PUSH_INT(1)  # dead code the jump skips
                SET_REG(0)
                label(target)
                RETURN()

        # writer.run() raises an undefined-label error if the label never resolved
        writer = self.compile_dsl(build)
        self.assertIn('WithForwardJump', writer.functions_by_name)

    def test_two_functions_each_calling_genlabel_do_not_collide(self):
        def build(scena):
            @scena.LLILCommonCode()
            def First():
                target = genLabel()
                JMP(target)
                label(target)
                RETURN()

            @scena.LLILCommonCode()
            def Second():
                target = genLabel()
                JMP(target)
                label(target)
                RETURN()

        writer = self.compile_dsl(build)
        self.assertEqual({f.name for f in writer.functions}, {'First', 'Second'})


if __name__ == '__main__':
    unittest.main()
