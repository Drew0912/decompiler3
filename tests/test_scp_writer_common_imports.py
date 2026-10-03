#!/usr/bin/env python3
'''Unit tests for ScpWriter.CommonImports, the duplicate-name guard, and genLabel()'''

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from falcom.ed9.writer import scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import fresh_writer


def compile_dsl(build) -> scp_writer.ScpWriter:
    '''Run build(scena) against a fresh writer and a throwaway output path; returns the writer'''
    fresh_writer()
    with tempfile.TemporaryDirectory() as tmp:
        writer = create_scp_writer(str(Path(tmp) / 'test_output.dat'))
        build(writer)
        writer.run(globals())

    return writer


class TestCommonImportsRegistrationOrder(unittest.TestCase):
    '''CommonImports (library imports) registers before any @LLILCommonCode fallback or @LLILCode
    source function textually below it, since all three register at decoration time and Python
    decorators run top-to-bottom.'''

    def test_manifest_then_fallback_then_source(self):
        def imported_common(arg1: Value32):
            LOAD_STACK(-4)
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

        writer = compile_dsl(build)
        names = [f.name for f in writer.functions]

        self.assertEqual(names, ['imported_common', 'fallback_common', 'SourceFunc'])
        self.assertEqual(writer.functions_by_name['imported_common'].entry.is_common_func, 1)
        self.assertEqual(writer.functions_by_name['fallback_common'].entry.is_common_func, 1)
        self.assertEqual(writer.functions_by_name['SourceFunc'].entry.is_common_func, 0)

    def test_commonImports_can_list_more_than_one_function(self):
        def imported_a(arg1: Value32):
            LOAD_STACK(-4)
            RETURN()

        def imported_b():
            RETURN()

        def build(scena):
            @scena.CommonImports()
            def commonImports():
                return [imported_a, imported_b]

        writer = compile_dsl(build)

        self.assertEqual([f.name for f in writer.functions], ['imported_a', 'imported_b'])


class TestDuplicateNameGuard(unittest.TestCase):
    def test_duplicate_name_raises(self):
        fresh_writer()
        with tempfile.TemporaryDirectory() as tmp:
            writer = create_scp_writer(str(Path(tmp) / 'test_dup.dat'))

            @writer.LLILCode()
            def Dup():
                RETURN()

            with self.assertRaisesRegex(ValueError, 'duplicate function name'):
                @writer.LLILCode()
                def Dup():
                    RETURN()

    def test_duplicate_name_across_common_and_source_raises(self):
        fresh_writer()
        with tempfile.TemporaryDirectory() as tmp:
            writer = create_scp_writer(str(Path(tmp) / 'test_dup2.dat'))

            def imported_shared():
                RETURN()

            @writer.CommonImports()
            def commonImports():
                return [imported_shared]

            with self.assertRaisesRegex(ValueError, 'duplicate function name'):
                @writer.LLILCode()
                def imported_shared():
                    RETURN()


class TestGenLabel(unittest.TestCase):
    '''genLabel() names must never collide with a decompiled loc_XXXX label, and must let a
    hand-written or generated function body resolve ordinary forward/backward jumps.'''

    def test_name_never_matches_the_decompiled_label_pattern(self):
        fresh_writer()
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
        writer = compile_dsl(build)
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

        writer = compile_dsl(build)
        self.assertEqual({f.name for f in writer.functions}, {'First', 'Second'})


class TestFreshWriterIsolation(unittest.TestCase):
    '''The writer has no reset; two compiles in one process only stay isolated if each gets its own
    writer instance - the compile-twice test in tests/test_common_function_library.py relies on
    the same.'''

    def test_same_function_object_compiles_twice_with_a_fresh_writer_each_time(self):
        def WithForwardJump():
            target = genLabel()
            JMP(target)
            PUSH_INT(1)
            SET_REG(0)
            label(target)
            RETURN()

        def build(scena):
            scena.LLILCommonCode()(WithForwardJump)

        writer_1 = compile_dsl(build)
        writer_2 = compile_dsl(build)

        self.assertIsNot(writer_1, writer_2)
        self.assertEqual(len(writer_1.functions), 1)
        self.assertEqual(len(writer_2.functions), 1)


if __name__ == '__main__':
    unittest.main()
