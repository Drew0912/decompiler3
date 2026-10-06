#!/usr/bin/env python3
'''The writer's compile: built in memory and written only on success, file-wide labels whose errors and warnings
name their functions, DSL statements in the wrong place rejected, and global vars declared once, in their block or a
run callback, and named right.'''

from pathlib import Path
import re
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from common.logging import log
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import WriterTestCase, at, fresh_writer, marked_line

OPCODE_SIZE = 1  # a jump's label operand follows its 1-byte opcode


def read_uint32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


class TestWrittenOnlyOnSuccess(WriterTestCase):
    def define_undefined_label(self):
        # The bad reference sits between two other functions: the message must name the one that holds it
        @self.writer.LLILCode()
        def First():
            RETURN()

        @self.writer.LLILCode()
        def Foo():
            JMP('nowhere')
            RETURN()

        @self.writer.LLILCode()
        def Last():
            RETURN()

    def test_failed_compile_writes_no_file(self):
        self.define_undefined_label()

        # The check's source map puts the reference's line first
        with self.assertRaisesRegex(ValueError, rf"^{re.escape(__file__)}:\d+: Foo: undefined label 'nowhere'$"):
            self.writer.run({})

        self.assertFalse(self.dat.exists())

    def test_failed_compile_leaves_an_older_dat_as_it_was(self):
        sentinel = b'older .dat' * 8
        self.dat.write_bytes(sentinel)
        self.define_undefined_label()

        with self.assertRaises(ValueError):
            self.writer.run({})

        self.assertEqual(self.dat.read_bytes(), sentinel)

    def test_build_returns_the_bytes_run_writes(self):
        def define(writer):
            @writer.LLILCode()
            def Foo(arg1: Value32 = 2):
                PUSH_STR('text')
                POP(WORD_SIZE)
                JMP('end')
                label('end')
                POP(WORD_SIZE)
                RETURN()

        define(self.writer)
        self.writer.run({})
        written = self.dat.read_bytes()
        self.dat.unlink()

        writer = self.fresh_writer()
        define(writer)

        self.assertEqual(writer.build({}), written)
        self.assertFalse(self.dat.exists())


class TestLabels(WriterTestCase):
    def test_label_at_the_end_of_a_function_is_where_the_next_starts(self):
        @self.writer.LLILCode()
        def A():
            JMP('a_end')
            label('a_end')

        @self.writer.LLILCode()
        def B():
            JMP('b_end')
            PUSH_INT(1)
            POP(WORD_SIZE)
            label('b_end')
            RETURN()

        with self.assertNoLogs(log, 'WARNING'):
            data = self.writer.build({})

        a, b = self.writer.functions
        self.assertEqual(read_uint32(data, a.entry.offset + OPCODE_SIZE), b.entry.offset)
        self.assertEqual(data[read_uint32(data, b.entry.offset + OPCODE_SIZE)], ED9Opcode.RETURN)

    def test_jump_to_another_function_compiles_with_a_warning(self):
        # Forward from A into B, and back from B into A
        @self.writer.LLILCode()
        def A():
            label('in_a')
            JMP('in_b')

        @self.writer.LLILCode()
        def B():
            label('in_b')
            JMP('in_a')

        with self.assertLogs(log, 'WARNING') as logs:
            data = self.writer.build({})

        location = rf'^{re.escape(__file__)}:\d+: '
        for record, message in zip(logs.records, (
            "A: jumps to label 'in_b' in B (another function)",
            "B: jumps to label 'in_a' in A (another function)",
        ), strict = True):
            self.assertRegex(record.getMessage(), location + re.escape(message) + '$')

        a, b = self.writer.functions
        self.assertEqual(read_uint32(data, a.entry.offset + OPCODE_SIZE), b.entry.offset)
        self.assertEqual(read_uint32(data, b.entry.offset + OPCODE_SIZE), a.entry.offset)

    def test_duplicate_label_names_both_functions(self):
        @self.writer.LLILCode()
        def A():
            label('ret')
            RETURN()

        @self.writer.LLILCode()
        def B():
            label('ret')
            RETURN()

        with self.assertRaisesRegex(ValueError, r"^B: label 'ret' is already defined in A$"):
            self.writer.build({})

    def test_duplicate_label_in_one_function(self):
        @self.writer.LLILCode()
        def A():
            label('x')
            label('x')
            RETURN()

        with self.assertRaisesRegex(ValueError, r"^A: label 'x' is already defined in A$"):
            self.writer.build({})

    def test_caller_frame_operand_lands_after_the_call(self):
        # Not the first function, so a wrong base (code-relative instead of file offset) shows
        @self.writer.LLILCode()
        def First():
            RETURN()

        @self.writer.LLILCode()
        def Caller():
            PUSH_CALLER_FRAME('back')
            CALL_SCRIPT('this', 'GetCoolBoost', 0)
            label('back')
            GET_REG(0)
            SET_REG(0)
            RETURN()

        self.writer.run({})
        parser, functions = ScpParser.load(self.dat, round_trip = True, keep_unreachable_code = True)
        caller = next(f for f in functions if f.name == 'Caller')
        instructions = parser.get_instructions(caller)
        frame = next(i for i, inst in enumerate(instructions) if inst.opcode == ED9Opcode.PUSH_CALLER_FRAME)

        self.assertEqual(instructions[frame + 1].opcode, ED9Opcode.CALL_SCRIPT)
        self.assertEqual(instructions[frame].operands[0].value, instructions[frame + 2].offset)


class TestDebugArgc(WriterTestCase):
    def test_debug_argc_trims_the_recorded_args(self):
        @self.writer.LLILCode()
        def Callee(arg1: Value32, arg2: Value32, arg3: Nullable32 = 0):
            POP(3 * WORD_SIZE)
            RETURN()

        def call_callee(ret: str):
            DEBUG_SET_LINENO(1)  # a call gets a debug record only after line info
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR(ret)
            PUSH_INT(0)
            PUSH_INT(1)
            PUSH_INT(2)
            CALL(Callee)
            label(ret)
            RETURN()

        @self.writer.LLILCode(debug_argc = {'ret_a': 2})
        def DefaultLeftOut():
            call_callee('ret_a')

        @self.writer.LLILCode()
        def AllPassed():
            call_callee('ret_b')

        self.writer.build({})
        callee = self.writer.functions_by_name['Callee']

        for name, argc in (('DefaultLeftOut', 2), ('AllPassed', 3)):
            with self.subTest(function = name):
                [record] = self.writer.functions_by_name[name].debug_records
                self.assertEqual(record.func_id, callee.index)
                self.assertEqual(len(record.args), argc)


class TestStatementsInTheWrongPlace(WriterTestCase):
    def test_outside_a_function_body(self):
        for statement, emit in (
            ('PUSH_INT', lambda: PUSH_INT(1)),
            ('PUSH_CURRENT_FUNC_ID', PUSH_CURRENT_FUNC_ID),
            ("label('top')", lambda: label('top')),
        ):
            with self.subTest(statement = statement):
                with self.assertRaisesRegex(ValueError, rf'^{re.escape(statement)} is outside a function body$'):
                    emit()

    def test_after_a_compile(self):
        @self.writer.LLILCode()
        def Foo():
            RETURN()

        self.writer.build({})

        with self.assertRaisesRegex(ValueError, r'^RETURN is outside a function body$'):
            RETURN()

    def test_after_a_failed_compile(self):
        @self.writer.LLILCode()
        def Foo():
            PUSH_INT(True)

        with self.assertRaises(TypeError):
            self.writer.build({})

        with self.assertRaisesRegex(ValueError, r'^RETURN is outside a function body$'):
            RETURN()

    def test_global_var_inside_a_function_body(self):
        @self.writer.GlobalVars()
        def globalvars():
            GLOBAL_VAR('a', 1)

        @self.writer.LLILCode()
        def Body():
            GLOBAL_VAR('b', 1)
            RETURN()

        with self.assertRaisesRegex(ValueError, r"^Body: GLOBAL_VAR\('b'\) is inside a function body; declare it in @scena\.GlobalVars\(\)$"):
            self.writer.build({})


OUTSIDE_THE_BLOCK = r"^GLOBAL_VAR\('x'\) is outside @scena\.GlobalVars\(\) and a hook's run or function callback$"


class TestGlobalVarNames(WriterTestCase):
    def test_duplicate_declaration(self):
        with self.assertRaisesRegex(ValueError, r"^global var already declared: 'a'$"):
            @self.writer.GlobalVars()
            def globalvars():
                GLOBAL_VAR('a', 1)
                GLOBAL_VAR('a', 1)

        # The block raised, so its body is over: GLOBAL_VAR is outside it again
        with self.assertRaisesRegex(ValueError, OUTSIDE_THE_BLOCK):
            GLOBAL_VAR('x', 1)

    def test_unknown_name_lists_the_declared_ones(self):
        @self.writer.GlobalVars()
        def globalvars():
            GLOBAL_VAR('a', 1)

        @self.writer.LLILCode()
        def Body():
            LOAD_GLOBAL('b')
            RETURN()

        with self.assertRaisesRegex(ValueError, r"^unknown global var 'b'; declared: \['a'\]$"):
            self.writer.build({})

    def test_outside_the_block(self):
        '''A script's top level, and a hook's (it runs before create_scp_writer())'''
        for case in ('script', 'before create_scp_writer'):
            with self.subTest(case):
                if case == 'before create_scp_writer':
                    fresh_writer()

                with self.assertRaisesRegex(ValueError, OUTSIDE_THE_BLOCK):
                    GLOBAL_VAR('x', 1)

    def test_block_before_create_scp_writer(self):
        writer = fresh_writer()
        with self.assertRaisesRegex(ValueError, rf"^{at(__file__, 'early block')}@GlobalVars\(\) runs before "
                                                r"create_scp_writer\(\); a hook adds global vars with GLOBAL_VAR in a run "
                                                r"callback$"):
            @writer.GlobalVars()
            def globalvars():                               # line: early block
                GLOBAL_VAR('x', 1)

    def test_second_block(self):
        '''It replaced the first table before'''
        @self.writer.GlobalVars()
        def first():                                        # line: first block
            GLOBAL_VAR('a', 1)

        first_def = re.escape(f'{__file__}:{marked_line(__file__, "first block")}')
        with self.assertRaisesRegex(ValueError, rf"^{at(__file__, 'second block')}the global var table is already "
                                                rf"declared at {first_def}$"):
            @self.writer.GlobalVars()
            def second():                                   # line: second block
                GLOBAL_VAR('b', 1)


if __name__ == '__main__':
    unittest.main()
