#!/usr/bin/env python3
'''The writer's compile: built in memory and written only on success, file-wide labels whose errors and warnings
name their functions, DSL statements in the wrong place rejected, global vars declared once, in their block or a
run callback, named right and typed as the games do (else a warning), the global opcodes by name or index (an index
within the declared table), an operand or pushed value out of its range or of the wrong type failing at its line, a
string the pool can't store failing where it enters, and the string pool without round_trip.'''

from enum import StrEnum
import logging
import math
from pathlib import Path
import re
import struct
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.logging import log
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.scp import OPCODE_SIZE, ScpParser
from falcom.ed9.parser.types_scp import ScpGlobalVar, ScpValue
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import WriterTestCase, at, fresh_writer, local_call, location


def read_uint32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def parse(data: bytes) -> tuple:
    '''(parser, {name: function}) of compiled bytes'''
    parser, functions = ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False,
                                             quiet = True)
    return parser, {func.name: func for func in functions}


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
        self.writer.warn_unreachable_code = False       # B's skipped pushes are on purpose

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

        any_line = rf'^{re.escape(__file__)}:\d+: '
        for record, message in zip(logs.records, (
            "A: jumps to label 'in_b' in B (another function)",
            "B: jumps to label 'in_a' in A (another function)",
        ), strict = True):
            self.assertRegex(record.getMessage(), any_line + re.escape(message) + '$')

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
    '''A local call's record keeps its args up to the last one the author wrote: the CALL's debug_argc, else the
    compiler's rule - trailing constants equal to the callee's defaults dropped'''
    ALL_DEFAULTS = ((PUSH_INT, 2), (PUSH_INT, 1), (PUSH_INT, 5))    # Callee(5, 1, 2): pushed last parameter first

    def define_callee(self):
        @self.writer.LLILCode()
        def Callee(arg1: Value32, arg2: Value32 = 1, arg3: Nullable32 = 2):
            POP(3 * WORD_SIZE)
            RETURN()

        return Callee

    def counts(self, name: str = 'Main') -> list[int]:
        '''Each record's arg count, in record order'''
        return [len(record.args) for record in self.writer.functions_by_name[name].debug_records]

    def test_records_keep_the_args_up_to_the_last_one_written(self):
        @self.writer.LLILCode()
        def Callee(arg1: Value32, arg2: Value32 = 1, arg3: Nullable32 = 2.0):
            POP(3 * WORD_SIZE)
            RETURN()

        # (pushes of arg3 and arg2, the CALL's keywords) -> the record's arg count; arg1 is 5
        cases = {
            'every default left out': (((PUSH_FLOAT, 2.0), (PUSH_INT, 1)), {}, 1),
            'the last one differs': (((PUSH_FLOAT, 3.0), (PUSH_INT, 1)), {}, 3),
            'a differing one stops the walk': (((PUSH_FLOAT, 2.0), (PUSH_INT, 7)), {}, 2),
            'Integer for a Float default': (((PUSH_INT, 2), (PUSH_INT, 1)), {}, 3),
            'a non-constant is kept': (((GET_REG, 1), (PUSH_INT, 1)), {}, 3),
            'debug_argc keeps more': (((PUSH_FLOAT, 2.0), (PUSH_INT, 1)), {'debug_argc': 3}, 3),
            'debug_argc keeps none': (((PUSH_FLOAT, 2.0), (PUSH_INT, 1)), {'debug_argc': 0}, 0),
        }

        @self.writer.LLILCode()
        def Main():
            DEBUG_SET_LINENO(1)  # a call gets a debug record only after line info
            for number, (pushes, keywords, _) in enumerate(cases.values()):
                local_call(Callee, f'ret{number}', (*pushes, (PUSH_INT, 5)), **keywords)

            RETURN()

        self.writer.build({})
        callee = self.writer.functions_by_name['Callee']
        self.assertEqual({record.func_id for record in self.writer.functions_by_name['Main'].debug_records}, {callee.index})
        self.assertEqual(dict(zip(cases, self.counts())), {case: count for case, (*_, count) in cases.items()})

    def test_default_vectors(self):
        '''One entry per parameter, None without a default - the parser's shape; the file stores only the defaulted
        suffix'''
        @self.writer.LLILCode()
        def OneDefault(arg1: Value32, arg2: Value32 = 0):
            POP(2 * WORD_SIZE)
            RETURN()

        @self.writer.LLILCode()
        def AllDefaults(arg1: Value32 = 1, arg2: Nullable32 = 2.0):
            POP(2 * WORD_SIZE)
            RETURN()

        @self.writer.LLILCode()
        def NoDefaults(arg1: Value32, arg2: Value32):
            POP(2 * WORD_SIZE)
            RETURN()

        def typed(values) -> list:
            return [None if value is None else (value.type, value.value) for value in values]

        _, functions = parse(self.writer.build({}))
        expected = {'OneDefault': [None, 0], 'AllDefaults': [1, 2.0], 'NoDefaults': [None, None]}
        for name, values in expected.items():
            with self.subTest(name):
                vector = typed(self.writer._parameter_defaults(self.writer.functions_by_name[name]))
                self.assertEqual(vector, typed(None if value is None else ScpValue(value) for value in values))
                self.assertEqual(vector, typed(param.default_value for param in functions[name].params))

    def test_callee_defaults_from_its_registered_function(self):
        '''A callee defined after its caller, and one imported as a common function'''
        def Imported(arg1: Value32, arg2: Value32 = 1, arg3: Nullable32 = 2):
            POP(3 * WORD_SIZE)
            RETURN()

        @self.writer.CommonImports()
        def commonImports():
            return [Imported]

        @self.writer.LLILCode()
        def Main():
            DEBUG_SET_LINENO(1)
            local_call(Later, 'later', self.ALL_DEFAULTS)
            local_call(Imported, 'imported', self.ALL_DEFAULTS)
            RETURN()

        @self.writer.LLILCode()
        def Later(arg1: Value32, arg2: Value32 = 1, arg3: Nullable32 = 2):
            POP(3 * WORD_SIZE)
            RETURN()

        self.writer.build({})
        self.assertEqual(self.counts(), [1, 1])

    def test_an_edit_changes_no_other_record(self):
        '''Each count rides on its own CALL: renaming labels, deleting or inserting a call leaves the other records'''
        annotated = {'debug_argc': 3}
        variants = {
            'as decompiled': ((('a', {}), ('b', annotated), ('c', {})), [1, 3, 1]),
            'labels renamed': ((('x', {}), ('y', annotated), ('z', {})), [1, 3, 1]),
            'first call deleted': ((('b', annotated), ('c', {})), [3, 1]),
            'a call inserted': ((('a', {}), ('new', {}), ('b', annotated), ('c', {})), [1, 1, 3, 1]),
        }
        for variant, (calls, expected) in variants.items():
            with self.subTest(variant):
                self.writer = self.fresh_writer()
                callee = self.define_callee()

                @self.writer.LLILCode()
                def Main():
                    DEBUG_SET_LINENO(1)
                    for ret, keywords in calls:
                        local_call(callee, ret, self.ALL_DEFAULTS, **keywords)

                    RETURN()

                self.writer.build({})
                self.assertEqual(self.counts(), expected)

    def assert_warns_of_no_caller_frame(self, marker: str):
        '''Main compiles, and the tracker warns once, at the CALL_SCRIPT, that its debug record is a guess'''
        with self.assertLogs(log, 'WARNING') as logs:
            self.writer.build({})

        [message] = [record.getMessage() for record in logs.records]
        expected = ('CALL_SCRIPT this.Main: no caller frame below its arguments in address order - its debug record '
                    'is a guess')
        self.assertRegex(message, '^' + at(__file__, marker) + re.escape(f'Main: {expected}') + '$')

    def test_script_call_in_unreachable_code_without_a_caller_frame_warns(self):
        '''The compile check doesn't simulate unreachable code; its warning about it is off here'''
        self.writer.warn_unreachable_code = False

        @self.writer.LLILCode()
        def Main():
            DEBUG_SET_LINENO(1)
            RETURN()
            PUSH_INT(0)
            CALL_SCRIPT('this', 'Main', 1)  # line: unpaired
            RETURN()

        self.assert_warns_of_no_caller_frame('unpaired')

    def test_branch_inside_a_script_calls_arguments_warns(self):
        '''The tracker reads straight through both arms, so it holds an argument too many above the frame'''
        @self.writer.LLILCode()
        def Main():
            DEBUG_SET_LINENO(1)
            PUSH_CALLER_FRAME('back')
            PUSH_INT(1)
            POP_JMP_ZERO('else_')
            PUSH_INT(2)
            JMP('join')
            label('else_')
            PUSH_INT(3)
            label('join')
            CALL_SCRIPT('this', 'Main', 1)  # line: branched
            label('back')
            RETURN()

        self.assert_warns_of_no_caller_frame('branched')


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
            LOAD_GLOBAL('b')                        # line: unknown global
            RETURN()

        with self.assertRaisesRegex(ValueError, rf"^{at(__file__, 'unknown global')}Body: unknown global var 'b'; "
                                                r"declared: \['a'\]$"):
            self.writer.build({})

    def test_outside_the_block(self):
        '''A script's top level, and a hook's (it runs before create_scp_writer())'''
        for case in ('script', 'before create_scp_writer'):
            with self.subTest(case):
                if case == 'before create_scp_writer':
                    fresh_writer()

                with self.assertRaisesRegex(ValueError, OUTSIDE_THE_BLOCK):
                    GLOBAL_VAR('x', 1)

    def test_type_must_fit_an_unsigned_word(self):
        '''The table stores the type as an unsigned word; one outside it failed the write with a bare struct.error'''
        for type in (-1, 2 ** 32):
            with self.subTest(type):
                writer = self.fresh_writer()
                with self.assertRaisesRegex(ValueError, rf"^GLOBAL_VAR\('x'\) type is {type}, "
                                                        r"outside 0\.\.4294967295$"):
                    @writer.GlobalVars()
                    def globalvars():
                        GLOBAL_VAR('x', type)

        # The last type that fits compiles, with test_type_other_than_integer_or_string_warns's warning
        with self.assertLogs(log, 'WARNING') as logs:
            parser = self.compile_global(2 ** 32 - 1)

        self.assertEqual(parser.global_vars[0].type, 2 ** 32 - 1)
        self.assertEqual([record.getMessage() for record in logs.records],
                         ["GLOBAL_VAR('x') type is 4294967295, not 0 (Integer) or 1 (String)"])

    def test_type_other_than_integer_or_string_warns(self):
        '''The games declare only Integer and String globals; another type compiles as written, so a script that has
        one still round-trips'''
        for type in (0, 1, ScpGlobalVar.Type.Integer, ScpGlobalVar.Type.String):
            with self.subTest(type = repr(type)):
                with self.assertNoLogs(log, 'WARNING'):
                    parser = self.compile_global(type)

                self.assertEqual(parser.global_vars[0].type, type)

        with self.assertLogs(log, 'WARNING') as logs:
            parser = self.compile_global(2)

        self.assertEqual(parser.global_vars[0].type, 2)
        self.assertEqual([record.getMessage() for record in logs.records],
                         ["GLOBAL_VAR('x') type is 2, not 0 (Integer) or 1 (String)"])

    def compile_global(self, global_type: int):
        '''The parser of a compiled script whose one global var has global_type'''
        writer = self.fresh_writer()

        @writer.GlobalVars()
        def globalvars():
            GLOBAL_VAR('x', global_type)

        @writer.LLILCode()
        def Body():
            RETURN()

        parser, _ = parse(writer.build({}))
        return parser

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

        first_def = location(__file__, 'first block')
        with self.assertRaisesRegex(ValueError, rf"^{at(__file__, 'second block')}the global var table is already "
                                                rf"declared at {first_def}$"):
            @self.writer.GlobalVars()
            def second():                                   # line: second block
                GLOBAL_VAR('b', 1)


class TestGlobalVarOpcodes(WriterTestCase):
    def test_set_and_load_global_by_name_and_by_index(self):
        @self.writer.GlobalVars()
        def globalvars():
            GLOBAL_VAR('a', 1)
            GLOBAL_VAR('b', 1)

        @self.writer.LLILCode()
        def Body():
            PUSH_INT(1)
            SET_GLOBAL('b')
            PUSH_INT(2)
            SET_GLOBAL(0)
            LOAD_GLOBAL('a')
            SET_REG(0)
            LOAD_GLOBAL(1)
            SET_REG(0)
            RETURN()

        parser, functions = parse(self.writer.build({}))
        globals_used = [(inst.mnemonic, inst.operands[0].value) for inst in parser.get_instructions(functions['Body'])
                        if inst.opcode in (ED9Opcode.SET_GLOBAL, ED9Opcode.LOAD_GLOBAL)]

        self.assertEqual(globals_used, [('SET_GLOBAL', 1), ('SET_GLOBAL', 0), ('LOAD_GLOBAL', 0), ('LOAD_GLOBAL', 1)])


class TestOperandRanges(WriterTestCase):
    '''A global index must be in the declared table, and an operand out of its type's range (test_scp_writer_dsl.py's
    TestValueRanges) fails at its line'''

    def test_global_index_past_the_table_fails(self):
        for index in (0, 1):
            with self.subTest(index = index):
                self.writer = self.fresh_writer()

                @self.writer.GlobalVars()
                def globalvars():
                    GLOBAL_VAR('only', 1)

                @self.writer.LLILCode()
                def Main():
                    LOAD_GLOBAL(index)                  # line: global index
                    SET_REG(0)
                    RETURN()

                if index == 0:
                    parser, functions = parse(self.writer.build({}))
                    [load] = [inst for inst in parser.get_instructions(functions['Main'])
                              if inst.opcode == ED9Opcode.LOAD_GLOBAL]
                    self.assertEqual(load.operands[0].value, index)
                    continue

                with self.assertRaisesRegex(ValueError, rf'^{at(__file__, "global index")}Main: LOAD_GLOBAL operand 1 '
                                                        rf'is 1, outside 0\.\.0$'):
                    self.writer.build({})

    def test_global_index_without_declared_globals(self):
        @self.writer.LLILCode()
        def Main():
            LOAD_GLOBAL(0)                          # line: no globals
            SET_REG(0)
            RETURN()

        with self.assertRaisesRegex(ValueError, rf'^{at(__file__, "no globals")}Main: LOAD_GLOBAL operand 1 is 0, but '
                                                'no global vars are declared$'):
            self.writer.build({})

    def test_failure_names_its_line(self):
        '''POP(256) used to pop 0 and fail later, at the RETURN'''
        for case in ('SET_REG', 'POP', 'DEBUG_SET_LINENO'):
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
                def Main():
                    if case == 'SET_REG':
                        SET_REG(256)                # line: SET_REG

                    elif case == 'POP':
                        POP(256)                    # line: POP

                    else:
                        DEBUG_SET_LINENO(70000)     # line: DEBUG_SET_LINENO

                    RETURN()

                with self.assertRaisesRegex(ValueError, rf'^{at(__file__, case)}Main: {case} operand 1 is '):
                    self.writer.build({})

    def test_pushed_value_failure_names_its_line(self):
        '''A pushed value's encoding errors had no line, unlike an operand's'''
        class Kind(StrEnum):
            A = 'a'

        cases = {
            'PUSH_INT': (lambda: PUSH_INT(600000000), ValueError,
                         r'PUSH_INT Integer 600000000 is outside -536870912\.\.536870911: the game stores a signed '
                         r'30-bit value$'),
            'PUSH_RAW': (lambda: PUSH_RAW(RawInt(0x40000001)), ValueError,
                         r'PUSH_RAW RawInt 0x40000001 is outside 0\.\.0x3fffffff: '),
            'PUSH': (lambda: PUSH(600000000), ValueError, 'PUSH Integer 600000000 is outside '),
            'PUSH_FLOAT inf': (lambda: PUSH_FLOAT(math.inf), ValueError,
                               "PUSH_FLOAT non-finite float inf: the game can't use it$"),
            'PUSH_FLOAT past float32': (lambda: PUSH_FLOAT(3.5e38), ValueError,
                                        r"PUSH_FLOAT float 3\.5e\+38 is outside float32's range: "),
            'PUSH_STR str enum': (lambda: PUSH_STR(Kind.A), TypeError,
                                  'PUSH_STR ScpValue takes int, float, str or RawInt, not Kind: '),
        }
        for case, (push, error, message) in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
                def Main():
                    push()                                  # line: push
                    POP(WORD_SIZE)
                    RETURN()

                with self.assertRaisesRegex(error, rf'^{at(__file__, "push")}Main: {message}'):
                    self.writer.build({})


class TestArgumentTypes(WriterTestCase):
    '''A wrong argument type fails at its line (test_scp_writer_dsl.py's TestArgumentTypes has the texts); outside a
    function body it comes before the body check, with no prefix'''

    def test_type_error_names_its_line(self):
        cases = {
            'PUSH_INT type': r'PUSH_INT value is 5\.0 \(float\), not int',
            'SET_REG type': r'SET_REG index is 1\.0 \(float\), not int',
            'label type': r'label name is 5 \(int\), not str',
            'CALL by name': r"CALL takes the function itself, not 'Foo'",
        }
        for case, message in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
                def Main():
                    # An opcode on the line before: the message names the failing statement's own line
                    PUSH_INT(0)
                    if case == 'PUSH_INT type':
                        PUSH_INT(5.0)                                       # line: PUSH_INT type

                    elif case == 'SET_REG type':
                        SET_REG(1.0)                                        # line: SET_REG type

                    elif case == 'label type':
                        label(5)                                            # line: label type

                    else:
                        CALL('Foo')                                         # line: CALL by name

                    RETURN()

                with self.assertRaisesRegex(TypeError, rf'^{at(__file__, case)}Main: {message}$'):
                    self.writer.build({})

    def test_outside_a_body_the_type_error_comes_first(self):
        with self.assertRaisesRegex(TypeError, r'^PUSH_INT value is 5\.0 \(float\), not int$'):
            PUSH_INT(5.0)

        with self.assertRaisesRegex(TypeError, r'^PUSH_INT value is 5\.0 \(float\), not int$'):
            @self.writer.GlobalVars()
            def globalvars():
                PUSH_INT(5.0)

    def test_bool_and_an_unregistered_call_name_their_line(self):
        cases = {
            'bool': r'PUSH_INT takes no bool operand: True',
            'unregistered': r'CALL\(Unregistered\): no function of that name in this script - a library function must '
                            r'be listed in @scena\.CommonImports\(\), a script function needs @scena\.LLILCode\(\), a '
                            r'hook function @add_function',
        }
        for case, message in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                def Unregistered():
                    RETURN()

                @self.writer.LLILCode()
                def Main():
                    PUSH_INT(0)
                    if case == 'bool':
                        PUSH_INT(True)                                      # line: bool

                    else:
                        CALL(Unregistered)                                  # line: unregistered

                    RETURN()

                with self.assertRaisesRegex(TypeError, rf'^{at(__file__, case)}Main: {message}$'):
                    self.writer.build({})

    def test_debug_argc_is_exactly_an_int(self):
        '''Checked in CALL itself: bool is an int subclass, and handle_opcode's bool check sees positional operands only'''
        for case, value in {'bool': True, 'float': 2.0}.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
                def Callee():
                    RETURN()

                @self.writer.LLILCode()
                def Main():
                    PUSH_CURRENT_FUNC_ID()
                    PUSH_RET_ADDR('ret')
                    CALL(Callee, debug_argc = value)                    # line: debug_argc
                    label('ret')
                    RETURN()

                message = rf'CALL debug_argc is {re.escape(repr(value))} \({type(value).__name__}\), not int'
                with self.assertRaisesRegex(TypeError, rf'^{at(__file__, "debug_argc")}Main: {message}$'):
                    self.writer.build({})

    def test_debug_record_is_exactly_a_bool(self):
        for case, value in {'int': 0, 'None': None}.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
                def Callee():
                    RETURN()

                @self.writer.LLILCode()
                def Main():
                    PUSH_CURRENT_FUNC_ID()
                    PUSH_RET_ADDR('ret')
                    CALL(Callee, debug_record = value)                  # line: debug_record
                    label('ret')
                    RETURN()

                message = rf'CALL debug_record is {re.escape(repr(value))} \({type(value).__name__}\), not bool'
                with self.assertRaisesRegex(TypeError, rf'^{at(__file__, "debug_record")}Main: {message}$'):
                    self.writer.build({})


class TestStrings(WriterTestCase):
    '''A string the pool can't store fails where it enters (a default at its def: test_scp_writer_hooks.py's parameter
    tests): the game reads a pooled string up to its first NUL, and a lone surrogate can't be encoded (it used to fail
    writing the pool, after every body, with no script line)'''

    def test_code_string_fails_at_its_line(self):
        cases = {
            'PUSH_STR NUL': r"PUSH_STR string 'abc\x00def' contains a NUL, which ends a .dat string early",
            'PUSH_STR surrogate': r"PUSH_STR string 'bad\ud800char' can't be encoded: surrogates not allowed at "
                                  'position 3',
            'PUSH NUL': r"PUSH string 'a\x00' contains a NUL, which ends a .dat string early",
            'CALL_SCRIPT module NUL': r"CALL_SCRIPT string 'mod\x00' contains a NUL, which ends a .dat string early",
            'CALL_SCRIPT function surrogate': r"CALL_SCRIPT string 'f\udc80' can't be encoded: surrogates not allowed "
                                              'at position 1',
        }
        for case, message in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
                def Main():
                    # An opcode on the line before: the message names the failing opcode's own line
                    PUSH_CALLER_FRAME('back')
                    if case == 'PUSH_STR NUL':
                        PUSH_STR('abc\x00def')                              # line: PUSH_STR NUL

                    elif case == 'PUSH_STR surrogate':
                        PUSH_STR('bad\ud800char')                           # line: PUSH_STR surrogate

                    elif case == 'PUSH NUL':
                        PUSH('a\x00')                                       # line: PUSH NUL

                    elif case == 'CALL_SCRIPT module NUL':
                        CALL_SCRIPT('mod\x00', 'f', 0)                      # line: CALL_SCRIPT module NUL

                    else:
                        CALL_SCRIPT('mod', ScpValue('f\udc80'), 0)          # line: CALL_SCRIPT function surrogate

                    label('back')
                    RETURN()

                with self.assertRaisesRegex(ValueError, rf'^{at(__file__, case)}Main: {re.escape(message)}$'):
                    self.writer.build({})

    def test_global_var_name_fails(self):
        for name, message in (
            ('g\x00h', r"global var name 'g\x00h' contains a NUL, which ends a .dat string early"),
            ('g\ud800', r"global var name 'g\ud800' can't be encoded: surrogates not allowed at position 1"),
        ):
            with self.subTest(name = name):
                self.writer = self.fresh_writer()
                with self.assertRaisesRegex(ValueError, f'^{re.escape(message)}$'):
                    @self.writer.GlobalVars()
                    def globalvars():
                        GLOBAL_VAR(name, 1)


class TestWriterWithoutRoundTrip(WriterTestCase):
    '''scena.round_trip = False: equal strings share one pool entry and no debug records are written'''

    def define_repeating_strings(self):
        @self.writer.LLILCode()
        def Foo():
            PUSH_STR('same')
            PUSH_STR('same')
            POP(2 * WORD_SIZE)
            RETURN()

    def pushed_strings(self, data: bytes) -> list:
        parser, functions = parse(data)
        return [inst.operands[0].value for inst in parser.get_instructions(functions['Foo'])
                if inst.opcode == ED9Opcode.PUSH_STR]

    def test_equal_strings_share_one_pool_entry(self):
        self.writer.round_trip = False
        self.define_repeating_strings()
        data = self.writer.build({})

        self.assertEqual(data.count(b'same\x00'), 1)
        self.assertEqual(self.pushed_strings(data), ['same', 'same'])

    def test_round_trip_pools_every_string(self):
        self.define_repeating_strings()
        data = self.writer.build({})

        self.assertEqual(data.count(b'same\x00'), 2)
        self.assertEqual(self.pushed_strings(data), ['same', 'same'])

    def test_call_keywords_compile_to_the_same_bytes(self):
        '''No call is tracked, so a CALL's debug_argc or debug_record changes nothing: no records, the bytes of the
        call without it'''
        compiled = {}
        for case, keywords in {'debug_argc': {'debug_argc': 2}, 'debug_record': {'debug_record': False}, 'plain': {}}.items():
            self.writer = self.fresh_writer()
            self.writer.round_trip = False

            @self.writer.LLILCode()
            def Callee(arg1: Value32, arg2: Value32 = 0):
                POP(2 * WORD_SIZE)
                RETURN()

            @self.writer.LLILCode()
            def Main():
                DEBUG_SET_LINENO(1)
                local_call(Callee, 'ret', ((PUSH_INT, 0), (PUSH_INT, 1)), **keywords)
                RETURN()

            compiled[case] = self.writer.build({})
            self.assertEqual([f.debug_records for f in self.writer.functions], [[], []])

        self.assertEqual(compiled['debug_argc'], compiled['plain'])
        self.assertEqual(compiled['debug_record'], compiled['plain'])


class TestCheckOffLocations(WriterTestCase):
    '''With the compile check off there is no source map: messages name the function and nothing else'''

    def test_undefined_label_names_only_the_function(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def Foo():
            JMP('nowhere')
            RETURN()

        with self.assertRaisesRegex(ValueError, r"^Foo: undefined label 'nowhere'$"):
            writer.build({})

    def test_jump_into_another_function_warns_with_the_function_only(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def A():
            label('in_a')
            JMP('in_b')
            RETURN()

        @writer.LLILCode()
        def B():
            label('in_b')
            RETURN()

        with self.assertLogs(log, logging.WARNING) as logs:
            writer.build({})

        self.assertEqual([record.getMessage() for record in logs.records],
                         ["A: jumps to label 'in_b' in B (another function)"])

    def test_operand_out_of_range_names_only_the_function(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def Main():
            SET_REG(256)
            RETURN()

        with self.assertRaisesRegex(ValueError, r'^Main: SET_REG operand 1 is 256, outside 0\.\.255$'):
            writer.build({})

    def test_pushed_value_out_of_range_names_only_the_function(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def Main():
            PUSH_INT(600000000)
            POP(WORD_SIZE)
            RETURN()

        with self.assertRaisesRegex(ValueError, r'^Main: PUSH_INT Integer 600000000 is outside '
                                                r'-536870912\.\.536870911: the game stores a signed 30-bit value$'):
            writer.build({})

    def test_string_with_a_nul_names_only_the_function(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def Main():
            PUSH_STR('a\x00')
            POP(WORD_SIZE)
            RETURN()

        with self.assertRaisesRegex(ValueError, r"^Main: PUSH_STR string 'a\\x00' contains a NUL, which ends a \.dat "
                                                r'string early$'):
            writer.build({})

    def test_type_error_names_only_the_function(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def Main():
            PUSH_INT(5.0)
            RETURN()

        with self.assertRaisesRegex(TypeError, r'^Main: PUSH_INT value is 5\.0 \(float\), not int$'):
            writer.build({})


if __name__ == '__main__':
    unittest.main()
