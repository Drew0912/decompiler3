#!/usr/bin/env python3
'''The writer's compile check (ScpWriter.check_compiled): compiled bytes must disassemble and lift again, and a failure
names the script line that emitted the failing opcode - or the failing function's def. Also the errors it maps
(ScpDisassemblyError, ED9LiftError), the def-line finder, and ScpParser.load_bytes / quiet.'''

from pathlib import Path
import importlib.util
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from common.logging import log
from ir.llil import WORD_SIZE
from falcom.ed9.ir.llil import ED9LiftError, ED9VMLifter
from falcom.ed9.parser.scp import ScpDisassemblyError, ScpParser
from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_compile_check import CompileCheckError, definition_line
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import fresh_writer

SOURCE_LINES = Path(__file__).read_text(encoding = 'utf-8').splitlines()
HEX = '0x[0-9A-F]+'

LIBRARY_SOURCE = '''from falcom.ed9.writer.scp_writer_helper import *


def lib_unbalanced(arg1: Value32):
    RETURN()
'''
LIBRARY_RETURN_LINE = 5


def marked_line(marker: str) -> int:
    '''The line of this file that ends with the comment # line: <marker>'''
    [number] = [number for number, text in enumerate(SOURCE_LINES, 1) if text.rstrip().endswith(f'# line: {marker}')]
    return number


def at(marker: str) -> str:
    '''A message prefix 'this file:line: ' for a marked line, as a regex'''
    return re.escape(f'{__file__}:{marked_line(marker)}: ')


def decorate(**kwargs):
    return lambda func: func


@decorate()
def one_line_decorator():                   # line: one-line decorator
    pass


@decorate(table = {
    'a': 1,
    'b': 2,
})
def multi_line_decorator():                 # line: multi-line decorator
    pass


@decorate(text = '''
def not_this(): pass
''')
def string_in_decorator():                  # line: string in decorator
    pass


@decorate()
# a comment between
async def async_function():                 # line: async function
    pass


def undecorated():                          # line: undecorated
    pass


LAMBDA = lambda: None                       # line: lambda


class CheckTestCase(unittest.TestCase):
    '''A fresh writer with the check on that compiles into a temp dir'''

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.dat = self.tmp / 'test.dat'
        self.writer = self.fresh_writer()

    def fresh_writer(self, check: bool = True):
        fresh_writer()
        writer = create_scp_writer(str(self.dat))
        writer.check_compiled = check
        return writer

    def assertCheckFails(self, message: str):
        '''run() raises a CompileCheckError matching message from its start and writes no .dat'''
        with self.assertRaisesRegex(CompileCheckError, f'^{message}'):
            self.writer.run({})

        self.assertFalse(self.dat.exists())


class TestStackMistakes(CheckTestCase):
    def define_wrong_pop(self, writer):
        @writer.LLILCode()
        def WrongPop(arg1: Value32, arg2: Value32):
            POP(WORD_SIZE)
            RETURN()                                # line: wrong pop

    def test_wrong_pop(self):
        self.define_wrong_pop(self.writer)
        self.assertCheckFails(rf"{at('wrong pop')}WrongPop: RETURN at {HEX}: the stack is not empty: \[param_0\]$")

    def test_failure_leaves_an_older_dat_as_it_was(self):
        sentinel = b'older .dat' * 8
        self.dat.write_bytes(sentinel)
        self.define_wrong_pop(self.writer)

        with self.assertRaises(CompileCheckError):
            self.writer.run({})

        self.assertEqual(self.dat.read_bytes(), sentinel)

    def test_check_off_writes_the_dat(self):
        writer = self.fresh_writer(check = False)
        self.define_wrong_pop(writer)
        writer.run({})

        self.assertTrue(self.dat.exists())

    def test_extra_call_argument(self):
        @self.writer.LLILCode()
        def Callee(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        @self.writer.LLILCode()
        def Caller():
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            PUSH_INT(1)
            PUSH_INT(2)
            CALL(Callee)                            # line: extra argument
            label('ret')
            RETURN()

        self.assertCheckFails(rf"{at('extra argument')}Caller: CALL at {HEX}: expects a return address")

    def test_read_above_the_stack(self):
        @self.writer.LLILCode()
        def Above():
            LOAD_STACK(0)                           # line: above the stack
            POP(WORD_SIZE)
            RETURN()

        self.assertCheckFails(rf"{at('above the stack')}Above: LOAD_STACK at {HEX}: addresses slot 0 \(above the stack\)$")

    def test_read_below_the_stack(self):
        @self.writer.LLILCode()
        def Below(arg1: Value32):
            LOAD_STACK(-3 * WORD_SIZE)              # line: below the stack
            POP(2 * WORD_SIZE)
            RETURN()

        self.assertCheckFails(rf"{at('below the stack')}Below: LOAD_STACK at {HEX}: addresses slot -2 \(below the stack\)$")

    def test_dead_store_is_rejected(self):
        '''Decompiling keeps it as a dead store; the check treats it as the mistake it almost always is'''
        @self.writer.LLILCode()
        def SetArg(arg1: Value32):
            PUSH_INT(1)
            POP_TO(0)                               # line: dead store
            LOAD_STACK(-WORD_SIZE)
            SET_REG(0)
            POP(WORD_SIZE)
            RETURN()

        self.assertCheckFails(rf"{at('dead store')}SetArg: POP_TO at {HEX}: addresses slot 1 \(above the stack\)$")

    def test_unreachable_code_is_not_checked(self):
        @self.writer.LLILCode()
        def Dead():
            JMP('dead_end')
            POP(WORD_SIZE)
            label('dead_end')
            RETURN()

        self.writer.run({})

        self.dat.unlink()
        self.writer = self.fresh_writer()

        @self.writer.LLILCode()
        def Live():
            POP(WORD_SIZE)                          # line: reachable pop
            RETURN()

        self.assertCheckFails(rf"{at('reachable pop')}Live: POP at {HEX}: pops 1 entries, the stack has 0")


class TestLocations(CheckTestCase):
    def test_missing_return_in_the_last_function_points_at_its_def(self):
        @self.writer.LLILCode(debug_argc = {
            'unused': 1,
        })
        def Last():                                 # line: last def
            PUSH_INT(1)
            SET_REG(0)

        self.assertCheckFails(rf"{at('last def')}Last: ")

    def test_library_body_points_at_its_own_file(self):
        library = self.tmp / 'step9_library.py'
        library.write_text(LIBRARY_SOURCE, encoding = 'utf-8')
        spec = importlib.util.spec_from_file_location('step9_library', library)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        @self.writer.CommonImports()
        def commonImports():
            return [module.lib_unbalanced]

        self.assertCheckFails(rf"{re.escape(f'{library}:{LIBRARY_RETURN_LINE}: ')}lib_unbalanced: RETURN at {HEX}: ")

    def test_helper_maps_to_the_calling_line(self):
        def pop_twice():
            POP(WORD_SIZE)
            POP(WORD_SIZE)

        @self.writer.LLILCode()
        def Caller(arg1: Value32):
            pop_twice()                             # line: helper call
            RETURN()

        self.assertCheckFails(rf"{at('helper call')}Caller: POP at {HEX}: pops 1 entries, the stack has 0")

    def test_failure_reached_through_a_cross_function_jump_points_into_the_other_function(self):
        @self.writer.LLILCode()
        def A():
            JMP('in_b')

        @self.writer.LLILCode()
        def B(arg1: Value32):
            label('in_b')
            POP(WORD_SIZE)                          # line: shared pop
            RETURN()

        with self.assertLogs(log, 'WARNING'):
            self.assertCheckFails(rf"{at('shared pop')}A: POP at {HEX}: pops 1 entries, the stack has 0")

    def test_valid_cross_function_jump_passes_and_its_warning_has_a_line(self):
        @self.writer.LLILCode()
        def A():
            JMP('in_b')                             # line: cross-function jump

        @self.writer.LLILCode()
        def B():
            label('in_b')
            RETURN()

        with self.assertLogs(log, 'WARNING') as logs:
            self.writer.run({})

        self.assertRegex(logs.records[0].getMessage(), rf"^{at('cross-function jump')}A: jumps to label 'in_b' in B")
        self.assertTrue(self.dat.exists())

    def test_equal_starts(self):
        '''An empty function starts where the next one does: the failing opcode still maps to its own line'''
        @self.writer.LLILCode()
        def AEmpty():
            pass

        @self.writer.LLILCode()
        def ZBody(arg1: Value32):
            RETURN()                                # line: equal starts

        self.assertCheckFails(rf"{at('equal starts')}ZBody: RETURN at {HEX}: the stack is not empty")

    def test_undefined_label_points_at_its_line(self):
        def define_jump(writer):
            @writer.LLILCode()
            def First():
                RETURN()

            @writer.LLILCode()
            def Jumps():
                JMP('nowhere')                      # line: undefined jump
                RETURN()

            return 'Jumps', 'nowhere', 'undefined jump'

        def define_return_address(writer):
            @writer.LLILCode()
            def First():
                RETURN()

            @writer.LLILCode()
            def Calls():
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('missing')            # line: undefined return
                CALL(First)
                RETURN()

            return 'Calls', 'missing', 'undefined return'

        for define in (define_jump, define_return_address):
            with self.subTest(encoding = define.__name__):
                writer = self.fresh_writer()
                function, name, marker = define(writer)

                with self.assertRaisesRegex(ValueError, rf"^{at(marker)}{function}: undefined label '{name}'$"):
                    writer.build({})


class TestDefinitionLine(unittest.TestCase):
    def test_past_the_decorators(self):
        for func, marker in (
            (one_line_decorator, 'one-line decorator'),
            (multi_line_decorator, 'multi-line decorator'),
            (string_in_decorator, 'string in decorator'),
            (async_function, 'async function'),
            (undecorated, 'undecorated'),
        ):
            with self.subTest(function = func.__name__):
                self.assertEqual(definition_line(func.__code__), marked_line(marker))

    def test_nested(self):
        @decorate(table = {
            'a': 1,
        })
        def nested():                               # line: nested
            pass

        self.assertEqual(definition_line(nested.__code__), marked_line('nested'))

    def test_first_line_when_there_is_no_def(self):
        namespace = {}
        exec(compile('def from_string():\n    pass\n', '<string>', 'exec'), namespace)

        for code in (LAMBDA.__code__, namespace['from_string'].__code__):
            with self.subTest(function = code.co_name):
                self.assertEqual(definition_line(code), code.co_firstlineno)


class TestErrors(CheckTestCase):
    def compiled(self, define) -> bytes:
        '''The bytes of a script compiled with the check off'''
        writer = self.fresh_writer(check = False)
        define(writer)
        return writer.build({})

    def test_parser_error_names_the_function_and_offset(self):
        def define(writer):
            @writer.LLILCode()
            def WrongPop(arg1: Value32):
                RETURN()

        data = self.compiled(define)
        with self.assertRaises(ScpDisassemblyError) as raised:
            ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False, quiet = True)

        error = raised.exception
        self.assertEqual((error.function, str(error)), ('WrongPop', f'WrongPop: RETURN at 0x{error.offset:X}: the stack is not empty: [param_0]'))

    def test_other_parser_error_is_wrapped_with_the_function(self):
        def define(writer):
            @writer.LLILCode()
            def Last():
                PUSH_INT(1)
                SET_REG(0)

        data = self.compiled(define)
        with self.assertRaises(ScpDisassemblyError) as raised:
            ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False, quiet = True)

        error = raised.exception
        self.assertEqual((error.function, error.offset), ('Last', None))
        self.assertRegex(str(error), r'^Last: Unknown opcode: 0x[0-9A-F]{2}$')
        self.assertIsInstance(error.__cause__, ValueError)

    def test_lift_error_names_the_function_and_instruction(self):
        def define(writer):
            @writer.LLILCode()
            def Above():
                LOAD_STACK(0)
                POP(WORD_SIZE)
                RETURN()

        data = self.compiled(define)
        with self.assertLogs(log, 'WARNING'):   # the parser's warning for the unusual slot
            parser, [func] = ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False)

        with self.assertRaises(ED9LiftError) as raised:
            ED9VMLifter(parser = parser).lift_function(func)

        error = raised.exception
        self.assertEqual((error.function, error.offset, error.mnemonic), ('Above', func.offset, 'LOAD_STACK'))
        self.assertEqual(str(error), f'Above: LOAD_STACK at 0x{func.offset:X}: Read of slot 0 at or above sp=0 is not '
                                     'supported - the slot holds no live value')
        self.assertIsInstance(error.__cause__, NotImplementedError)

    def test_decompiling_reports_the_new_types(self):
        '''scena2py prints type(e).__name__: a file the parser rejects, and a function the lifter rejects'''
        config = ScenaDecompileConfig()
        config.output_dir = self.tmp / 'out'

        def wrong_pop(writer):
            @writer.LLILCode()
            def WrongPop(arg1: Value32):
                RETURN()

        def read_above(writer):
            @writer.LLILCode()
            def Above():
                LOAD_STACK(0)
                POP(WORD_SIZE)
                RETURN()

        self.dat.write_bytes(self.compiled(wrong_pop))
        with self.assertRaises(ScpDisassemblyError) as raised, self.assertLogs(log, 'ERROR'):
            process_file(self.dat, config)

        self.assertRegex(f'{type(raised.exception).__name__}: {raised.exception}',
                         rf'^ScpDisassemblyError: WrongPop: RETURN at {HEX}: the stack is not empty')

        self.dat.write_bytes(self.compiled(read_above))
        with self.assertLogs(log, 'WARNING') as logs:
            process_file(self.dat, config)

        [lift_warning] = [record.getMessage() for record in logs.records if 'ED9LiftError' in record.getMessage()]
        self.assertRegex(lift_warning, rf'\[Above\]: ED9LiftError: Above: LOAD_STACK at {HEX}: Read of slot 0 at or above sp=0')


class TestLoadBytes(CheckTestCase):
    def define(self, writer):
        @writer.LLILCode()
        def Callee(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        @writer.LLILCode()
        def Caller():
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            PUSH_INT(1)
            CALL(Callee)
            label('ret')
            RETURN()

    def test_same_as_load(self):
        writer = self.fresh_writer(check = False)
        self.define(writer)
        writer.run({})

        def listing(loaded) -> list:
            parser, functions = loaded
            return [(func.name, [(inst.offset, inst.mnemonic) for inst in parser.get_instructions(func)]) for func in functions]

        from_path = ScpParser.load(self.dat, round_trip = True, keep_unreachable_code = True)
        from_bytes = ScpParser.load_bytes(self.dat.read_bytes(), self.dat.name, round_trip = True, keep_unreachable_code = True)
        self.assertEqual(from_path[0].name, from_bytes[0].name)
        self.assertEqual(listing(from_path), listing(from_bytes))

    def test_quiet_drops_the_progress_lines(self):
        writer = self.fresh_writer(check = False)
        self.define(writer)
        data = writer.build({})

        for quiet, logged in ((False, ['Disassembling Callee', 'Disassembling Caller']), (True, [])):
            with self.subTest(quiet = quiet):
                with mock.patch.object(log, 'info') as info:
                    ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False, quiet = quiet)

                self.assertEqual([call.args[0].split(' @ ')[0] for call in info.call_args_list], logged)

    def test_quiet_drops_the_error_line(self):
        writer = self.fresh_writer(check = False)

        @writer.LLILCode()
        def WrongPop(arg1: Value32):
            RETURN()

        data = writer.build({})
        for quiet, logged in ((False, ['Error disassembling WrongPop']), (True, [])):
            with self.subTest(quiet = quiet):
                with self.assertRaises(ScpDisassemblyError), mock.patch.object(log, 'error') as error:
                    ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False, quiet = quiet)

                self.assertEqual([call.args[0].split(' @ ')[0] for call in error.call_args_list], logged)


if __name__ == '__main__':
    unittest.main()
