#!/usr/bin/env python3
'''The writer's compile check (ScpWriter.check_compiled): compiled bytes must disassemble and lift again, and a failure
names the script line that emitted the failing opcode - or the failing function's def. Also the errors it maps
(ScpDisassemblyError, ED9LiftError), the def-line finder, and ScpParser.load_bytes / quiet.'''

from pathlib import Path
import importlib.util
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from common.logging import log
from ir.llil import WORD_SIZE
from falcom.ed9.ir.llil import ED9LiftError, ED9VMLifter
from falcom.ed9.parser.scp import ScpDisassemblyError, ScpParser
from falcom.ed9.scena2py import main
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_compile_check import CompileCheckError, definition_line
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import WriterTestCase

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


def define_wrong_pop(writer):
    @writer.LLILCode()
    def WrongPop(arg1: Value32, arg2: Value32):
        POP(WORD_SIZE)
        RETURN()                                    # line: wrong pop


def define_read_above(writer):
    @writer.LLILCode()
    def Above():
        LOAD_STACK(0)                               # line: above the stack
        POP(WORD_SIZE)
        RETURN()


class CheckTestCase(WriterTestCase):
    def assertCheckFails(self, message: str):
        '''run() raises a CompileCheckError matching message from its start and writes no .dat'''
        with self.assertRaisesRegex(CompileCheckError, f'^{message}'):
            self.writer.run({})

        self.assertFalse(self.dat.exists())

    def compiled(self, define) -> bytes:
        '''The bytes of a script compiled with the check off'''
        writer = self.fresh_writer(check = False)
        define(writer)
        return writer.build({})

    def load(self, data: bytes, **kwargs):
        return ScpParser.load_bytes(data, 'test.dat', round_trip = False, keep_unreachable_code = False, **kwargs)


class TestStackMistakes(CheckTestCase):
    def test_wrong_pop(self):
        define_wrong_pop(self.writer)
        self.assertCheckFails(rf"{at('wrong pop')}WrongPop: RETURN at {HEX}: the stack is not empty: \[param_0\]$")

    def test_build_runs_the_check(self):
        '''Every caller of build() gets the check, not only run()'''
        define_wrong_pop(self.writer)
        with self.assertRaisesRegex(CompileCheckError, rf"^{at('wrong pop')}WrongPop: "):
            self.writer.build({})

    def test_failure_leaves_an_older_dat_as_it_was(self):
        sentinel = b'older .dat' * 8
        self.dat.write_bytes(sentinel)
        define_wrong_pop(self.writer)

        with self.assertRaises(CompileCheckError):
            self.writer.run({})

        self.assertEqual(self.dat.read_bytes(), sentinel)

    def test_check_off_writes_the_dat(self):
        writer = self.fresh_writer(check = False)
        define_wrong_pop(writer)
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
        define_read_above(self.writer)
        self.assertCheckFails(rf"{at('above the stack')}Above: LOAD_STACK at {HEX}: addresses slot 0 \(above the stack\)$")

    def test_read_below_the_stack(self):
        '''The parser fails right there, without first logging the warning decompiling gives'''
        @self.writer.LLILCode()
        def Below(arg1: Value32):
            LOAD_STACK(-3 * WORD_SIZE)              # line: below the stack
            POP(2 * WORD_SIZE)
            RETURN()

        with self.assertNoLogs(log, 'WARNING'):
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


class TestRunOn(CheckTestCase):
    '''A function without RETURN runs on into the next function's code: a warning while that decompiles, a note on the
    error when it doesn't; the last function has nothing to run on into'''

    def define_runs_on(self, writer):
        @writer.LLILCode()
        def A():
            PUSH_INT(1)
            SET_REG(0)                              # line: runs on

    def assertCompilesWithWarning(self, message: str):
        '''run() writes the .dat and logs exactly one warning, matching message'''
        with self.assertLogs(log, 'WARNING') as logs:
            self.writer.run({})

        [warning] = [record.getMessage() for record in logs.records]
        self.assertRegex(warning, f'^{message}$')
        self.assertTrue(self.dat.exists())

    def test_warns_while_it_decompiles(self):
        self.define_runs_on(self.writer)

        @self.writer.LLILCode()
        def B():
            RETURN()

        self.assertCompilesWithWarning(rf"{at('runs on')}A: SET_REG at {HEX}: runs past its end into B without RETURN")

    def test_conditional_jump_falls_through_into_the_next_function(self):
        @self.writer.LLILCode()
        def A():
            label('top')
            PUSH_INT(0)
            POP_JMP_ZERO('top')                     # line: falls through

        @self.writer.LLILCode()
        def B():
            RETURN()

        self.assertCompilesWithWarning(rf"{at('falls through')}A: POP_JMP_ZERO at {HEX}: runs past its end into B without RETURN")

    def test_empty_function_warns_at_its_def(self):
        @self.writer.LLILCode()
        def AEmpty():                               # line: empty function
            pass

        @self.writer.LLILCode()
        def B():
            RETURN()

        self.assertCompilesWithWarning(rf"{at('empty function')}AEmpty: has no code, so it runs on into B without RETURN")

    def test_empty_function_sharing_a_start_with_a_run_on_gets_its_own_wording(self):
        @self.writer.LLILCode()
        def E():                                    # line: empty before a run-on
            pass

        @self.writer.LLILCode()
        def R():
            PUSH_INT(1)
            SET_REG(0)                              # line: shared start runs on

        @self.writer.LLILCode()
        def C():
            RETURN()

        with self.assertLogs(log, 'WARNING') as logs:
            self.writer.run({})

        warnings = [record.getMessage() for record in logs.records]
        self.assertEqual(len(warnings), 2, warnings)
        self.assertRegex(warnings[0], rf"^{at('empty before a run-on')}E: has no code, so it runs on into R without RETURN$")
        self.assertRegex(warnings[1], rf"^{at('shared start runs on')}R: SET_REG at {HEX}: runs past its end into C without RETURN$")

    def test_failure_gets_the_run_on_as_a_note(self):
        self.define_runs_on(self.writer)

        @self.writer.LLILCode()
        def B(arg1: Value32):
            POP(WORD_SIZE)                          # line: pop in B
            RETURN()

        self.assertCheckFails(rf"{at('pop in B')}A: POP at {HEX}: pops 1 entries, the stack has 0: \[\]; "
                              rf"{at('runs on')}A: SET_REG at {HEX}: runs past its end into B without RETURN$")

    def test_lift_failure_gets_the_run_on_as_a_note(self):
        self.define_runs_on(self.writer)

        @self.writer.LLILCode()
        def B():
            PUSH_INT(0)
            LOAD_STACK_DEREF(-WORD_SIZE)            # line: deref in B
            POP(2 * WORD_SIZE)
            RETURN()

        self.assertCheckFails(rf"{at('deref in B')}A: LOAD_STACK_DEREF at {HEX}: .*; "
                              rf"{at('runs on')}A: SET_REG at {HEX}: runs past its end into B without RETURN$")

    def test_last_function_fails_at_its_last_instruction(self):
        @self.writer.LLILCode()
        def Last():
            PUSH_INT(1)
            SET_REG(0)                              # line: last runs on

        self.assertCheckFails(rf"{at('last runs on')}Last: SET_REG at {HEX}: runs past the end of the code without RETURN$")

    def test_last_function_jumping_past_the_end_fails_at_the_jump(self):
        @self.writer.LLILCode()
        def Trailing():
            JMP('end')                              # line: jumps past the end
            label('end')

        self.assertCheckFails(rf"{at('jumps past the end')}Trailing: JMP at {HEX}: jumps to {HEX}, past the end of the "
                              r"code \(no RETURN after its label\)$")

    def test_running_into_the_last_function_fails_where_the_code_ends(self):
        '''No function's code may run past the end, not only the last function's own'''
        self.define_runs_on(self.writer)

        @self.writer.LLILCode()
        def ZLast():
            PUSH_INT(2)
            SET_REG(0)                              # line: code ends

        self.assertCheckFails(rf"{at('code ends')}A: SET_REG at {HEX}: runs past the end of the code without RETURN; "
                              rf"{at('runs on')}A: SET_REG at {HEX}: runs past its end into ZLast without RETURN$")

    def test_jumping_into_the_last_function_fails_where_the_code_ends(self):
        @self.writer.LLILCode()
        def A():
            JMP('in_last')

        @self.writer.LLILCode()
        def ZLast():
            label('in_last')
            PUSH_INT(2)
            SET_REG(0)                              # line: jumped-to code ends

        with self.assertLogs(log, 'WARNING'):       # the cross-function jump
            self.assertCheckFails(rf"{at('jumped-to code ends')}A: SET_REG at {HEX}: runs past the end of the code "
                                  r"without RETURN$")

    def test_return_label_at_the_end_fails_with_its_own_wording(self):
        def define_call(writer):
            @writer.LLILCode()
            def Callee():
                RETURN()

            @writer.LLILCode()
            def Caller():
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('back')
                CALL(Callee)                        # line: call returns past the end
                label('back')

            return 'CALL', 'call returns past the end'

        def define_call_script(writer):
            @writer.LLILCode()
            def Inner():
                RETURN()

            @writer.LLILCode()
            def Caller():
                PUSH_CALLER_FRAME('back')
                CALL_SCRIPT('this', 'Inner', 0)     # line: script call returns past the end
                label('back')

            return 'CALL_SCRIPT', 'script call returns past the end'

        for define in (define_call, define_call_script):
            for last in (True, False):
                with self.subTest(call = define.__name__, last = last):
                    writer = self.fresh_writer()
                    mnemonic, marker = define(writer)
                    if not last:
                        @writer.LLILCode()
                        def After():
                            RETURN()

                    message = rf'^{at(marker)}Caller: {mnemonic} at {HEX}: returns to {HEX}, past its end \(no RETURN'
                    with self.assertRaisesRegex(CompileCheckError, message):
                        writer.build({})

    def test_empty_last_function_points_at_its_def(self):
        @self.writer.LLILCode(debug_argc = {
            'unused': 1,
        })
        def Last():                                 # line: last def
            pass

        self.assertCheckFails(rf"{at('last def')}Last: has no code before the end of the code \(no RETURN\)$")

    def test_decompiling_records_it_without_a_failure(self):
        def define(writer):
            self.define_runs_on(writer)

            @writer.LLILCode()
            def B():
                RETURN()

        parser, functions = self.load(self.compiled(define))
        self.assertEqual({func.name: func.runs_on and func.runs_on.mnemonic for func in functions}, {'A': 'SET_REG', 'B': None})


class TestLocations(CheckTestCase):
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
    def test_parser_error_names_the_function_and_offset(self):
        data = self.compiled(define_wrong_pop)
        with self.assertRaises(ScpDisassemblyError) as raised:
            self.load(data, quiet = True)

        error = raised.exception
        self.assertEqual((error.function, str(error)),
                         ('WrongPop', f'WrongPop: RETURN at 0x{error.offset:X}: the stack is not empty: [param_0]'))

    def test_other_parser_error_is_wrapped_with_the_function(self):
        def define(writer):
            @writer.LLILCode()
            def Last():
                PUSH_INT(1)
                SET_REG(0)

        with self.assertRaises(ScpDisassemblyError) as raised:
            self.load(self.compiled(define), quiet = True)

        error = raised.exception
        self.assertEqual((error.function, error.offset), ('Last', None))
        self.assertRegex(str(error), r'^Last: Unknown opcode: 0x[0-9A-F]{2}$')
        self.assertIsInstance(error.__cause__, ValueError)

    def test_lift_error_names_the_function_and_instruction(self):
        data = self.compiled(define_read_above)
        with self.assertLogs(log, 'WARNING'):   # the parser's warning for the unusual slot
            parser, [func] = self.load(data)

        with self.assertRaises(ED9LiftError) as raised:
            ED9VMLifter(parser = parser).lift_function(func)

        error = raised.exception
        self.assertEqual((error.function, error.offset, error.mnemonic), ('Above', func.offset, 'LOAD_STACK'))
        self.assertEqual(str(error), f'Above: LOAD_STACK at 0x{func.offset:X}: Read of slot 0 at or above sp=0 is not '
                                     'supported - the slot holds no live value')
        self.assertIsInstance(error.__cause__, NotImplementedError)

    def test_decompiling_reports_the_new_types(self):
        '''scena2py's main() logs type(e).__name__: a file the parser rejects (ERROR, exit code 1), and a function the
        lifter rejects (WARNING, the file still decompiles)'''
        file_error = rf'^{re.escape(str(self.dat))}: ScpDisassemblyError: WrongPop: RETURN at {HEX}: the stack is not empty'
        lift_warning = rf'\[Above\]: ED9LiftError: Above: LOAD_STACK at {HEX}: Read of slot 0 at or above sp=0'

        for define, level, expected, exit_code in (
            (define_wrong_pop, 'ERROR', file_error, 1),
            (define_read_above, 'WARNING', lift_warning, 0),
        ):
            with self.subTest(define = define.__name__):
                self.dat.write_bytes(self.compiled(define))
                with (
                    mock.patch.object(sys, 'argv', ['scena2py', str(self.dat)]),
                    mock.patch.object(ScenaDecompileConfig, 'output_dir', self.tmp / 'out'),
                    self.assertLogs(log, level) as logs,
                ):
                    self.assertEqual(main(), exit_code)

                messages = [record.getMessage() for record in logs.records if record.levelname == level]
                self.assertTrue(any(re.search(expected, message) for message in messages), messages)


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
        self.dat.write_bytes(self.compiled(self.define))

        def listing(loaded) -> list:
            parser, functions = loaded
            return [(func.name, [(inst.offset, inst.mnemonic) for inst in parser.get_instructions(func)])
                    for func in functions]

        from_path = ScpParser.load(self.dat, round_trip = True, keep_unreachable_code = True)
        from_bytes = ScpParser.load_bytes(self.dat.read_bytes(), self.dat.name, round_trip = True,
                                          keep_unreachable_code = True)
        self.assertEqual(from_path[0].name, from_bytes[0].name)
        self.assertEqual(listing(from_path), listing(from_bytes))

    def test_quiet_drops_the_progress_and_error_lines(self):
        def define(writer):
            self.define(writer)
            define_wrong_pop(writer)

        data = self.compiled(define)
        lines = ['Disassembling Callee', 'Disassembling Caller', 'Disassembling WrongPop', 'Error disassembling WrongPop']
        for quiet, logged in ((False, lines), (True, [])):
            with self.subTest(quiet = quiet):
                # The load raises, so assertLogs only captures here (it checks nothing on an exception)
                with self.assertRaises(ScpDisassemblyError), self.assertLogs(log, 'INFO') as logs:
                    self.load(data, quiet = quiet)

                self.assertEqual([record.getMessage().split(' @ ')[0] for record in logs.records], logged)


if __name__ == '__main__':
    unittest.main()
