#!/usr/bin/env python3
'''Hook files (Step 10a): function callbacks and replace_function swap a function's body in place - position, table
index and common flag kept, the signature merged with the original's - and every error or compile-check failure in a
hook points at the hook's own line. Also the parameter-type check on every new function.'''

from pathlib import Path
import functools
import re
import runpy
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from common.logging import log
from ir.llil import WORD_SIZE
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer.scp_compile_check import CompileCheckError
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import WriterTestCase, load_module

HEX = '0x[0-9A-F]+'
SOURCE_LINES = Path(__file__).read_text(encoding = 'utf-8').splitlines()


def line_of(lines: list[str], marker: str) -> int:
    '''The line ending with the comment # line: <marker>'''
    [number] = [number for number, text in enumerate(lines, 1) if text.rstrip().endswith(f'# line: {marker}')]
    return number


def here(marker: str) -> str:
    '''A message prefix 'this file:line: ' for a marked line of this file, as a regex'''
    return re.escape(f'{__file__}:{line_of(SOURCE_LINES, marker)}: ')


class HookTestCase(WriterTestCase):
    def setUp(self):
        super().setUp()
        self.hook_count = 0

    def hook(self, source: str, future: bool = False):
        '''source run as a fresh hook module in the temp dir (future: under `from __future__ import annotations`); what
        it registers goes to self.writer'''
        self.hook_count += 1
        path = self.tmp / f'hook{self.hook_count}.py'
        header = ('from __future__ import annotations\n' if future else '') + 'from falcom.ed9.writer.scp_writer_helper import *\n'
        path.write_text(header + textwrap.dedent(source), encoding = 'utf-8')
        return load_module(path)

    def site(self, module, marker: str) -> str:
        ''''hook file:line' of a marked line of a hook'''
        path = Path(module.__file__)
        return f'{path}:{line_of(path.read_text(encoding = "utf-8").splitlines(), marker)}'

    def at(self, module, marker: str) -> str:
        '''A message prefix 'hook file:line: ' for a marked line of a hook, as a regex'''
        return re.escape(f'{self.site(module, marker)}: ')

    def parsed(self) -> dict:
        '''The script compiled and parsed again: name -> Function (self.parser holds the parse)'''
        self.parser, functions = ScpParser.load_bytes(self.writer.build({}), 'test.dat', round_trip = False,
                                                      keep_unreachable_code = False, quiet = True)
        return {func.name: func for func in functions}

    def mnemonics(self, func) -> list[str]:
        return [inst.mnemonic for inst in self.parser.get_instructions(func)]

    def signature(self, func) -> str:
        return str(func).splitlines()[0]

    def define_caller_and_callee(self):
        @self.writer.LLILCode()
        def Callee(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        @self.writer.LLILCode()
        def Caller():
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            PUSH_INT(1)
            CALL(Callee)
            label('ret')
            RETURN()

    def define_target(self):
        @self.writer.LLILCode()
        def Target(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()


PUSH_POP_RETURN = ['PUSH_INT', 'POP', 'RETURN']

REPLACE_CALLEE = '''
    @replace_function('Callee')
    def Callee(arg1):
        PUSH_INT(7)
        POP(2 * WORD_SIZE)
        RETURN()
'''


class TestReplace(HookTestCase):
    def test_body_swapped_in_place(self):
        self.define_caller_and_callee()
        before = self.parsed()

        self.writer = self.fresh_writer()
        self.define_caller_and_callee()
        self.hook(REPLACE_CALLEE)
        after = self.parsed()

        self.assertEqual(self.mnemonics(after['Callee']), PUSH_POP_RETURN)
        self.assertEqual({name: (func.index, func.is_common_func) for name, func in after.items()},
                         {name: (func.index, func.is_common_func) for name, func in before.items()})
        self.assertEqual(sorted(after, key = lambda name: after[name].offset), ['Callee', 'Caller'])
        [call] = [inst for inst in self.parser.get_instructions(after['Caller']) if inst.mnemonic == 'CALL']
        self.assertEqual(call.operands[0].value, after['Callee'].index)

    def test_common_function(self):
        def lib_common(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        @self.writer.CommonImports()
        def commonImports():
            return [lib_common]

        self.hook(REPLACE_CALLEE.replace('Callee', 'lib_common'))
        func = self.parsed()['lib_common']

        self.assertTrue(func.is_common_func)
        self.assertEqual(self.mnemonics(func), PUSH_POP_RETURN)

    def test_raw_callbacks_chain_and_match_patterns(self):
        @self.writer.LLILCode()
        def AniA():
            RETURN()

        @self.writer.LLILCode()
        def AniB():
            RETURN()

        @self.writer.LLILCode()
        def Other():
            RETURN()

        received = []

        def mark(name, func):
            if not name.startswith('Ani'):
                return None

            def marked():
                PUSH_INT(1)
                POP(WORD_SIZE)
                func()

            return marked

        def keep(name, func):
            received.append((name, func.__name__))
            return func

        registerFuncCallback(mark)
        registerFuncCallback(keep)

        with self.assertNoLogs(log, 'WARNING'):
            functions = self.parsed()

        self.assertEqual(received, [('AniA', 'marked'), ('AniB', 'marked'), ('Other', 'Other')])
        self.assertEqual({name: self.mnemonics(func) for name, func in functions.items()},
                         {'AniA': PUSH_POP_RETURN, 'AniB': PUSH_POP_RETURN, 'Other': ['RETURN']})

    def test_replaced_twice_warns_and_the_last_wins(self):
        self.define_caller_and_callee()
        with self.assertLogs(log, 'WARNING') as logs:
            hook = self.hook('''
                @replace_function('Callee')
                def Callee(arg1):                           # line: first
                    POP(WORD_SIZE)
                    RETURN()

                @replace_function('Callee')
                def Callee(arg1):                           # line: second
                    PUSH_INT(7)
                    POP(2 * WORD_SIZE)
                    RETURN()
            ''')

        [warning] = [record.getMessage() for record in logs.records]
        self.assertEqual(warning, f"{self.site(hook, 'second')}: replace_function('Callee') again, overriding the one at "
                                  f"{self.site(hook, 'first')}")
        self.assertEqual(self.mnemonics(self.parsed()['Callee']), PUSH_POP_RETURN)

    def test_unknown_name_points_at_the_hook(self):
        self.define_caller_and_callee()
        hook = self.hook('''
            @replace_function('Calee')
            def Calee(arg1):                                # line: misspelled
                RETURN()
        ''')

        with self.assertRaisesRegex(ValueError, rf"^{self.at(hook, 'misspelled')}replace_function\('Calee'\): the script has "
                                                rf"no function 'Calee'$"):
            self.writer.run({})

        self.assertFalse(self.dat.exists())

    def test_debug_argc_cleared(self):
        '''The original's record trimming is keyed by its return labels, which a copied body reuses for other calls'''
        @self.writer.LLILCode()
        def Callee(arg1: Value32, arg2: Value32):
            POP(2 * WORD_SIZE)
            RETURN()

        @self.writer.LLILCode(debug_argc = {'ret': 1})
        def Caller():
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            PUSH_INT(1)
            PUSH_INT(2)
            CALL(Callee)
            label('ret')
            RETURN()

        @replace_function('Caller')
        def Copied():
            DEBUG_SET_LINENO(1)                     # call records start at a function's first line number
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            PUSH_INT(3)
            PUSH_INT(4)
            CALL(Callee)
            label('ret')
            RETURN()

        self.writer.build({})

        [record] = self.writer.functions_by_name['Caller'].debug_records
        self.assertEqual(len(record.args), 2)

    def test_hook_imported_before_the_writer_exists(self):
        '''The generated script's own order: the hook import comes before create_scp_writer()'''
        script = self.tmp / 'e2e.py'
        script.write_text(textwrap.dedent(f'''
            from falcom.ed9.writer.scp_writer_helper import *
            import e2e_hook

            scena = create_scp_writer({str(self.dat)!r})

            @scena.LLILCode()
            def Callee(arg1: Value32):
                POP(WORD_SIZE)
                RETURN()

            scena.run(globals())
        '''), encoding = 'utf-8')
        (self.tmp / 'e2e_hook.py').write_text('from falcom.ed9.writer.scp_writer_helper import *\n'
                                              + textwrap.dedent(REPLACE_CALLEE), encoding = 'utf-8')
        sys.path.insert(0, str(self.tmp))
        self.addCleanup(sys.path.remove, str(self.tmp))
        self.addCleanup(sys.modules.pop, 'e2e_hook', None)

        runpy.run_path(str(script), run_name = '__main__')

        self.parser, [func] = ScpParser.load(self.dat, round_trip = False, keep_unreachable_code = False)
        self.assertEqual(self.mnemonics(func), PUSH_POP_RETURN)


class TestRejected(HookTestCase):
    def test_not_a_plain_function(self):
        def body(arg1):
            RETURN()

        with self.assertRaisesRegex(TypeError, '^registerFuncCallback: expected a plain function'):
            registerFuncCallback(functools.partial(body))

        with self.assertRaisesRegex(TypeError, r"^replace_function\('Target'\): expected a plain function"):
            replace_function('Target')(functools.partial(body))

    def test_callback_returning_a_non_function_points_at_the_callback(self):
        self.define_target()
        hook = self.hook('''
            import functools

            def body(arg1):
                RETURN()

            def to_partial(name, func):                     # line: partial
                return functools.partial(body)

            registerFuncCallback(to_partial)
        ''')

        with self.assertRaisesRegex(TypeError, rf"^{self.at(hook, 'partial')}to_partial for Target: expected a plain "
                                               "function"):
            self.writer.build({})

    def test_callback_registering_a_function(self):
        self.define_target()
        hook = self.hook('''
            def adds(name, func):                           # line: adds
                def Extra():
                    RETURN()

                get_scp_writer().LLILCode()(Extra)

            registerFuncCallback(adds)
        ''')

        with self.assertRaisesRegex(ValueError, rf"^{self.at(hook, 'adds')}a function callback can't register functions$"):
            self.writer.build({})

    def test_parameter_count_and_kinds(self):
        cases = {
            'count': ('def Target(arg1, arg2):', 'Target takes 1 parameters, its replacement 2$'),
            'args': ('def Target(*args):', r"Target's replacement can't take \*args, keyword-only or \*\*kwargs "
                                           r'parameters \(args\); a wrapper keeps the replaced signature with functools.wraps$'),
            'keyword-only': ('def Target(arg1, *, flag):', r"Target's replacement can't take .* \(flag\);"),
        }
        for case, (definition, message) in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()
                self.define_target()
                hook = self.hook(f'''
                    @replace_function('Target')
                    {definition}                                # line: def
                        RETURN()
                ''')

                with self.assertRaisesRegex(TypeError, f"^{self.at(hook, 'def')}{message}"):
                    self.writer.build({})

    def test_parameter_without_a_type(self):
        with self.assertRaisesRegex(TypeError, rf"^{here('no type')}parameter arg2 of NoType needs a type: Value32, "
                                               'Nullable32, str, NullableStr or Pointer$'):
            @self.writer.LLILCode()
            def NoType(arg1: Value32, arg2):                # line: no type
                RETURN()


class TestSignatures(HookTestCase):
    def test_merged_with_the_original(self):
        '''Per parameter, the replacement's type or default wins where it gives one, else the original's: arg1 keeps
        its type, arg2 changes type and keeps its default, arg3 and arg4 change default, and Added gains one'''
        @self.writer.LLILCode()
        def Target(arg1: Value32, arg2: Nullable32 = 2, arg3: Value32 = 3, arg4: Value32 = 4):
            POP(4 * WORD_SIZE)
            RETURN()

        @self.writer.LLILCode()
        def Added(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        self.hook('''
            @replace_function('Target')
            def Target(a, b: Value32, c = 30, d = 40):
                POP(4 * WORD_SIZE)
                RETURN()

            @replace_function('Added')
            def Added(a: Nullable32 = 5):
                POP(WORD_SIZE)
                RETURN()
        ''')
        functions = self.parsed()

        self.assertEqual(self.signature(functions['Target']), 'Target(Value32, Value32 = 2, Value32 = 30, Value32 = 40)')
        self.assertEqual(self.signature(functions['Added']), 'Added(Nullable32 = 5)')

    def test_postponed_annotations(self):
        '''from __future__ import annotations makes annotations strings, for a replacement and a new function alike'''
        self.define_target()
        self.hook('''
            @replace_function('Target')
            def Target(arg1: Nullable32):
                POP(WORD_SIZE)
                RETURN()

            @get_scp_writer().LLILCode()
            def New(arg1: NullableStr):
                POP(WORD_SIZE)
                RETURN()
        ''', future = True)
        functions = self.parsed()

        self.assertEqual(self.signature(functions['Target']), 'Target(Nullable32)')
        self.assertEqual(self.signature(functions['New']), 'New(NullableStr)')


class TestLocations(HookTestCase):
    def test_replacement_failure_points_at_the_hook(self):
        self.define_target()
        hook = self.hook('''
            @replace_function('Target')
            def Target(arg1):
                POP(2 * WORD_SIZE)                          # line: bad pop
                RETURN()
        ''')

        with self.assertRaisesRegex(CompileCheckError, rf"^{self.at(hook, 'bad pop')}Target: POP at {HEX}: "):
            self.writer.build({})

    def test_wrapper_halves_point_at_their_own_lines(self):
        '''A functools.wraps wrapper's own opcodes map to the wrapper, the body it inlines to that body'''
        cases = {'wrapper': (3 * WORD_SIZE, 2 * WORD_SIZE), 'inlined': (WORD_SIZE, 3 * WORD_SIZE)}
        for case, (wrapper_pop, original_pop) in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()
                writer = self.writer

                @writer.LLILCode()
                def Target(arg1: Value32):
                    PUSH_INT(1)
                    POP(original_pop)                       # line: original pop
                    RETURN()

                hook = self.hook(f'''
                    import functools

                    def wrap(name, func):
                        @functools.wraps(func)
                        def wrapper(*args):
                            PUSH_INT(1)
                            POP({wrapper_pop})                 # line: wrapper pop
                            func(*args)

                        return wrapper

                    registerFuncCallback(wrap)
                ''')
                expected = self.at(hook, 'wrapper pop') if case == 'wrapper' else here('original pop')

                with self.assertRaisesRegex(CompileCheckError, rf'^{expected}Target: POP at {HEX}: '):
                    self.writer.build({})

    def test_decorated_body_points_at_its_own_line(self):
        '''A body wrapped by a functools.wraps decorator maps to the body, not to the decorator's call'''
        def traced(body):
            @functools.wraps(body)
            def wrapper(*args):
                body(*args)

            return wrapper

        @self.writer.LLILCode()
        @traced
        def Decorated(arg1: Value32):
            POP(2 * WORD_SIZE)                      # line: decorated body
            RETURN()

        with self.assertRaisesRegex(CompileCheckError, rf"^{here('decorated body')}Decorated: POP at {HEX}: "):
            self.writer.build({})

    def test_middle_of_a_chain_points_at_its_own_line(self):
        '''Two raw wrappers without functools.wraps around one function: the middle one's mistake is its own line'''
        self.define_target()
        hook = self.hook('''
            def shared(name, func):
                def traced(arg1):
                    POP(2 * WORD_SIZE)                      # line: middle
                    func(arg1)

                return traced

            def local(name, func):
                def buffed(arg1):
                    func(arg1)                              # line: outer call

                return buffed

            registerFuncCallback(shared)
            registerFuncCallback(local)
        ''')

        with self.assertRaisesRegex(CompileCheckError, rf"^{self.at(hook, 'middle')}Target: "):
            self.writer.build({})


if __name__ == '__main__':
    unittest.main()
