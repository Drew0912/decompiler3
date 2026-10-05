#!/usr/bin/env python3
'''Hook files (Step 10a): function callbacks and replace_function swap a function's body in place - position, table
index and common flag kept, the signature merged with the original's - and every error or compile-check failure in a
hook points at the hook's own line. Also the parameter checks on every new function.'''

from pathlib import Path
import functools
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
from scp_writer_test_utils import WriterTestCase, at, load_module, marked_line

HEX = '0x[0-9A-F]+'
PUSH_POP_RETURN = ['PUSH_INT', 'POP', 'RETURN']

REPLACE_TARGET = '''
    @replace_function('Target')
    def Target(arg1):
        PUSH_INT(7)
        POP(2 * WORD_SIZE)
        RETURN()
'''


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

    def parsed(self) -> dict:
        '''The script compiled and parsed again: name -> Function (self.parser holds the parse)'''
        self.parser, functions = ScpParser.load_bytes(self.writer.build({}), 'test.dat', round_trip = False,
                                                      keep_unreachable_code = False, quiet = True)
        return {func.name: func for func in functions}

    def mnemonics(self, func) -> list[str]:
        return [inst.mnemonic for inst in self.parser.get_instructions(func)]

    def signature(self, func) -> str:
        return str(func).splitlines()[0]

    def define_target(self):
        @self.writer.LLILCode()
        def Target(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        return Target

    def define_caller_and_target(self):
        target = self.define_target()

        @self.writer.LLILCode()
        def Caller():
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR('ret')
            PUSH_INT(1)
            CALL(target)
            label('ret')
            RETURN()


class TestReplace(HookTestCase):
    def test_body_swapped_in_place(self):
        self.define_caller_and_target()
        self.hook(REPLACE_TARGET)
        functions = self.parsed()

        self.assertEqual(self.mnemonics(functions['Target']), PUSH_POP_RETURN)
        self.assertEqual({name: (func.index, func.is_common_func) for name, func in functions.items()},
                         {'Caller': (0, False), 'Target': (1, False)})
        self.assertEqual(sorted(functions, key = lambda name: functions[name].offset), ['Target', 'Caller'])
        [call] = [inst for inst in self.parser.get_instructions(functions['Caller']) if inst.mnemonic == 'CALL']
        self.assertEqual(call.operands[0].value, functions['Target'].index)

    def test_common_function(self):
        def lib_common(arg1: Value32):
            POP(WORD_SIZE)
            RETURN()

        @self.writer.CommonImports()
        def commonImports():
            return [lib_common]

        self.hook(REPLACE_TARGET.replace('Target', 'lib_common'))
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

    def test_hook_functions_are_the_hooks_own(self):
        '''What 10b injects script names into: the registered functions, never the writer's own chain entries'''
        def raw(name, func):
            return None

        registerFuncCallback(raw)
        body = replace_function('Target')(lambda arg1: None)

        self.assertEqual(self.writer.hook_functions, [raw, body])

    def test_replaced_twice_warns_and_the_last_wins(self):
        self.define_target()
        with self.assertLogs(log, 'WARNING') as logs:
            hook = self.hook('''
                @replace_function('Target')
                def Target(arg1):                           # line: first
                    POP(WORD_SIZE)
                    RETURN()

                @replace_function('Target')
                def Target(arg1):                           # line: second
                    PUSH_INT(7)
                    POP(2 * WORD_SIZE)
                    RETURN()
            ''')

        [warning] = [record.getMessage() for record in logs.records]
        first, second = (f'{hook.__file__}:{marked_line(hook.__file__, marker)}' for marker in ('first', 'second'))
        self.assertEqual(warning, f"{second}: replace_function('Target') again, overriding the one at {first}")
        self.assertEqual(self.mnemonics(self.parsed()['Target']), PUSH_POP_RETURN)

    def test_unknown_name_points_at_the_hook(self):
        self.define_target()
        hook = self.hook('''
            @replace_function('Targt')
            def Targt(arg1):                                # line: misspelled
                RETURN()
        ''')

        with self.assertRaisesRegex(ValueError, rf"^{at(hook.__file__, 'misspelled')}replace_function\('Targt'\): the "
                                                rf"script has no function 'Targt'$"):
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
            def Target(arg1: Value32):
                POP(WORD_SIZE)
                RETURN()

            scena.run(globals())
        '''), encoding = 'utf-8')
        (self.tmp / 'e2e_hook.py').write_text('from falcom.ed9.writer.scp_writer_helper import *\n'
                                              + textwrap.dedent(REPLACE_TARGET), encoding = 'utf-8')
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

    def test_replace_function_without_the_name(self):
        with self.assertRaisesRegex(TypeError, r"^replace_function takes the function's name - "
                                               r"@replace_function\('Name'\) - not <function "):
            @replace_function
            def Target(arg1):
                RETURN()

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

        with self.assertRaisesRegex(TypeError, rf"^{at(hook.__file__, 'partial')}to_partial for Target: expected a "
                                               "plain function"):
            self.writer.build({})

    def test_callback_registering_a_function_or_callback(self):
        registrations = {
            'function': 'get_scp_writer().LLILCode()(Extra)',
            'callback': 'registerFuncCallback(lambda name, func: None)',
            'replacement': "replace_function('Nmae')(Extra)",
        }
        for case, registration in registrations.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()
                self.define_target()
                hook = self.hook(f'''
                    def Extra():
                        RETURN()

                    def adds(name, func):                   # line: adds
                        {registration}

                    registerFuncCallback(adds)
                ''')

                with self.assertRaisesRegex(ValueError, rf"^{at(hook.__file__, 'adds')}a function callback can't register "
                                                        "functions or callbacks$"):
                    self.writer.build({})

    def test_replacement_signatures(self):
        cases = {
            'count': ('def Target(arg1, arg2):', 'Target takes 1 parameters, its replacement 2$', False),
            'args': ('def Target(*args):', r"Target's replacement can't take \*args, keyword-only or \*\*kwargs "
                                           r'parameters \(args\); a wrapper keeps the replaced signature with functools.wraps$',
                     False),
            'keyword-only': ('def Target(arg1, *, flag):', r"Target's replacement can't take .* \(flag\);", False),
            'type': ('def Target(arg1: int):', r"parameter arg1 of Target: unsupported type: <class 'int'>$", False),
            'default': ('def Target(arg1 = None):', 'parameter arg1 of Target: a default is an int, float or str, not None$',
                        False),
            'misspelled type': ('def Target(arg1: Valu32):', "Target: name 'Valu32' is not defined", True),
            'missing attribute type': ('def Target(arg1: ScpValue.Valu32):', "Target: type object 'ScpValue' has no "
                                                                         "attribute 'Valu32'", False),
            'out-of-range default': ('def Target(arg1 = 0x80000000):', 'parameter arg1 of Target: Integer 2147483648 '
                                                                     'is outside', False),
        }
        for case, (definition, message, future) in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()
                self.define_target()
                hook = self.hook(f'''
                    @replace_function('Target')
                    {definition}                                # line: def
                        RETURN()
                ''', future = future)

                with self.assertRaisesRegex(TypeError, f"^{at(hook.__file__, 'def')}{message}"):
                    self.writer.build({})

    def test_new_function_parameters(self):
        '''Every new function's parameters are checked where it is defined, not later while writing the .dat'''
        cases = {
            'no type': 'needs a type: Value32, Nullable32, str, NullableStr or Pointer$',
            'wrong type': r"unsupported type: <class 'int'>$",
            'None default': 'a default is an int, float or str, not None$',
            'None type': 'needs a type: Value32, Nullable32, str, NullableStr or Pointer$',
            'non-finite default': "non-finite float nan: the game can't use it$",
        }
        for case, message in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()
                with self.assertRaisesRegex(TypeError, rf"^{at(__file__, case)}parameter arg2 of New: {message}"):
                    if case == 'no type':
                        @self.writer.LLILCode()
                        def New(arg1: Value32, arg2):                   # line: no type
                            RETURN()

                    elif case == 'wrong type':
                        @self.writer.LLILCode()
                        def New(arg1: Value32, arg2: int):              # line: wrong type
                            RETURN()

                    elif case == 'None default':
                        @self.writer.LLILCode()
                        def New(arg1: Value32, arg2: Value32 = None):   # line: None default
                            RETURN()

                    elif case == 'None type':
                        @self.writer.LLILCode()
                        def New(arg1: Value32, arg2: None):             # line: None type
                            RETURN()

                    else:
                        @self.writer.LLILCode()
                        def New(arg1: Value32, arg2: Value32 = float('nan')):   # line: non-finite default
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

        with self.assertRaisesRegex(CompileCheckError, rf"^{at(hook.__file__, 'bad pop')}Target: POP at {HEX}: "):
            self.writer.build({})

    def test_wrapper_halves_point_at_their_own_lines(self):
        '''A functools.wraps wrapper's own opcodes map to the wrapper, the body it inlines to that body'''
        cases = {'wrapper': (3 * WORD_SIZE, 2 * WORD_SIZE), 'inlined': (WORD_SIZE, 3 * WORD_SIZE)}
        for case, (wrapper_pop, original_pop) in cases.items():
            with self.subTest(case):
                self.writer = self.fresh_writer()

                @self.writer.LLILCode()
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
                expected = at(hook.__file__, 'wrapper pop') if case == 'wrapper' else at(__file__, 'original pop')

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

        with self.assertRaisesRegex(CompileCheckError, rf"^{at(__file__, 'decorated body')}Decorated: POP at {HEX}: "):
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

        with self.assertRaisesRegex(CompileCheckError, rf"^{at(hook.__file__, 'middle')}Target: "):
            self.writer.build({})


if __name__ == '__main__':
    unittest.main()
