#!/usr/bin/env python3
"""Unit tests for the common-function library generator (gen_common_library.py) and the library it
generates. Generator: the facts that decide a function's inclusion and module, a function rendered from hand-built
bytecode with the scripts' stack comments, a module's imports, the closure check and the corpus-root check. Library:
compiling a label-heavy generated function twice in one process, each time on a fresh writer against the same cached
module, must fingerprint identically to the corpus canonical both times - proving genLabel() names are allocated per
execution, not baked in once at module import time."""

import contextlib
import importlib
import inspect
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.metadata import COMMON_LIBRARY_FOLDER, game_metadata_module
from falcom.ed9.metadata import gen_common_library as gen
from falcom.ed9.metadata.fingerprint import function_fingerprint, fingerprint_digest
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.parser.parser_types import Function
from ir.llil.llil import WORD_SIZE
from tests.shared.scp_asm import (
    Asm, Func, Program, CALLEE_ID, CALLEE_NAME, CALLER_ID, FLOAT_VALUE, FUNC_NAME, GLOBAL_INDEX, LEFT_VALUE,
    returning_callee,
)
from tests.shared.corpus import require_library
from tests.shared.scp_writer_test_utils import fresh_writer

CHECK_SBREAK = 'CheckSBreak'  # forward and backward branches
SUBSYSTEM = 5
SYSCALL_FUNC = 0
SYSCALL_ARGC = 0
OWN_MODULE = f'{gen.MODULE_PREFIX}{SUBSYSTEM}'
SCRIPT_CALLEE = 'ScriptOnly'  # a script's own function: never in the library
GAME = 'sora2'
LIBRARY_PACKAGE = game_metadata_module(GAME, COMMON_LIBRARY_FOLDER)


def disassemble(asm: Asm, argc: int = 0) -> tuple[ScpParser, dict[str, Function]]:
    """FUNC_NAME assembled from asm, calling a callee that returns at once"""
    parser, functions = Program(Func(FUNC_NAME, argc, asm), returning_callee()).disassemble()
    return parser, {func.name: func for func in functions}


def defined_functions(module) -> list:
    """Functions actually defined in module (not opcode primitives/genLabel/other common modules
    reaching it through the helper star-import or a cross-module "import ... as common_N")"""
    return [obj for obj in vars(module).values() if inspect.isfunction(obj) and obj.__module__ == module.__name__]


def compile_and_fingerprint(name: str, index: dict[str, tuple[str, str]]) -> str:
    """Registers every common function of sora2's library (index) through one CommonImports() manifest - the
    generator already asserts every CALL target is included, so this always resolves - compiles to
    a throwaway .dat, then re-disassembles it and fingerprints the requested function."""
    module_keys = sorted({module_key for module_key, _digest in index.values()})
    modules = [importlib.import_module(f'{LIBRARY_PACKAGE}.{key}') for key in module_keys]
    functions = [func for module in modules for func in defined_functions(module)]

    with tempfile.TemporaryDirectory() as tmp:
        dat_path = Path(tmp) / 'test_output.dat'

        writer = fresh_writer(dat_path)

        @writer.CommonImports()
        def commonImports():
            return functions

        writer.run(globals())

        parser, disasm_functions = ScpParser.load(dat_path, round_trip=False, keep_unreachable_code=False)

        func = next(f for f in disasm_functions if f.name == name)
        return fingerprint_digest(function_fingerprint(parser, func))


class TestGenerator(unittest.TestCase):
    def test_facts_from_the_instructions(self):
        global_uses = {
            'load_global'   : lambda asm: (asm.load_global(GLOBAL_INDEX), asm.pop(WORD_SIZE)),
            'set_global'    : lambda asm: (asm.push_int(LEFT_VALUE), asm.set_global(GLOBAL_INDEX)),
        }
        for use, emit in global_uses.items():
            with self.subTest(use=use):
                asm = Asm()
                asm.syscall(SUBSYSTEM, SYSCALL_FUNC, SYSCALL_ARGC)
                asm.syscall(SUBSYSTEM + 1, SYSCALL_FUNC, SYSCALL_ARGC)
                emit(asm)
                asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.call(CALLEE_ID); asm.label('return'); asm.ret()
                parser, functions = disassemble(asm)

                facts = {name: gen.function_facts(parser, func) for name, func in functions.items()}
                self.assertEqual(facts, {
                    FUNC_NAME   : gen.FunctionFacts(touches_global=True, call_targets={CALLEE_NAME},
                                                    subsystem=SUBSYSTEM),
                    CALLEE_NAME : gen.FunctionFacts(touches_global=False, call_targets=set(), subsystem=None),
                })

    def render(self, callee_module: str) -> list[str]:
        asm = Asm()
        asm.push_float(FLOAT_VALUE); asm.syscall(SUBSYSTEM, SYSCALL_FUNC, 1); asm.pop(WORD_SIZE)  # no opt-in comments
        asm.load_stack(-WORD_SIZE); asm.jz('skip')                                     # sp 1: slot 0
        asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.call(CALLEE_ID); asm.label('return')
        asm.push_raw(0)                                                                 # opens slot 1
        asm.push_int(LEFT_VALUE); asm.pop_to(-WORD_SIZE); asm.pop(WORD_SIZE)            # sp 2 after its pop: slot 1
        asm.label('skip'); asm.pop(WORD_SIZE); asm.ret()
        parser, functions = disassemble(asm, argc=1)

        func = functions[FUNC_NAME]
        digest = fingerprint_digest(function_fingerprint(parser, func))
        name_to_module = {FUNC_NAME: OWN_MODULE, CALLEE_NAME: callee_module}
        return gen.render_function(parser, func, Path('test.dat'), digest, name_to_module)

    def test_function_rendered_from_its_instructions_with_stack_comments(self):
        """The stack comments only: a float SYSCALL argument gets neither the float bits nor its argument number"""
        self.assertEqual(self.render(callee_module=OWN_MODULE), [
            f'def {FUNC_NAME}(arg1: Value32):',
            '    L0 = genLabel()',
            '    L1 = genLabel()',
            f'    PUSH_FLOAT({FLOAT_VALUE})',
            f'    SYSCALL({SUBSYSTEM}, 0x{SYSCALL_FUNC:02X}, 0x01)',
            '    POP(4)                          # 1 slot',
            '    LOAD_STACK(-4)                  # slot 0 = arg1',
            '    POP_JMP_ZERO(L1)',
            '    PUSH_CURRENT_FUNC_ID()',
            '    PUSH_RET_ADDR(L0)',
            f'    CALL({CALLEE_NAME})',
            '    label(L0)                       # sp = 1',
            '    PUSH_RAW(RawInt(0x00000000))    # slot 1 (local)',
            f'    PUSH_INT({LEFT_VALUE})',
            '    POP_TO(-4)                      # slot 1',
            '    POP(4)                          # 1 slot',
            '    label(L1)                       # sp = 1',
            '    POP(4)                          # 1 slot',
            '    RETURN()',
        ])

    def test_callee_in_another_module_is_qualified(self):
        lines = self.render(callee_module=gen.NO_SYSCALL_MODULE)
        self.assertIn(f'    CALL({gen.module_alias(gen.NO_SYSCALL_MODULE)}.{CALLEE_NAME})', lines)

    def test_module_imports_only_the_other_modules_it_calls(self):
        facts = {FUNC_NAME: gen.FunctionFacts(touches_global=False, call_targets={CALLEE_NAME},
                                              subsystem=SUBSYSTEM)}
        rendered = {FUNC_NAME: [f'def {FUNC_NAME}():', '    pass']}
        other_module = gen.NO_SYSCALL_MODULE
        other_import = f'import {LIBRARY_PACKAGE}.{other_module} as {gen.module_alias(other_module)}'
        for callee_module, imports in ((OWN_MODULE, []), (other_module, [other_import])):
            with self.subTest(callee_module=callee_module):
                name_to_module = {FUNC_NAME: OWN_MODULE, CALLEE_NAME: callee_module}
                text = gen.render_module(LIBRARY_PACKAGE, OWN_MODULE, [FUNC_NAME], rendered, facts, name_to_module)
                self.assertEqual([line for line in text.split('\n') if line.startswith('import ')], imports)

    def test_included_functions_call_only_included_ones(self):
        """require_closed_calls: a callee left out of the library, excluded or not a common function at all, stops
        generation; a closed set passes"""
        facts = {
            FUNC_NAME   : gen.FunctionFacts(touches_global=False, call_targets={CALLEE_NAME}, subsystem=None),
            CALLEE_NAME : gen.FunctionFacts(touches_global=False, call_targets=set(), subsystem=None),
        }
        gen.require_closed_calls({FUNC_NAME, CALLEE_NAME}, facts)

        calls_script = {FUNC_NAME: gen.FunctionFacts(touches_global=False, call_targets={SCRIPT_CALLEE},
                                                     subsystem=None)}
        for case, included, case_facts, target in (('excluded', {FUNC_NAME}, facts, CALLEE_NAME),
                                                   ('not common', {FUNC_NAME}, calls_script, SCRIPT_CALLEE)):
            with self.subTest(case=case):
                with self.assertRaises(RuntimeError) as raised:
                    gen.require_closed_calls(included, case_facts)

                self.assertEqual(str(raised.exception),
                                 f'{FUNC_NAME}: CALL target {target!r} is excluded or not a common function')

    def game_folder(self, games: Path, name: str = 'game') -> Path:
        """A game package in games, a stand-in for falcom/ed9/games/ (gen.GAMES_DIR)"""
        game = games / name
        game.mkdir(parents=True)
        (game / '__init__.py').write_text('', encoding='utf-8')
        return game

    def script_folder(self, folder: Path) -> Path:
        """folder, holding one .dat in a subfolder"""
        (folder / 'ai').mkdir(parents=True)
        (folder / 'ai' / 'script.dat').write_bytes(b'')
        return folder

    def test_wrong_corpus_root_writes_nothing(self):
        """generate() replaces the game's whole library: it must stop first on a file, a missing path, a folder not
        named script(_<lang>) (the game folder, extracted/, a subfolder of the script folder), a script folder whose
        path names no game here with no --game (the old <game>/script_en, a game folder without its package), a path
        and a --game naming different games, a --game naming no game, and a script folder with no .dat. Parsing is
        stubbed out, so only the input checks can stop it"""
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(gen, 'collect_occurrences', return_value=({}, {})), \
             mock.patch.object(gen, 'write_output') as write_output:
            games = Path(tmp) / 'games'
            game = self.game_folder(games)
            self.game_folder(games, 'second')
            script_en = self.script_folder(game / 'extracted' / 'script_en')
            old_layout = self.script_folder(Path(tmp) / 'game' / 'script_en')
            no_package = self.script_folder(games / 'other' / 'extracted' / 'script_en')
            empty = game / 'extracted' / 'script_fr'
            empty.mkdir()
            cases = ((script_en / 'ai' / 'script.dat', None, NotADirectoryError),
                     (game / 'missing', None, NotADirectoryError), (game, None, ValueError),
                     (game / 'extracted', None, ValueError), (script_en / 'ai', 'game', ValueError),
                     (old_layout, None, ValueError), (no_package, None, ValueError), (script_en, 'second', ValueError),
                     (old_layout, 'missing', ValueError), (empty, None, FileNotFoundError))
            with mock.patch.object(gen, 'GAMES_DIR', games):
                for corpus_root, game_name, error in cases:
                    with self.subTest(corpus_root=corpus_root.relative_to(tmp).as_posix(), game=game_name):
                        with self.assertRaises(error):
                            gen.generate(corpus_root, game_name)

                        write_output.assert_not_called()

    def test_game_from_the_path_wherever_it_is_else_from_the_game_argument(self):
        """<game>/extracted/script_<lang> names its game outside games/ too (a copy, a junction's target); a path that
        names no game here takes --game; a --game agreeing with the path is accepted"""
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
             mock.patch.object(gen, 'collect_occurrences', return_value=({}, {})), \
             mock.patch.object(gen, 'write_output') as write_output:
            games = Path(tmp) / 'games'
            game = self.game_folder(games)
            copy = self.script_folder(Path(tmp) / 'copies' / 'game' / 'extracted' / 'script_en')
            bare = self.script_folder(Path(tmp) / 'copies' / 'script_en')
            unknown = self.script_folder(Path(tmp) / 'copies' / 'other' / 'extracted' / 'script_en')
            with mock.patch.object(gen, 'GAMES_DIR', games):
                for corpus_root, game_name in ((copy, None), (copy, 'game'), (bare, 'game'), (unknown, 'game')):
                    with self.subTest(corpus_root=corpus_root.relative_to(tmp).as_posix(), game=game_name):
                        write_output.reset_mock()
                        gen.generate(corpus_root, game_name)
                        self.assertEqual(write_output.call_args.args[0], game)

    def test_script_folder_of_any_language_is_accepted(self):
        """The language in script_<lang> is not fixed (script_en today), and a bare script folder passes too; the
        library goes to the script folder's game"""
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
             mock.patch.object(gen, 'collect_occurrences', return_value=({}, {})), \
             mock.patch.object(gen, 'write_output') as write_output:
            games = Path(tmp) / 'games'
            game = self.game_folder(games)
            with mock.patch.object(gen, 'GAMES_DIR', games):
                for folder_name in ('script_en', 'script_sc', 'script'):
                    with self.subTest(folder_name=folder_name):
                        write_output.reset_mock()
                        gen.generate(self.script_folder(game / 'extracted' / folder_name))
                        write_output.assert_called_once()
                        self.assertEqual(write_output.call_args.args[0], game)


class TestGeneratedLibraryFingerprintStable(unittest.TestCase):
    def test_check_sbreak_matches_canonical_across_two_independent_compiles(self):
        index = require_library(GAME)
        self.assertIn(CHECK_SBREAK, index, 'corpus canonical index has no CheckSBreak')
        _module_key, expected_digest = index[CHECK_SBREAK]

        for attempt in (1, 2):
            digest = compile_and_fingerprint(CHECK_SBREAK, index)
            self.assertEqual(digest, expected_digest, f'attempt {attempt}: fingerprint diverged from the corpus canonical')


if __name__ == '__main__':
    unittest.main()
