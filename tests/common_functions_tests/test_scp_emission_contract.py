#!/usr/bin/env python3
"""Unit tests for ScpParser's selection-to-emission contract: match_library_functions,
get_inline_functions, gen_common_imports and gen_python_script must all agree on which functions got
matched to the shared library, in the script's own code order, only outside strict round-trip
mode and only with a game. Uses a real corpus file (TEST_FILE) and sora2's library rather than a fake
index, since its common/source split is already exercised (and known) elsewhere in this test suite; the game
selection uses stand-in games instead (TestEachGameMatchesItsOwnLibrary)."""

from pathlib import Path
import sys
import types
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.structs.common_library import COMMON_ALL_MODULE, COMMON_INDEX_MODULE, game_metadata_module
from falcom.ed9.structs.fingerprint import function_fingerprint, fingerprint_digest
from falcom.ed9.formatter.llil_dsl.script_formatter import LLILScriptFormatter, common_library_index
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.corpus import SORA2_SCRIPTS, require, require_library
from tests.shared.scp_writer_test_utils import WriterTestCase

TEST_FILE = SORA2_SCRIPTS / 'ai/ai_chr0100_e00.dat'
GAME = 'sora2'
LIBRARY_IMPORT = 'from falcom.ed9.games.sora2.metadata.common_all import *'

MATCHED_COMMON_FUNC = 'chr_info'   # canonical-matching common function - imported, not inlined
SOURCE_FUNC = 'SkillTable'         # this script's own function - always inlined


def load(game: str | None = GAME) -> tuple[ScpParser, list]:
    require_library(GAME)
    return ScpParser.load(require(TEST_FILE), round_trip=False, keep_unreachable_code=False, game=game)


class TestLibraryMatching(unittest.TestCase):
    def test_canonical_common_function_is_matched(self):
        parser, functions = load()
        matched = LLILScriptFormatter(parser).match_library_functions(functions)

        self.assertIn(MATCHED_COMMON_FUNC, matched)

    def test_source_function_is_never_matched(self):
        parser, functions = load()
        matched = LLILScriptFormatter(parser).match_library_functions(functions)

        self.assertNotIn(SOURCE_FUNC, matched)

    def test_round_trip_mode_disables_matching_entirely(self):
        parser, functions = load()
        parser.round_trip = True

        self.assertEqual(LLILScriptFormatter(parser).match_library_functions(functions), {})

    def test_keep_unreachable_code_also_disables_matching(self):
        """The library was generated with unreachable code dropped - importing it under
        keep_unreachable_code=True would silently drop a script's own dead bytes even though that
        flag asked to keep them, so this must gate matching exactly like round_trip does."""
        parser, functions = load()
        parser.keep_unreachable_code = True

        self.assertEqual(LLILScriptFormatter(parser).match_library_functions(functions), {})

    def test_no_game_matches_nothing_and_imports_no_library(self):
        """game=None (the validator without --game, most tests): every common function inline, no library import"""
        parser, functions = load(game=None)
        script = LLILScriptFormatter(parser).gen_python_script(functions)

        self.assertEqual(LLILScriptFormatter(parser).match_library_functions(functions), {})
        self.assertNotIn('common_all', script)
        self.assertIn(f'def {MATCHED_COMMON_FUNC}(', script)


class TestEmissionContract(unittest.TestCase):
    def test_matched_functions_are_excluded_from_inline_output(self):
        parser, functions = load()
        inline_names = {func.name for func in LLILScriptFormatter(parser).get_inline_functions(functions)}

        self.assertNotIn(MATCHED_COMMON_FUNC, inline_names)
        self.assertIn(SOURCE_FUNC, inline_names)

    def test_manifest_lists_matched_functions_in_code_order(self):
        parser, functions = load()
        matched = LLILScriptFormatter(parser).match_library_functions(functions)
        self.assertTrue(matched, 'expected at least one matched function for this fixture')

        manifest_lines = LLILScriptFormatter(parser).gen_common_imports(functions, matched=matched)
        return_block_start = manifest_lines.index('    return [')
        return_block_end = manifest_lines.index('    ]', return_block_start)
        listed = [line.strip().rstrip(',') for line in manifest_lines[return_block_start + 1:return_block_end]]

        expected_order = [func.name for func in functions if func.name in matched]
        self.assertEqual(listed, expected_order)

    def test_header_and_inline_set_agree_on_the_same_precomputed_match(self):
        """gen_python_script computes match_library_functions exactly once and threads it through
        both halves - the header's manifest and the inline-function loop can never disagree about
        which functions got imported, unlike calling gen_python_header/get_inline_functions
        separately (each would recompute the match independently)."""
        parser, functions = load()
        script = LLILScriptFormatter(parser).gen_python_script(functions)
        header = script.split('\n@scena.CommonImports()')[0]

        self.assertIn(f'    {LIBRARY_IMPORT}', header)
        self.assertIn(f'{MATCHED_COMMON_FUNC},', script.split('def commonImports():')[1].split(']')[0])
        self.assertIn(f'def {SOURCE_FUNC}(', script)
        self.assertNotIn(f'def {MATCHED_COMMON_FUNC}(', script)

    def test_strict_round_trip_mode_inlines_everything(self):
        parser, functions = load()
        parser.round_trip = True
        script = LLILScriptFormatter(parser).gen_python_script(functions)

        self.assertNotIn('CommonImports', script)
        self.assertIn(f'def {MATCHED_COMMON_FUNC}(', script)
        self.assertIn(f'def {SOURCE_FUNC}(', script)


class TestEachGameMatchesItsOwnLibrary(WriterTestCase):
    """A parser matches against its own game's index only, and its script imports that game's common_all: two
    stand-in games whose indexes (planted in sys.modules, where the parser's import finds them) list the same common
    function, only one of them with its fingerprint"""

    def test_the_parsers_game_picks_the_index(self):
        @self.writer.LLILCommonCode()
        def Shared():
            RETURN()

        parser, functions = ScpParser.load_bytes(self.writer.build({}), 'test.dat', round_trip=False,
                                                 keep_unreachable_code=False, quiet=True)
        digest = fingerprint_digest(function_fingerprint(parser, functions[0]))
        indexes = {
            'stand_in_a': {'Shared': ('module_a', digest)},
            'stand_in_b': {'Shared': ('module_b', 'another digest')},
        }
        planted = {}
        for game, index in indexes.items():
            module = types.ModuleType(game_metadata_module(game, COMMON_INDEX_MODULE))
            module.COMMON_FUNCTIONS = index
            planted[module.__name__] = module

        self.enterContext(mock.patch.dict(sys.modules, planted))
        self.addCleanup(common_library_index.cache_clear)

        for game, expected in (('stand_in_a', {'Shared': 'module_a'}), ('stand_in_b', {})):
            with self.subTest(game=game):
                parser.game = game
                self.assertEqual(LLILScriptFormatter(parser).match_library_functions(functions), expected)
                self.assertIn(f'    from {game_metadata_module(game, COMMON_ALL_MODULE)} import *',
                              LLILScriptFormatter(parser).gen_python_script(functions))


if __name__ == '__main__':
    unittest.main()
