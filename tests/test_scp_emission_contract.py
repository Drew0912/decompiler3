#!/usr/bin/env python3
'''Unit tests for ScpParser's selection-to-emission contract: match_library_functions,
get_inline_functions, gen_common_imports and gen_python_script must all agree on which functions got
matched to the shared library, in the script's own code order, and only outside strict round-trip
mode. Uses a real corpus file (sora2_1.0/script_en/ai/ai_chr0100_e00.dat) rather than a fake index,
since its common/source split is already exercised (and known) elsewhere in this test suite.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.parser.scp import ScpParser

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'
TEST_FILE = SORA2_DIR / 'ai' / 'ai_chr0100_e00.dat'

MATCHED_COMMON_FUNC = 'chr_info'   # canonical-matching common function - imported, not inlined
SOURCE_FUNC = 'SkillTable'         # this script's own function - always inlined


def load() -> tuple[ScpParser, list]:
    if not TEST_FILE.exists():
        raise unittest.SkipTest(f'Test file not found: {TEST_FILE}')

    return ScpParser.load(TEST_FILE, round_trip = False, keep_unreachable_code = False)


class TestLibraryMatching(unittest.TestCase):
    def test_canonical_common_function_is_matched(self):
        parser, functions = load()
        matched = parser.match_library_functions(functions)

        self.assertIn(MATCHED_COMMON_FUNC, matched)

    def test_source_function_is_never_matched(self):
        parser, functions = load()
        matched = parser.match_library_functions(functions)

        self.assertNotIn(SOURCE_FUNC, matched)

    def test_round_trip_mode_disables_matching_entirely(self):
        parser, functions = load()
        parser.round_trip = True

        self.assertEqual(parser.match_library_functions(functions), {})

    def test_keep_unreachable_code_also_disables_matching(self):
        '''The library was generated with unreachable code dropped - importing it under
        keep_unreachable_code=True would silently drop a script's own dead bytes even though that
        flag asked to keep them, so this must gate matching exactly like round_trip does.'''
        parser, functions = load()
        parser.keep_unreachable_code = True

        self.assertEqual(parser.match_library_functions(functions), {})


class TestEmissionContract(unittest.TestCase):
    def test_matched_functions_are_excluded_from_inline_output(self):
        parser, functions = load()
        inline_names = {func.name for func in parser.get_inline_functions(functions)}

        self.assertNotIn(MATCHED_COMMON_FUNC, inline_names)
        self.assertIn(SOURCE_FUNC, inline_names)

    def test_manifest_lists_matched_functions_in_code_order(self):
        parser, functions = load()
        matched = parser.match_library_functions(functions)
        self.assertTrue(matched, 'expected at least one matched function for this fixture')

        manifest_lines = parser.gen_common_imports(functions, matched = matched)
        return_block_start = manifest_lines.index('    return [')
        return_block_end = manifest_lines.index('    ]', return_block_start)
        listed = [line.strip().rstrip(',') for line in manifest_lines[return_block_start + 1:return_block_end]]

        expected_order = [func.name for func in functions if func.name in matched]
        self.assertEqual(listed, expected_order)

    def test_header_and_inline_set_agree_on_the_same_precomputed_match(self):
        '''gen_python_script computes match_library_functions exactly once and threads it through
        both halves - the header's manifest and the inline-function loop can never disagree about
        which functions got imported, unlike calling gen_python_header/get_inline_functions
        separately (each would recompute the match independently).'''
        parser, functions = load()
        script = parser.gen_python_script(functions)
        header = script.split('\n@scena.CommonImports()')[0]

        self.assertIn('from falcom.ed9.writer.metadata.common_all import *', header)
        self.assertIn(f'{MATCHED_COMMON_FUNC},', script.split('def commonImports():')[1].split(']')[0])
        self.assertIn(f'def {SOURCE_FUNC}(', script)
        self.assertNotIn(f'def {MATCHED_COMMON_FUNC}(', script)

    def test_strict_round_trip_mode_inlines_everything(self):
        parser, functions = load()
        parser.round_trip = True
        script = parser.gen_python_script(functions)

        self.assertNotIn('CommonImports', script)
        self.assertIn(f'def {MATCHED_COMMON_FUNC}(', script)
        self.assertIn(f'def {SOURCE_FUNC}(', script)


if __name__ == '__main__':
    unittest.main()
