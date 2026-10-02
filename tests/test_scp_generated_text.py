#!/usr/bin/env python3
'''Text of the generated LLIL DSL .py (header, hook import, label spacers, footer) and LF line
endings in every generated text file (scena2py.process_file, the common-library generator, the round-trip
validator's intermediate scripts).'''

from pathlib import Path
import importlib
import re
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer import scp_writer_gen_common_funcs as gen
from falcom.ed9.writer.metadata import SCP_WRITER_HELPER_IMPORT
from falcom.ed9.writer.metadata import common_all
from falcom.ed9.writer.metadata.common_index import COMMON_FUNCTIONS
import scp_roundtrip_validator
from scp_roundtrip_validator import compile_and_decompile_round, decompile_to_python

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'
TEST_FILE = SORA2_DIR / 'ai' / 'ai_chr5122_e00.dat'
SMALL_FILE = SORA2_DIR / 'scena' / 'e0000.dat'
LABEL_LINE = re.compile(r"^ *label\('[^']*'\)$")


def require(path: Path):
    if not path.exists():
        raise unittest.SkipTest(f'Test file not found: {path}')


def named_parser(name: str) -> ScpParser:
    '''A parser with only what the header needs: a name and no global vars'''
    parser = ScpParser(None, name)
    parser.global_vars = []
    return parser


def hook_block(name: str) -> list[str]:
    '''The hook try/except lines exactly as the generated header emits them'''
    header = named_parser(name).gen_python_header()
    start = header.index('try:')
    return header[start:header.index('', start)]


class TestHeader(unittest.TestCase):
    def test_header_starts_with_the_helper_import(self):
        '''Guard: no provenance comment above the imports (decided against, 2026-10-02)'''
        header = named_parser('ai_chr5122_e00.dat').gen_python_header()
        self.assertEqual(header[:2], [SCP_WRITER_HELPER_IMPORT, 'try:'])

    def test_hook_import_reraises_unless_the_hook_is_missing(self):
        self.assertEqual(hook_block('ai_chr5122_e00.dat'), [
            'try:',
            '    import ai_chr5122_e00_hook',
            'except ModuleNotFoundError as e:',
            "    if e.name != 'ai_chr5122_e00_hook':",
            '        raise',
        ])

    def test_hook_import_for_a_stem_that_is_not_a_module_name(self):
        self.assertEqual(hook_block('mon5078+.dat'), [
            'try:',
            "    __import__('mon5078+_hook')",
            'except ModuleNotFoundError as e:',
            "    if e.name != 'mon5078+_hook':",
            '        raise',
        ])

    def test_hook_import_for_a_dotted_stem_accepts_a_missing_parent(self):
        self.assertEqual(hook_block('X.original.dat'), [
            'try:',
            '    import X.original_hook',
            'except ModuleNotFoundError as e:',
            "    if e.name not in ('X', 'X.original_hook'):",
            '        raise',
        ])


class TestHookImportRuns(unittest.TestCase):
    '''Executes the generated hook block against hook files in a temp dir (unique module names)'''

    def setUp(self):
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.prefix = f'h{uuid.uuid4().hex}'
        sys.path.insert(0, str(self.dir))
        self.addCleanup(sys.path.remove, str(self.dir))
        self.addCleanup(self.forget_modules)

    def forget_modules(self):
        for name in [name for name in sys.modules if name.startswith(self.prefix)]:
            del sys.modules[name]

    def run_hook_block(self, stem: str):
        importlib.invalidate_caches()
        exec('\n'.join(hook_block(f'{stem}.dat')), {})

    def test_missing_hook_is_ignored(self):
        self.run_hook_block(self.prefix)

    def test_missing_hook_is_ignored_in_the_dunder_import_form(self):
        self.run_hook_block(f'{self.prefix}+')

    def test_missing_parent_of_a_dotted_stem_is_ignored(self):
        self.run_hook_block(f'{self.prefix}.original')

    def test_missing_hook_under_an_existing_parent_package_is_ignored(self):
        package = self.dir / self.prefix
        package.mkdir()
        (package / '__init__.py').write_text('', encoding = 'utf-8')
        self.run_hook_block(f'{self.prefix}.original')

    def test_present_hook_is_imported(self):
        (self.dir / f'{self.prefix}_hook.py').write_text('LOADED = True\n', encoding = 'utf-8')
        self.run_hook_block(self.prefix)
        self.assertTrue(sys.modules[f'{self.prefix}_hook'].LOADED)

    def test_failed_import_inside_the_hook_reraises(self):
        missing = f'{self.prefix}_missing_dependency'
        (self.dir / f'{self.prefix}_hook.py').write_text(f'import {missing}\n', encoding = 'utf-8')

        with self.assertRaises(ModuleNotFoundError) as ctx:
            self.run_hook_block(self.prefix)

        self.assertEqual(ctx.exception.name, missing)


class TestFooter(unittest.TestCase):
    def test_footer_calls_main_directly(self):
        self.assertEqual(named_parser('e0000.dat').gen_python_footer(), [
            'def main():',
            '    scena.run(globals())',
            '',
            "if __name__ == '__main__':",
            '    main()',
        ])


class TestGeneratedScript(unittest.TestCase):
    def assert_clean_whitespace(self, round_trip: bool):
        require(TEST_FILE)
        parser, functions = ScpParser.load(TEST_FILE, round_trip = round_trip, keep_unreachable_code = round_trip)
        lines = parser.gen_python_script(functions).split('\n')
        self.assertEqual([line for line in lines if line != line.rstrip()], [])

        after_labels = [lines[index + 1] for index, line in enumerate(lines) if LABEL_LINE.match(line)]
        self.assertTrue(after_labels)
        self.assertEqual(set(after_labels), {''})

    def test_no_trailing_whitespace_and_empty_label_spacers(self):
        self.assert_clean_whitespace(round_trip = False)

    def test_no_trailing_whitespace_and_empty_label_spacers_in_fidelity_mode(self):
        self.assert_clean_whitespace(round_trip = True)


class TestLineEndings(unittest.TestCase):
    def assert_lf_only(self, paths: list[Path]):
        self.assertTrue(paths)
        for path in paths:
            self.assertNotIn(b'\r', path.read_bytes(), path.name)

    def test_process_file_writes_lf(self):
        require(TEST_FILE)
        config = ScenaDecompileConfig()
        config.write_llil_asm = config.write_llil_dot = config.write_mlil_asm = config.write_mlil_dot = True
        config.write_hlil_ts = config.write_debug_info = True

        with tempfile.TemporaryDirectory() as tmp:
            config.output_dir = Path(tmp)
            process_file(TEST_FILE, config)
            outputs = sorted(Path(tmp).rglob('*.*'))
            self.assertEqual({''.join(path.suffixes[-2:]) for path in outputs},
                             {'.py', '.ts', '.hlil.ts', '.llil.asm', '.mlil.asm', '.llil.dot', '.mlil.dot', '.debug.txt'})
            self.assert_lf_only(outputs)

    def test_common_library_generator_writes_lf(self):
        text = 'line 1\nline 2\n'
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch.object(gen, 'OUTPUT_DIR', out / 'common'), \
                 mock.patch.object(gen, 'INDEX_PATH', out / 'common_index.py'), \
                 mock.patch.object(gen, 'ALL_PATH', out / 'common_all.py'), \
                 mock.patch.object(gen, 'render_module', return_value = text), \
                 mock.patch.object(gen, 'render_index', return_value = text), \
                 mock.patch.object(gen, 'render_all', return_value = text):
                # write_output deletes every .py in OUTPUT_DIR: never let it reach the real library
                self.assertEqual(gen.OUTPUT_DIR, out / 'common')
                gen.write_output({}, {'f'}, {'f': 'scp_writer_common_0'})

            paths = sorted(out.rglob('*.py'))
            self.assertEqual({path.name for path in paths}, {'__init__.py', 'scp_writer_common_0.py', 'common_index.py', 'common_all.py'})
            self.assert_lf_only(paths)

    def test_validator_intermediate_scripts_are_lf(self):
        require(SMALL_FILE)
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / 'e0000.py'
            decompile_to_python(SMALL_FILE, first, round_trip = False, keep_unreachable_code = False)
            with mock.patch.object(scp_roundtrip_validator, 'compile_dsl', return_value = (0, [])):
                compile_and_decompile_round('e0000', Path(tmp) / 'round1', first.read_text(encoding = 'utf-8'))

            self.assert_lf_only([first, Path(tmp) / 'round1' / 'e0000.py'])


class TestLibraryExports(unittest.TestCase):
    '''Scripts star-import common_all after the helper; re-exporting the helper's names a second time
    turns aliases like Value32 into variables for type checkers'''

    def public_names(self, namespace: dict) -> set[str]:
        return {name for name in namespace if not name.startswith('_')}

    def test_module_exports_only_its_own_functions(self):
        canon = {
            name: gen.CanonicalFunction(name = name, params = [], instructions = [], referenced_offsets = set(), touches_global = False,
                                        call_targets = set(), subsystem = None, digest = '')
            for name in ('Zeta', 'Alpha')
        }
        namespace = {}
        exec(gen.render_module(f'{gen.MODULE_PREFIX}0', list(canon), canon, {}), namespace)

        self.assertEqual(namespace['__all__'], ('Alpha', 'Zeta'))

    def test_all_module_keeps_its_logger_private(self):
        namespace = {}
        exec(gen.render_all(['not_generated']), namespace)

        self.assertEqual(self.public_names(namespace), {'COMMON_LIBRARY_GENERATED'})

    def test_generated_library_exports_only_library_functions(self):
        if not common_all.COMMON_LIBRARY_GENERATED:
            raise unittest.SkipTest('common-function library not generated')

        self.assertEqual(self.public_names(vars(common_all)), set(COMMON_FUNCTIONS) | {'COMMON_LIBRARY_GENERATED'})


if __name__ == '__main__':
    unittest.main()
