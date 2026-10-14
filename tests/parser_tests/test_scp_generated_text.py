#!/usr/bin/env python3
'''Text of the generated LLIL DSL .py (header, hook import, label spacers, footer, the omitted-commons comment),
scena2py's recursion limit and summary, the opt-in hook template, a fidelity script compiling back to its bytes,
and LF line endings in every generated text file (scena2py.process_file, the common-library generator, the round-trip
validator's intermediate scripts).'''

from pathlib import Path
import importlib
import logging
import re
import runpy
import sys
import tempfile
import unittest
import uuid
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from dc3.logging import log
from dc3.utils import PROJECT_ROOT, RECURSION_LIMIT, write_text_lf
from falcom.ed9.metadata import SCP_WRITER_HELPER_IMPORT
from falcom.ed9.metadata import common_all
from falcom.ed9.metadata import gen_common_library as gen
from falcom.ed9.metadata.common_index import COMMON_FUNCTIONS
from falcom.ed9.parser.scp import SYS_PATH_SETUP_LINES, ScpParser
from falcom.ed9.parser.types_parser import GlobalVar
from falcom.ed9.parser.types_scp import ScpGlobalVar
from falcom.ed9.scena2py import COMMON_FUNCTIONS_OMITTED_COMMENT, main, process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
import scp_roundtrip_validator
from scp_roundtrip_validator import compile_and_decompile_round, decompile_to_python
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.scp_writer_test_utils import fresh_writer

TEST_FILE = SORA2_SCRIPTS / 'ai/ai_chr5122_e00.dat'
SMALL_FILE = SORA2_SCRIPTS / 'scena/e0000.dat'
DEAD_CODE_FILE = SORA2_SCRIPTS / 'ai/ai_chr5121_e01.dat'    # has unreachable code
PYTHON_DEFAULT_RECURSION_LIMIT = 1000
LABEL_LINE = re.compile(r"^ *label\('[^']*'\)( +# .*)?$")     # with its depth comment, if any

HOOK_TEMPLATE_IMPORTS = '''\
    from ai_chr5122_e00 import *  # pyright: ignore[reportAssignmentType]
    import ai_chr5122_e00 as original
'''

HOOK_TEMPLATE = f'''\
# pyright: basic
from typing import TYPE_CHECKING
from falcom.ed9.writer.scp_writer_helper import *
if TYPE_CHECKING:
{HOOK_TEMPLATE_IMPORTS}
# Functions to add
def run_hook(g):
    for func in [
    ]:
        add_function(func)

# registerRunCallback(run_hook)

def func_hook(name, func):
    return None

# registerFuncCallback(func_hook)

def opcode_hook(opcode, *args):
    return None

# registerOpcodeCallback(opcode_hook)
'''

MON5078_RENAME_HINT = '''\
    # 'mon5078+' isn't a valid module name, so Pylance can't import the script's names. To get them, rename
    # mon5078+.py to a valid name (it still compiles to mon5078+.dat; keep this file's name) and uncomment:
    # from mon5078_ import *  # pyright: ignore[reportAssignmentType]
    # import mon5078_ as original
    pass
'''

# The checkout's own dc3/ package takes the name
DC3_RENAME_HINT = '''\
    # 'dc3' is also the name of another module, so Pylance can't import the script's names. To get them, rename
    # dc3.py to a valid name (it still compiles to dc3.dat; keep this file's name) and uncomment:
    # from dc3_ import *  # pyright: ignore[reportAssignmentType]
    # import dc3_ as original
    pass
'''

# A function for the template's run_hook list: calls e0000's Init by its plain name
HOOK_EXTRA = '''
def HookExtra():
    PUSH_CURRENT_FUNC_ID()
    PUSH_RET_ADDR('hook_extra_ret')
    CALL(Init)
    label('hook_extra_ret')
    RETURN()
'''


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
    def test_header_starts_with_the_sys_path_setup_then_the_helper_import(self):
        '''Guard: no provenance comment above the imports (decided against, 2026-10-02)'''
        header = named_parser('ai_chr5122_e00.dat').gen_python_header()
        self.assertEqual(header[:len(SYS_PATH_SETUP_LINES) + 2], [*SYS_PATH_SETUP_LINES, SCP_WRITER_HELPER_IMPORT, 'try:'])

    def test_sys_path_setup_names_the_repo_root(self):
        '''The baked-in path is what lets a generated script run without PYTHONPATH'''
        self.assertTrue((PROJECT_ROOT / 'falcom' / 'ed9' / 'writer' / 'scp_writer_helper.py').is_file())
        self.assertEqual(SYS_PATH_SETUP_LINES[1], f'sys.path.insert(0, {str(PROJECT_ROOT)!r})')

    def test_global_var_comments_share_the_comment_column(self):
        parser = named_parser('ai_chr5122_e00.dat')
        integer = int(ScpGlobalVar.Type.Integer)                       # the parser keeps the raw type
        parser.global_vars = [GlobalVar(0, 'x', integer), GlobalVar(1, 'reaches_the_comment_column', integer)]
        header = parser.gen_python_header()
        self.assertEqual(header[header.index('def globalvars():') + 1:][:2], [
            '    GLOBAL_VAR("x", 0)              # global var 0',
            '    GLOBAL_VAR("reaches_the_comment_column", 0)  # global var 1',
        ])

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


class TestHookTemplate(unittest.TestCase):
    '''The starting <stem>_hook.py written with ScenaDecompileConfig.write_hook_template'''

    def test_text(self):
        self.assertEqual(named_parser('ai_chr5122_e00.dat').gen_hook_template(), HOOK_TEMPLATE)

    def test_rename_hint_when_the_stem_is_not_a_module_name(self):
        self.assertEqual(named_parser('mon5078+.dat').gen_hook_template(),
                         HOOK_TEMPLATE.replace(HOOK_TEMPLATE_IMPORTS, MON5078_RENAME_HINT))

    def test_rename_hint_when_another_module_has_the_name(self):
        self.assertEqual(named_parser('dc3.dat').gen_hook_template(),
                         HOOK_TEMPLATE.replace(HOOK_TEMPLATE_IMPORTS, DC3_RENAME_HINT))

    def test_rename_hint_decided_on_the_raw_stem(self):
        '''A keyword, a leading digit or space, a stdlib module's name: the .py carries the raw stem, so no import names
        the script; the suggestion is a free module name'''
        for name, suggested in (('class.dat', 'class_'), ('0abc.dat', '_0abc'), (' ai.dat', 'ai'), ('types.dat', 'types_')):
            with self.subTest(name = name):
                self.assertIn(f'    # from {suggested} import *  # pyright: ignore[reportAssignmentType]\n'
                              f'    # import {suggested} as original\n', named_parser(name).gen_hook_template())

    def test_hint_imports_parse_uncommented(self):
        '''An import under TYPE_CHECKING still has to parse: `from class import *` would break the whole hook'''
        for name in ('mon5078+.dat', 'dc3.dat', 'class.dat', '0abc.dat', ' ai.dat', 'types.dat'):
            with self.subTest(name = name):
                text = named_parser(name).gen_hook_template()
                compile(text.replace('    # from ', '    from ').replace('    # import ', '    import '), f'{name}_hook.py', 'exec')


class TestHookTemplateWritten(unittest.TestCase):
    '''process_file writes the template only when asked, next to the .py, and never over an existing file'''

    def setUp(self):
        require(SMALL_FILE)
        self.out = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = ScenaDecompileConfig()
        self.config.output_dir = self.out
        self.config.write_ts = self.config.write_mlil_asm = False

    def hooks(self) -> list[Path]:
        return sorted(self.out.rglob('*_hook.py'))

    def test_not_written_by_default(self):
        process_file(SMALL_FILE, self.config)
        self.assertTrue((self.out / 'e0000' / 'e0000.py').exists())
        self.assertEqual(self.hooks(), [])

    def test_named_like_the_import(self):
        '''The module the script imports: a leading space in the stem is stripped from both'''
        self.config.write_hook_template = True
        dat = self.out / ' ai.dat'
        dat.write_bytes(SMALL_FILE.read_bytes())
        process_file(dat, self.config)
        self.assertEqual(self.hooks(), [self.out / ' ai' / 'ai_hook.py'])
        self.assertIn('    import ai_hook\n', (self.out / ' ai' / ' ai.py').read_text(encoding = 'utf-8'))

    def test_only_with_write_py(self):
        self.config.write_hook_template = True
        self.config.write_py = False
        process_file(SMALL_FILE, self.config)
        self.assertEqual(self.hooks(), [])

    def test_existing_hook_kept(self):
        self.config.write_hook_template = True
        hook = self.out / 'e0000' / 'e0000_hook.py'
        hook.parent.mkdir()
        hook.write_bytes(b'# mine\r\n')
        with self.assertLogs(log, 'INFO') as logs:
            process_file(SMALL_FILE, self.config)

        self.assertEqual(hook.read_bytes(), b'# mine\r\n')
        self.assertIn(f'{hook} exists - not overwritten', '\n'.join(logs.output))

    def test_dotted_stem_skipped_with_a_warning(self):
        self.config.write_hook_template = True
        dat = self.out / 'X.original.dat'
        dat.write_bytes(SMALL_FILE.read_bytes())
        with self.assertLogs(log, 'WARNING') as logs:
            process_file(dat, self.config)

        self.assertTrue((self.out / 'X.original' / 'X.original.py').exists())
        self.assertEqual(self.hooks(), [])
        self.assertIn("X.original.dat: hook template not written - a stem with a dot ('X.original') isn't supported",
                      '\n'.join(logs.output))


class TestHookTemplateCompiles(unittest.TestCase):
    '''The written template next to e0000.py compiles to the same bytes as no hook, as written and with its register
    lines uncommented; a function put in its run_hook list is added and reaches the script's names'''

    def setUp(self):
        require(SMALL_FILE)
        out = Path(self.enterContext(tempfile.TemporaryDirectory()))
        config = ScenaDecompileConfig()
        config.output_dir = out
        config.write_ts = config.write_mlil_asm = False
        config.write_hook_template = True
        process_file(SMALL_FILE, config)

        self.script = out / 'e0000' / 'e0000.py'
        self.hook = out / 'e0000' / 'e0000_hook.py'
        self.template = self.hook.read_text(encoding = 'utf-8')
        self.enterContext(mock.patch.object(sys, 'path', [str(self.script.parent), *sys.path]))
        self.enterContext(mock.patch.object(sys, 'dont_write_bytecode', True))
        self.addCleanup(sys.modules.pop, 'e0000_hook', None)

    def compiled(self, hook_text: str | None) -> bytes:
        '''e0000.py compiled in memory with hook_text as its hook (None: no hook file)'''
        if hook_text is None:
            self.hook.unlink(missing_ok = True)

        else:
            self.hook.write_text(hook_text, encoding = 'utf-8')

        sys.modules.pop('e0000_hook', None)
        importlib.invalidate_caches()
        fresh_writer()
        g = runpy.run_path(str(self.script), run_name = 'hook_template_check')
        return g['scena'].build(g)

    def test_written_text(self):
        self.assertEqual(self.template, named_parser('e0000.dat').gen_hook_template())

    def test_same_bytes_as_no_hook(self):
        no_hook = self.compiled(None)
        registered = self.template.replace('\n# register', '\nregister')
        self.assertEqual(registered.count('\nregister'), 3)
        self.assertEqual(self.compiled(self.template), no_hook)
        self.assertEqual(self.compiled(registered), no_hook)

    def test_listed_function_is_added(self):
        '''Last in code order, and its CALL reaches the script's Init by its plain name'''
        hook = self.template.replace('# registerRunCallback', 'registerRunCallback')
        hook = hook.replace('    for func in [\n', '    for func in [\n        HookExtra,\n') + HOOK_EXTRA
        parser, functions = ScpParser.load_bytes(self.compiled(hook), 'e0000.dat', round_trip = False,
                                                 keep_unreachable_code = False, quiet = True)
        by_name = {func.name: func for func in functions}
        self.assertEqual(max(functions, key = lambda func: func.offset).name, 'HookExtra')
        [call] = [inst for inst in parser.get_instructions(by_name['HookExtra']) if inst.mnemonic == 'CALL']
        self.assertEqual(call.operands[0].value, by_name['Init'].index)


class TestFidelityScriptCompiles(unittest.TestCase):
    '''A fidelity decompile of a script with dead code compiles back to its own bytes, warning about that dead code'''

    def setUp(self):
        require(DEAD_CODE_FILE)
        out = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.script = out / DEAD_CODE_FILE.with_suffix('.py').name
        decompile_to_python(DEAD_CODE_FILE, self.script, round_trip = True, keep_unreachable_code = True)
        self.text = self.script.read_text(encoding = 'utf-8')

    def compiled(self, text: str) -> bytes:
        '''text compiled in memory'''
        write_text_lf(self.script, text)
        fresh_writer()
        g = runpy.run_path(str(self.script), run_name = 'fidelity_check')
        return g['scena'].build(g)

    def test_same_bytes_with_only_unreachable_code_warnings(self):
        with self.assertLogs(log, 'WARNING') as logs:
            data = self.compiled(self.text)

        self.assertEqual(data, DEAD_CODE_FILE.read_bytes())
        self.assertEqual([message for message in logs.output if 'never run' not in message], [])


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
        config.write_hlil_ts = config.write_debug_info = config.write_hook_template = True

        with tempfile.TemporaryDirectory() as tmp:
            config.output_dir = Path(tmp)
            process_file(TEST_FILE, config)
            outputs = sorted(Path(tmp).rglob('*.*'))
            self.assertEqual({''.join(path.suffixes[-2:]) for path in outputs},
                             {'.py', '.ts', '.hlil.ts', '.llil.asm', '.mlil.asm', '.llil.dot', '.mlil.dot', '.debug.txt'})
            self.assertIn(Path(tmp) / TEST_FILE.stem / f'{TEST_FILE.stem}_hook.py', outputs)
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
                gen.write_output({}, {}, {'f': []}, {'f': 'scp_writer_common_0'})

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


class TestScena2py(unittest.TestCase):
    def setUp(self):
        require(SMALL_FILE)
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def config(self, **settings) -> ScenaDecompileConfig:
        config = ScenaDecompileConfig()
        config.output_dir = self.tmp
        config.write_ts = config.write_mlil_asm = False
        for name, value in settings.items():
            setattr(config, name, value)

        return config

    def py_text(self) -> str:
        return (self.tmp / SMALL_FILE.stem / f'{SMALL_FILE.stem}.py').read_text(encoding = 'utf-8')

    def test_omitted_common_functions_comment_only_when_they_are_omitted(self):
        for include, expected in ((True, False), (False, True)):
            with self.subTest(include_common_functions = include):
                process_file(SMALL_FILE, self.config(include_common_functions = include))
                self.assertEqual(COMMON_FUNCTIONS_OMITTED_COMMENT.splitlines()[0] in self.py_text(), expected)

    def test_line_markers_reach_both_hlil_outputs(self):
        '''On by default; off, neither .hlil.ts nor .ts has a // line(N) comment'''
        for settings, expected in (({}, True), ({'line_markers': False}, False)):
            with self.subTest(**settings):
                process_file(SMALL_FILE, self.config(write_hlil_ts = True, write_ts = True, **settings))
                for suffix in ('.hlil.ts', '.ts'):
                    text = (self.tmp / SMALL_FILE.stem / f'{SMALL_FILE.stem}{suffix}').read_text(encoding = 'utf-8')
                    self.assertEqual('// line(' in text, expected, suffix)

    def test_process_file_raises_the_recursion_limit(self):
        self.addCleanup(sys.setrecursionlimit, sys.getrecursionlimit())
        sys.setrecursionlimit(PYTHON_DEFAULT_RECURSION_LIMIT)
        process_file(SMALL_FILE, self.config())

        self.assertGreaterEqual(sys.getrecursionlimit(), RECURSION_LIMIT)

    def test_main_logs_how_many_files_succeeded(self):
        with (
            mock.patch.object(sys, 'argv', ['scena2py', str(SMALL_FILE)]),
            mock.patch.object(ScenaDecompileConfig, 'output_dir', self.tmp),
            self.assertLogs(log, logging.INFO) as logs,
        ):
            self.assertEqual(main(), 0)

        self.assertIn('1/1 succeeded', [record.getMessage() for record in logs.records])


class TestLibraryExports(unittest.TestCase):
    '''Scripts star-import common_all after the helper; re-exporting the helper's names a second time
    turns aliases like Value32 into variables for type checkers'''

    def public_names(self, namespace: dict) -> set[str]:
        return {name for name in namespace if not name.startswith('_')}

    def test_module_exports_only_its_own_functions(self):
        names = ['Zeta', 'Alpha']
        rendered = {name: [f'def {name}():', '    pass'] for name in names}
        facts = {name: gen.FunctionFacts(touches_global = False, call_targets = set(), subsystem = None) for name in names}
        namespace = {}
        exec(gen.render_module(f'{gen.MODULE_PREFIX}0', names, rendered, facts, {}), namespace)

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
