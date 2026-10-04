#!/usr/bin/env python3
'''Unit tests for the string pool's sections (falcom/ed9/parser/string_pool.py) - every section in pool order, code
strings in code order with unreachable code - and the round-trip validator that checks them.'''

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))
sys.path.insert(0, str(Path(__file__).parent))

from ml import fileio

from common.config import default_encoding
from ir.llil import WORD_SIZE
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.parser.string_pool import StringRefs, collect_string_refs
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import fresh_writer
from scp_roundtrip_validator import Status, load_script, validate_file

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'
PERSONAL_TEMPLATE_FILE = SORA2_DIR / 'scena' / 'personalTemplate.dat'
NUL = b'\0'
SECTIONS = ('code', 'names', 'defaults', 'debug', 'global_names')

# compile_script's strings by section, in pool order
SCRIPT_SECTIONS = {
    'code'          : ['zeta', 'dead', 'hello', 'arg', 'this', 'Zeta', 'mod', 'Tail'],
    'names'         : ['Alpha', 'Mid', 'Zeta'],
    'defaults'      : ['fallback'],
    'debug'         : ['this.Zeta'],
    'global_names'  : ['flag'],
}


def compile_script(dat: Path):
    '''Zeta is defined first, so the code order (Zeta, Alpha, Mid) is not the table's (Alpha, Mid, Zeta). Zeta pushes a
    string in dead code after its RETURN; Alpha passes a pushed string to Zeta, so its debug record repeats a code string,
    and its CALL_SCRIPT record names "this.Zeta", a debug-only string.'''
    fresh_writer()
    writer = create_scp_writer(str(dat))

    @writer.GlobalVars()
    def globalvars():
        GLOBAL_VAR('flag', 1)

    @writer.LLILCode()
    def Zeta(arg1: Value32 = 'fallback'):
        PUSH_STR('zeta')
        POP(WORD_SIZE)
        POP(WORD_SIZE)
        RETURN()
        PUSH_STR('dead')
        POP(WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Alpha():
        DEBUG_SET_LINENO(1)  # a call gets a debug record only after line info
        PUSH_STR('hello')
        POP(WORD_SIZE)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('ret')
        PUSH_STR('arg')
        CALL(Zeta)
        label('ret')
        PUSH_CALLER_FRAME('back')
        CALL_SCRIPT('this', 'Zeta', 0)
        label('back')
        RETURN()

    @writer.LLILCode()
    def Mid():
        CALL_SCRIPT_NO_RETURN('mod', 'Tail', 0)

    writer.run({})


def load_string_refs(path: Path) -> tuple[bytes, StringRefs]:
    '''The file's bytes and string refs, unreachable code decoded; the raw debug records are read from the bytes'''
    parser, _ = ScpParser.load(path, round_trip = True, keep_unreachable_code = True)
    data = path.read_bytes()
    fs = fileio.FileStream(encoding = default_encoding()).OpenMemory(data)
    records = [parser.read_debug_info(fs, entry) for entry in parser.function_entries]
    return data, collect_string_refs(data, parser, records)


def read_text(data: bytes, offset: int) -> str:
    return data[offset:data.find(NUL, offset)].decode(default_encoding())


def pool_strings(data: bytes, start: int) -> list[int]:
    '''Offset of every string from start to the end of the file'''
    offsets = []
    position = start
    while position < len(data):
        offsets.append(position)
        position = data.index(NUL, position) + 1

    return offsets


class TestCollectStringRefs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dat = Path(tmp_dir) / 'test.dat'
            compile_script(dat)
            cls.data, cls.refs = load_string_refs(dat)

    def test_every_section_in_pool_order(self):
        sections = {name: [read_text(self.data, offset) for offset in getattr(self.refs, name)] for name in SECTIONS}
        self.assertEqual(sections, SCRIPT_SECTIONS)

    def test_sections_hold_every_pool_string_in_order(self):
        self.assertEqual(self.refs.pool_start, self.refs.code[0])
        self.assertEqual(self.refs.expected_pool, pool_strings(self.data, self.refs.pool_start))


class TestValidator(unittest.TestCase):
    def test_string_pool_check_counts_unreachable_code_strings(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dat = Path(tmp_dir) / 'test.dat'
            compile_script(dat)
            results, _ = validate_file(dat)

        [string_pool] = [result for result in results if result.name == 'string pool']
        self.assertEqual(string_pool.status, Status.PASS, string_pool.details)

    def test_load_script_closes_the_file_when_the_load_fails(self):
        streams = []

        def fail(parser, *args, **kwargs):
            streams.append(parser.fs)
            raise ValueError('bad code')

        # A leaked handle would also fail the cleanup on Windows; report the assertion instead
        with tempfile.TemporaryDirectory(ignore_cleanup_errors = True) as tmp_dir:
            dat = Path(tmp_dir) / 'test.dat'
            compile_script(dat)
            with mock.patch.object(ScpParser, 'disasm_all_functions', autospec = True, side_effect = fail):
                with self.assertRaisesRegex(ValueError, '^bad code$'):
                    load_script(dat)

            self.assertTrue(streams[0].Stream.closed)


@unittest.skipUnless(PERSONAL_TEMPLATE_FILE.exists(), 'needs the sora2_1.0 corpus')
class TestRealScript(unittest.TestCase):
    '''Its table order is not its code order, and 5 of its 6 debug record strings repeat a code string'''

    def test_personal_template_sections(self):
        data, refs = load_string_refs(PERSONAL_TEMPLATE_FILE)

        self.assertEqual([len(getattr(refs, name)) for name in SECTIONS], [19, 18, 4, 1, 1])
        self.assertEqual(refs.expected_pool, pool_strings(data, refs.pool_start))
        self.assertEqual([read_text(data, offset) for offset in refs.code[:2]], ['system', 'OnTalkBegin'])
        self.assertEqual(read_text(data, refs.names[0]), 'Init')
        self.assertEqual([read_text(data, offset) for offset in refs.debug + refs.global_names],
                         ['system.OnMapReinit', 'lastMenuSel'])


if __name__ == '__main__':
    unittest.main()
