#!/usr/bin/env python3
'''Unit tests for the readable .dat listing (.debug.txt, falcom/ed9/parser/scp_listing.py): the sections, every code byte
listed once, record tags at their calls, escaped text, and scena2py's write_debug_info / debug_sections.'''

from dataclasses import fields
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from common.config import default_endian
from common.logging import log
from common.utils import quote_string
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.code_layout import code_start
from falcom.ed9.parser.scp_listing import BYTES_WIDTH, COLUMN_GAP, ListingSections, ScpListing
from falcom.ed9.parser.types_scp import ScpFunctionCallDebugInfo
from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import fresh_writer

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'
CHECK_ALGO_USE_FILE = SORA2_DIR / 'ai' / 'ai_chr5122_e00.dat'
DEAD_CODE_CALLS_FILE = SORA2_DIR / 'ani' / 'chr0109.dat'
CODE_BEFORE_FUNCTIONS_FILE = SORA2_DIR / 'scena' / 'mp0090.dat'
UNMARKED_CALL_FILE = SORA2_DIR / 'ai' / 'ai_chr5004p.dat'

SPECIAL_TEXT = 'a, "b" \\ c\r\nd'      # a comma, quotes, a backslash, CR and LF
POOL_HEADING = '=== String pool'
SECTION_MARKERS = {                     # the start of a line only that section prints
    'header'            : '=== Header ===',
    'global_vars'       : '=== Global vars',
    'function_entries'  : 'code 0x',
    'code'              : '--- code ---',
    'call_records'      : '--- call records',
    'string_pool'       : POOL_HEADING,
}
CALL_OPCODES = {
    ScpFunctionCallDebugInfo.CallType.Local             : ED9Opcode.CALL,
    ScpFunctionCallDebugInfo.CallType.Script            : ED9Opcode.CALL_SCRIPT,
    ScpFunctionCallDebugInfo.CallType.ScriptNoReturn    : ED9Opcode.CALL_SCRIPT_NO_RETURN,
    ScpFunctionCallDebugInfo.CallType.Syscall           : ED9Opcode.SYSCALL,
}
INVALID_OPCODE = 0xFF                   # no ED9 opcode
IR_OUTPUTS = ('write_py', 'write_ts', 'write_llil_asm', 'write_llil_dot', 'write_mlil_asm', 'write_mlil_dot', 'write_hlil_ts')


def compile_main(dat: Path):
    '''Global var types 1 and 2; Outer has a float and a string default; Main makes a call before any line info, pushes a
    string with every character that needs escaping, nests Inner() in Outer's arguments (records in source order: Outer's
    first), and calls Inner again in dead code after its RETURN'''
    fresh_writer()
    writer = create_scp_writer(str(dat))

    @writer.GlobalVars()
    def globalvars():
        GLOBAL_VAR('flag', 1)
        GLOBAL_VAR('odd', 2)

    @writer.LLILCode()
    def Inner():
        PUSH_INT(5)
        SET_REG(0)
        RETURN()

    @writer.LLILCode()
    def Outer(arg1: Value32 = 0.3, arg2: str = 'default'):
        POP(2 * WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Main():
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('early')
        CALL(Inner)
        label('early')
        DEBUG_SET_LINENO(1)  # a call gets a debug record only after line info
        PUSH_STR(SPECIAL_TEXT)
        POP(WORD_SIZE)
        PUSH_FLOAT(0.3)
        POP(WORD_SIZE)
        LOAD_GLOBAL('flag')
        POP(WORD_SIZE)
        PUSH_INT(1)
        SYSCALL(1, 0x2F, 1)
        POP(WORD_SIZE)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('outer')
        PUSH_STR('x')
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('inner')
        CALL(Inner)
        label('inner')
        GET_REG(0)
        CALL(Outer)
        label('outer')
        PUSH_CALLER_FRAME('back')
        CALL_SCRIPT('this', 'Inner', 0)
        label('back')
        RETURN()
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('dead')
        CALL(Inner)
        label('dead')
        RETURN()

    writer.run({})


def compile_shared(dat: Path):
    '''ZEmpty has no code, so it starts where ABody does; Jumper jumps into ABody (compiles with a warning)'''
    fresh_writer()
    writer = create_scp_writer(str(dat))

    @writer.LLILCode()
    def ZEmpty():
        pass

    @writer.LLILCode()
    def ABody():
        label('body')
        RETURN()

    @writer.LLILCode()
    def Jumper():
        JMP('body')

    writer.run({})


def compile_common(dat: Path):
    '''A common function (laid out first, with no line info) and two source functions'''
    fresh_writer()
    writer = create_scp_writer(str(dat))

    @writer.LLILCommonCode()
    def CommonOne():
        PUSH_INT(1)
        SET_REG(0)
        RETURN()

    @writer.LLILCode()
    def Main():
        DEBUG_SET_LINENO(1)
        RETURN()

    @writer.LLILCode()
    def Other():
        DEBUG_SET_LINENO(2)
        RETURN()

    writer.run({})


def code_area(listing: ScpListing, lines: list[str]) -> bytes:
    '''The bytes of the code and raw lines before the string pool, in printed order; each line must start where the
    previous one ended (from the code start), so a range listed twice or skipped fails'''
    lines = lines[:next((i for i, line in enumerate(lines) if line.startswith(POOL_HEADING)), len(lines))]
    bytes_column = len('0x') + listing.offset_width + COLUMN_GAP
    cursor = code_start(listing.parser.header)
    area = b''
    for line in (line for line in lines if line.startswith('0x')):
        offset = int(line[len('0x'):bytes_column - COLUMN_GAP], 16)
        if offset != cursor:
            raise AssertionError(f'0x{offset:X} listed where 0x{cursor:X} comes next')

        chunk = bytes.fromhex(line[bytes_column:bytes_column + BYTES_WIDTH])
        area += chunk
        cursor += len(chunk)

    return area


def whole_code_area(listing: ScpListing) -> bytes:
    return listing.data[code_start(listing.parser.header):listing.refs.pool_start]


def group_lines(lines: list[str], name: str) -> list[str]:
    '''The lines of the function group whose heading starts with name'''
    start = next(i for i, line in enumerate(lines) if line.startswith(f'=== {name} '))
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith('===')), len(lines))
    return lines[start:end]


def function_headings(lines: list[str]) -> list[str]:
    '''Each function group's names'''
    return [line.split(' (')[0].removeprefix('=== ') for line in lines if line.startswith('=== ') and 'code 0x' in line]


def record_offsets_and_tags(lines: list[str]) -> list[str]:
    '''The lines that exist only for a paired function: a record's call offset, a tag under a call'''
    return [line for line in lines if ' @ 0x' in line or ';   record' in line]


def patched_listing(data: bytes) -> ScpListing:
    with tempfile.TemporaryDirectory() as tmp_dir:
        dat = Path(tmp_dir) / 'main.dat'
        dat.write_bytes(data)
        return ScpListing(dat)


class TestListing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.dat = Path(cls.tmp_dir.name) / 'main.dat'
        compile_main(cls.dat)
        cls.listing = ScpListing(cls.dat)
        cls.lines = cls.listing.lines(ListingSections())
        cls.functions = {func.name: func for func in cls.listing.parser.functions}

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def test_each_section_alone(self):
        for field in fields(ListingSections):
            with self.subTest(section = field.name):
                sections = ListingSections(**{other.name: other.name == field.name for other in fields(ListingSections)})
                lines = self.listing.lines(sections)
                printed = {section for section, marker in SECTION_MARKERS.items() if any(line.startswith(marker) for line in lines)}
                self.assertEqual(printed, {field.name})

    def test_code_area_listed_once_and_whole(self):
        self.assertEqual(code_area(self.listing, self.lines), whole_code_area(self.listing))

    def test_records_tagged_at_their_calls(self):
        main = self.functions['Main']
        call_offsets, note = self.listing.pairing(main)
        records = self.listing.records[main.index]
        self.assertIsNone(note)
        self.assertEqual(len(call_offsets), len(records))
        for i, offset in call_offsets.items():
            with self.subTest(record = i):
                [(inst, _)] = self.listing.decoded[offset]
                self.assertEqual(inst.opcode, CALL_OPCODES[records[i].call_type])
                if inst.opcode == ED9Opcode.CALL:
                    self.assertEqual(inst.operands[0].value, records[i].func_id)

                line = next(j for j, text in enumerate(self.lines) if text.startswith(f'0x{offset:0{self.listing.offset_width}X}'))
                self.assertIn(f';   record {i}: ', self.lines[line + 1])

    def test_record_order_is_source_order(self):
        '''Outer's record comes before the Inner call nested in its arguments, which sits earlier in the code'''
        records = [line for line in group_lines(self.lines, 'Main') if line.startswith('[')]
        self.assertEqual([line.split(' @ ')[0] for line in records[1:3]], ['[ 1] Local Outer(CallResult, "x")', '[ 2] Local Inner()'])
        self.assertLess(int(records[2].split(' @ ')[1], 16), int(records[1].split(' @ ')[1], 16))

    def test_dead_code_call_is_tagged(self):
        lines = group_lines(self.lines, 'Main')
        dead_call = next(i for i, line in enumerate(lines) if 'CALL 0' in line and 'unreachable' in line)
        self.assertIn('record 4: Local Inner()', lines[dead_call + 1])

    def test_call_before_line_info_has_no_record(self):
        lines = group_lines(self.lines, 'Main')
        first_call = next(i for i, line in enumerate(lines) if 'CALL 0' in line)
        self.assertNotIn('record', lines[first_call + 1])

    def test_text_is_escaped(self):
        text = '\n'.join(self.lines)
        self.assertNotIn('\r', text)
        self.assertEqual(text.count(quote_string(SPECIAL_TEXT)), 2)  # the PUSH comment and the pool

    def test_operands_as_encoded(self):
        text = '\n'.join(self.lines)
        for expected in ('PUSH 4, Float(0.3)', 'f32 0x3E999998, raw 0x8FA66666', 'SYSCALL 1, 0x2F, 0x01', 'LOAD_GLOBAL 0',
                         '"flag", global var 0', 'PUSH 4, Raw(0x1)', 'func id: Main', 'CALL_SCRIPT Str(', '"this", "Inner"'):
            with self.subTest(expected = expected):
                self.assertIn(expected, text)

    def test_global_var_types(self):
        self.assertIn('[0] "flag", type 1 (String)', self.lines)
        self.assertIn('[1] "odd", type 2', self.lines)

    def test_entry_line(self):
        [entry] = [line for line in group_lines(self.lines, 'Outer') if line.startswith('code 0x')]
        self.assertIn("2 params [arg1: Value32 = 0.3, arg2: str = 'default']; 2 defaults", entry)

    def test_record_content_mismatch_is_noted(self):
        record = self.listing.records[self.functions['Main'].index][1]     # Local Outer(CallResult, "x")
        result_arg = record.arg_offsets()[0]
        data = bytearray(self.listing.data)
        data[result_arg:result_arg + WORD_SIZE] = (1).to_bytes(WORD_SIZE, default_endian())
        lines = group_lines(patched_listing(bytes(data)).lines(ListingSections()), 'Main')
        self.assertIn('--- call records (5) ---  ; records not paired: record 1 differs from its call (arg 0: value 0x00000001 != None)', lines)
        self.assertFalse(record_offsets_and_tags(lines))

    def test_undecoded_bytes_listed_raw(self):
        '''Dead code that doesn't decode (an opcode the table lacks) is kept as raw bytes inside its function'''
        dead_start = self.functions['Main'].unreachable_blocks[0].start_offset
        data = bytearray(self.listing.data)
        data[dead_start] = INVALID_OPCODE
        listing = patched_listing(bytes(data))
        lines = listing.lines(ListingSections())
        main_lines = group_lines(lines, 'Main')
        raw = [line for line in main_lines if line.endswith('; not decoded')]
        self.assertTrue(raw[0].startswith(f'0x{dead_start:0{listing.offset_width}X}  ff '))
        self.assertEqual(code_area(listing, lines), whole_code_area(listing))
        self.assertIn('--- call records (5) ---  ; records not paired: 4 calls, 5 records', main_lines)
        self.assertFalse(record_offsets_and_tags(main_lines))


class TestSharedCode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.dat = Path(cls.tmp_dir.name) / 'shared.dat'
        compile_shared(cls.dat)
        cls.listing = ScpListing(cls.dat)
        cls.indices = {func.name: func.index for func in cls.listing.parser.functions}

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def test_shared_start_listed_once(self):
        lines = self.listing.lines(ListingSections())
        self.assertEqual(function_headings(lines), ['ABody + ZEmpty', 'Jumper'])
        self.assertRegex(next(line for line in lines if line.startswith('=== ABody')),
                         r'^=== ABody \+ ZEmpty \(ids 0x0000, 0x0002, shared code 0x[0-9A-F]+\.\.0x[0-9A-F]+\) ===$')
        self.assertEqual(code_area(self.listing, lines), whole_code_area(self.listing))

    def test_any_member_selects_the_shared_range(self):
        for name in ('ABody', 'ZEmpty'):
            with self.subTest(selected = name):
                self.assertEqual(function_headings(self.listing.lines(ListingSections(), {self.indices[name]})), ['ABody + ZEmpty'])

    def test_jump_into_another_function(self):
        lines = group_lines(self.listing.lines(ListingSections()), 'ABody')
        [ret] = [line for line in lines if line.startswith('0x') and 'RETURN' in line]
        self.assertIn('also decoded by ZEmpty, Jumper', ret)


class TestProcessFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.main = Path(cls.tmp_dir.name) / 'main.dat'
        cls.common = Path(cls.tmp_dir.name) / 'common.dat'
        compile_main(cls.main)
        compile_common(cls.common)

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def listing_text(self, dat: Path, **settings) -> str:
        '''dat's .debug.txt from process_file, every other output off, into an output folder of its own'''
        config = ScenaDecompileConfig()
        config.output_dir = Path(tempfile.mkdtemp(dir = self.tmp_dir.name))
        for flag in IR_OUTPUTS:
            setattr(config, flag, False)

        config.write_debug_info = True
        for name, value in settings.items():
            setattr(config, name, value)

        process_file(dat, config)
        return (config.output_dir / dat.stem / f'{dat.stem}.debug.txt').read_text(encoding = 'utf-8')

    def test_listing_alone_in_both_modes(self):
        '''No other output asked for - the listing is still written, the same whatever the decompile mode'''
        texts = [self.listing_text(self.main, round_trip = mode, keep_unreachable_code = mode) for mode in (False, True)]
        self.assertEqual(texts[0], texts[1])
        self.assertEqual(texts[0], '\n'.join(ScpListing(self.main).lines(ListingSections())) + '\n')

    def test_selected_functions_only(self):
        lines = self.listing_text(self.main, filter_func = lambda func: func.name in ('Main', 'Inner')).splitlines()
        self.assertEqual(function_headings(lines), ['Inner', 'Main'])
        self.assertIn('0x1B1  name     "Outer"', lines)     # the pool lists an unselected function's name too
        self.assertFalse([line for line in lines if 'not decoded' in line])

    def test_common_functions_left_out(self):
        for settings, expected in (
            ({}, ['CommonOne', 'Main', 'Other']),
            ({'include_common_functions': False}, ['Main', 'Other']),
            ({'include_common_functions': False, 'filter_func': lambda func: func.name in ('CommonOne', 'Other')}, ['Other']),
        ):
            with self.subTest(settings = sorted(settings)):
                lines = self.listing_text(self.common, **settings).splitlines()
                self.assertEqual(function_headings(lines), expected)
                self.assertTrue(any(line.endswith(' name     "CommonOne"') for line in lines))

    def test_every_section_off(self):
        no_sections = ListingSections(**{field.name: False for field in fields(ListingSections)})
        with self.assertLogs(log, 'WARNING') as logs:
            text = self.listing_text(self.main, debug_sections = no_sections)

        self.assertEqual(text, '.debug.txt of main.dat\n')
        self.assertIn('every .debug.txt section is off', logs.output[0])


class TestRealScripts(unittest.TestCase):
    @unittest.skipUnless(CHECK_ALGO_USE_FILE.exists(), 'needs the sora2_1.0 corpus')
    def test_check_algo_use_records_all_tagged(self):
        lines = group_lines(ScpListing(CHECK_ALGO_USE_FILE).lines(ListingSections()), 'CheckAlgoUse')
        self.assertEqual(len([line for line in lines if line.startswith('[') and ' @ 0x' in line]), 22)
        self.assertEqual(len([line for line in lines if ';   record' in line]), 22)

    @unittest.skipUnless(DEAD_CODE_CALLS_FILE.exists(), 'needs the sora2_1.0 corpus')
    def test_dead_code_calls_tagged(self):
        listing = ScpListing(DEAD_CODE_CALLS_FILE)
        call_offsets, note = listing.pairing(listing.parser.get_func_by_name('AniBtlCraft01'))
        self.assertIsNone(note)
        self.assertTrue([offset for offset in call_offsets.values() if id(listing.decoded[offset][0][0]) in listing.unreachable])

    @unittest.skipUnless(CODE_BEFORE_FUNCTIONS_FILE.exists(), 'needs the sora2_1.0 corpus')
    def test_code_before_the_first_function(self):
        listing = ScpListing(CODE_BEFORE_FUNCTIONS_FILE)
        lines = listing.lines(ListingSections(header = False, global_vars = False, function_entries = False,
                                              call_records = False, string_pool = False))
        block = lines.index('=== Outside every function: 0xA4..0xB9 ===')
        first_function = next(i for i in range(block + 1, len(lines)) if lines[i].startswith('==='))
        self.assertEqual(code_area(listing, lines[block:first_function]), listing.data[0xA4:0xB9])
        self.assertEqual(code_area(listing, lines), whole_code_area(listing))

    @unittest.skipUnless(UNMARKED_CALL_FILE.exists(), 'needs the sora2_1.0 corpus')
    def test_unmarked_call_is_not_paired(self):
        lines = ScpListing(UNMARKED_CALL_FILE).lines(ListingSections(code = False))
        self.assertTrue(any('records not paired:' in line and ' calls, ' in line for line in lines))


if __name__ == '__main__':
    unittest.main()
