#!/usr/bin/env python3
"""Unit tests for the .tbl reader and writer (falcom/ed9/parser/tbl.py) on hand-built tables and sora1's and sora2's
records"""

from contextlib import chdir
from pathlib import Path
import struct
import sys
import tempfile
import traceback
import types
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.games.sora1.tbl import tbl_records as sora1_records
from falcom.ed9.games.sora2.tbl import tbl_records as sora2_records
from falcom.ed9.parser.tbl import RawSection, RawTableEntry, TableDataEntry, TblParser, record_classes, tbl_bytes
from falcom.ed9.structs.crc32 import hash_function_name
from tests.shared.corpus import require

GAMES_DIR = REPO_ROOT / 'falcom' / 'ed9' / 'games'
NAME_TABLES = {
    'sora1': GAMES_DIR / 'sora1' / 'extracted' / 'table_en' / 't_name.tbl',
    'sora2': GAMES_DIR / 'sora2' / 'extracted' / 'table_en' / 't_name.tbl',
}
# No pointers, so nothing could check a class for them
UNCHECKED_SECTIONS = {'ConstantValue', 'BTResultTable', 'DLCAppIDConvertTableData'}
ENTRY_HEADER_SIZE = 8
SECTION_SIZE      = 0x50
NAME_SIZE         = 64
SLOT              = 8
NAME_TABLE_SIZE   = 13 * SLOT


class Pair(TableDataEntry):
    DESCRIPTOR = (('id', 'X'), ('text', 'S'))


class PairWide(TableDataEntry):
    SECTION = 'Pair'
    DESCRIPTOR = (('id', 'X'), ('text', 'S'), ('more', 'Q'))


class Mixed(TableDataEntry):
    DESCRIPTOR = (('low', 'W'), ('high', 'W'), ('count', 'I'), ('code', 'L'), ('ratio', 'f'), ('wide', 'X'),
                  ('big', 'Q'))


class Lists(TableDataEntry):
    DESCRIPTOR = (('shorts', 'A2'), ('pad', 'I'), ('text', 'S'), ('words', 'A4'), ('pad2', 'I'))


CLASSES = {('Pair', Pair.record_size()): Pair}
LIST_CLASSES = {('Lists', Lists.record_size()): Lists}
LISTS_SIZE = Lists.record_size()


def array(pointer: int, count: int) -> bytes:
    return struct.pack('<QII', pointer, count, 0)


def build_tbl(sections: list[tuple[str, int, list[list[int | str]]]], pool: bytes = None) -> bytes:
    """sections: (name, record size, records); a record's str slot becomes a pointer to it, placed in record order, a
    bytes slot goes in as it is; pool, when given, is the data block, the numeric slots holding its pointers"""
    records_start = ENTRY_HEADER_SIZE + len(sections) * SECTION_SIZE
    block = records_start + sum(size * len(records) for _, size, records in sections)
    strings = bytearray()
    header = bytearray(b'#TBL' + struct.pack('<I', len(sections)))
    body = bytearray()
    start = records_start
    for name, size, records in sections:
        entry = struct.pack('<4I', hash_function_name(name), start, size, len(records))
        header += name.encode().ljust(NAME_SIZE, b'\0') + entry
        for record in records:
            for slot in record:
                if isinstance(slot, str):
                    body += struct.pack('<Q', block + len(strings))
                    strings += slot.encode() + b'\0'
                elif isinstance(slot, bytes):
                    body += slot
                else:
                    body += struct.pack('<Q', slot)
        start += size * len(records)

    return bytes(header + body + (strings if pool is None else pool))


def block_start(section_count: int, record_bytes: int) -> int:
    return ENTRY_HEADER_SIZE + section_count * SECTION_SIZE + record_bytes


def name_row(chr_id: int, name: str) -> list:
    return [chr_id, name, 'model', 'face', 'ani', 30, 'F', 2, 'npc', 0, '', '', '']


class TestReading(unittest.TestCase):
    def test_a_record_reads_through_its_class(self):
        data = build_tbl([('Pair', 2 * SLOT, [[7, 'Estelle'], [8, 'エステル']])])
        parser = TblParser(data, CLASSES)
        self.assertEqual([(e.id, e.text) for e in parser.entries], [(7, 'Estelle'), (8, 'エステル')])
        self.assertEqual(parser.problems, [])

    def test_sections_are_found_by_their_entries(self):
        data = build_tbl([('Other', SLOT, [[1], [2]]), ('Pair', 2 * SLOT, [[7, 'a']]), ('Empty', SLOT, [])])
        parser = TblParser(data, CLASSES)
        self.assertEqual([e.text for e in parser.entries if isinstance(e, Pair)], ['a'])
        self.assertEqual(parser.raw_sections, ['Other'])

    def test_a_section_with_no_class_stays_raw_hex(self):
        parser = TblParser(build_tbl([('Other', SLOT, [[0xAB]])]), CLASSES)
        self.assertEqual(parser.entries, [RawTableEntry('Other', 'AB 00 00 00 00 00 00 00')])
        self.assertEqual(parser.problems, [])

    def test_records_may_share_a_string(self):
        block = block_start(1, 2 * 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[1, block], [2, block]])], pool=b'same\0')
        parser = TblParser(data, CLASSES)
        self.assertEqual([e.text for e in parser.entries], ['same', 'same'])
        self.assertEqual(parser.problems, [])


class TestFieldKinds(unittest.TestCase):
    def test_each_number_kind_reads_its_width(self):
        record = struct.pack('<HHIIfQQ', 0x1234, 0x5678, 7, 0xAABBCCDD, 1.5, 0x10, 20)
        parser = TblParser(build_tbl([('Mixed', len(record), [[record]])]), {('Mixed', len(record)): Mixed})
        entry = parser.entries[0]
        self.assertEqual((entry.low, entry.high, entry.count, entry.code, entry.ratio, entry.wide, entry.big),
                         (0x1234, 0x5678, 7, 0xAABBCCDD, 1.5, 0x10, 20))
        self.assertEqual(parser.problems, [])


class TestArrays(unittest.TestCase):
    def parse(self, record: list, pool: bytes) -> TblParser:
        return TblParser(build_tbl([('Lists', LISTS_SIZE, [record])], pool=pool), LIST_CLASSES)

    def lists_block(self) -> int:
        return block_start(1, LISTS_SIZE)

    def test_arrays_read_their_elements(self):
        block = self.lists_block()
        pool = struct.pack('<HH', 3, 4) + b'a\0\0\0' + struct.pack('<I', 9)
        parser = self.parse([array(block, 2), struct.pack('<Q', block + 4), array(block + 8, 1)], pool)
        entry = parser.entries[0]
        self.assertEqual(parser.problems, [])
        self.assertEqual((entry.shorts, entry.text, entry.words), ([3, 4], 'a', [9]))

    def test_padding_may_align_an_array_after_a_string(self):
        block = self.lists_block()
        pool = b'a\0\0\0' + struct.pack('<I', 9)
        record = [array(block, 0), struct.pack('<Q', block), array(block + 4, 1)]
        parser = self.parse(record, pool)
        self.assertEqual(parser.problems, [])
        self.assertEqual((parser.entries[0].shorts, parser.entries[0].text, parser.entries[0].words), ([], 'a', [9]))

    def test_an_empty_array_explains_the_padding_before_it(self):
        block = self.lists_block()
        record = [array(block + 4, 0), struct.pack('<Q', block), array(block + 4, 0)]
        self.assertEqual(self.parse(record, b'ab\0\0').problems, [])

    def test_non_zero_bytes_are_never_padding(self):
        block = self.lists_block()
        pool = b'a\0\xff\0' + struct.pack('<I', 9)
        record = [array(block, 0), struct.pack('<Q', block), array(block + 4, 1)]
        self.assertEqual(self.parse(record, pool).problems, [f'data block: gap at {block + 2:#x}'])

    def test_padding_shorter_than_the_alignment_only(self):
        block = self.lists_block()
        pool = b'a\0\0\0\0\0\0\0' + struct.pack('<I', 9)
        record = [array(block, 0), struct.pack('<Q', block), array(block + 8, 1)]
        self.assertEqual(self.parse(record, pool).problems, [f'data block: gap at {block + 2:#x}'])

    def test_an_unaligned_array_does_not_fit(self):
        block = self.lists_block()
        pool = b'a\0\0' + struct.pack('<I', 9)
        record = [array(block, 0), struct.pack('<Q', block), array(block + 3, 1)]
        self.assertEqual(self.parse(record, pool).raw_sections, ['Lists'])

    def test_an_array_past_the_end_does_not_fit(self):
        block = self.lists_block()
        record = [array(block, 3), struct.pack('<Q', block + 4), array(block + 4, 0)]
        self.assertEqual(self.parse(record, b'\0\0\0\0').raw_sections, ['Lists'])

    def test_an_array_before_the_block_does_not_fit(self):
        block = self.lists_block()
        record = [array(0, 0), struct.pack('<Q', block), array(block, 0)]
        self.assertEqual(self.parse(record, b'a\0').raw_sections, ['Lists'])


class TestMismatches(unittest.TestCase):
    def test_a_known_name_at_another_size_is_reported_and_stays_raw(self):
        parser = TblParser(build_tbl([('Pair', 3 * SLOT, [[1, 'a', 2]])]), CLASSES)
        self.assertEqual(parser.raw_sections, ['Pair'])
        self.assertEqual(parser.problems, ['Pair: record size 0x18, classes for 0x10'])

    def test_a_moved_string_at_the_same_size_is_caught_by_its_pointer(self):
        """MonsterSettingParam 0xa8 in sora1 and sora2: the size matches, the class's pointer slot holds 0"""
        class Moved(TableDataEntry):
            SECTION = 'Pair'
            DESCRIPTOR = (('text', 'S'), ('id', 'X'))

        data = build_tbl([('Pair', 2 * SLOT, [[0, 'a']])])
        parser = TblParser(data, {('Pair', Moved.record_size()): Moved})
        self.assertEqual(parser.raw_sections, ['Pair'])
        self.assertIn('Moved does not fit: pointer 0x0', parser.problems[0])

    def test_a_pointer_into_a_character_does_not_fit(self):
        block = block_start(1, 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[1, block + 1]])], pool='エ'.encode() + b'\0')
        parser = TblParser(data, CLASSES)
        self.assertEqual(parser.raw_sections, ['Pair'])

    def test_a_string_pointer_at_end_of_file_does_not_fit(self):
        data = build_tbl([('Pair', 2 * SLOT, [[7, block_start(1, 2 * SLOT)]])], pool=b'')
        self.assertEqual(TblParser(data, CLASSES).raw_sections, ['Pair'])

    def test_an_unterminated_string_does_not_fit(self):
        block = block_start(1, 2 * SLOT)
        parser = TblParser(build_tbl([('Pair', 2 * SLOT, [[1, block]])], pool=b'abc'), CLASSES)
        self.assertEqual(parser.raw_sections, ['Pair'])

    def test_a_string_nothing_reaches_is_a_gap(self):
        block = block_start(1, 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[1, block + 2]])], pool=b'x\0a\0')
        parser = TblParser(data, CLASSES)
        self.assertEqual(parser.problems, [f'data block: gap at {block:#x}'])

    def test_bytes_after_the_last_string_are_a_gap(self):
        block = block_start(1, 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[1, block]])], pool=b'a\0x\0')
        self.assertEqual(TblParser(data, CLASSES).problems, [f'data block: gap at {block + 2:#x}'])

    def test_overlapping_strings_are_reported(self):
        block = block_start(1, 2 * 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[1, block], [2, block + 1]])], pool=b'ab\0')
        self.assertEqual(TblParser(data, CLASSES).problems, [f'data block: overlap at {block + 1:#x}'])

    def test_a_raw_section_leaves_the_data_block_unchecked(self):
        data = build_tbl([('Pair', 2 * SLOT, [[1, 'a']]), ('Other', SLOT, [['b']])])
        self.assertEqual(TblParser(data, CLASSES).problems, [])


class TestRecordClasses(unittest.TestCase):
    def test_a_section_may_have_a_class_per_size(self):
        module = types.ModuleType('records')
        module.Pair, module.PairWide, module.TableDataEntry = Pair, PairWide, TableDataEntry
        self.assertEqual(record_classes(module), {('Pair', 2 * SLOT): Pair, ('Pair', 3 * SLOT): PairWide})

    def test_sora2_gets_sora1s_class_through_the_star_import(self):
        self.assertIs(sora2_records.NameTableData, sora1_records.NameTableData)
        self.assertIs(sora2_records.NPCParam, sora1_records.NPCParam)

    def test_a_class_of_the_same_name_replaces_sora1s(self):
        classes = record_classes(sora2_records)
        self.assertIs(classes['MonsterSettingParam', 0xb0], sora2_records.MonsterSettingParam)
        self.assertIs(classes['MonsterSettingParam', 0xa8], sora2_records.MonsterSettingParamA8)
        self.assertIs(record_classes(sora1_records)['MonsterSettingParam', 0xa8], sora1_records.MonsterSettingParam)


class TestRebuilding(unittest.TestCase):
    def assert_rebuilds(self, data: bytes, classes: dict) -> None:
        self.assertEqual(tbl_bytes(TblParser(data, classes).entries), data)

    def test_records_and_strings_come_back_byte_for_byte(self):
        self.assert_rebuilds(build_tbl([('Pair', 2 * SLOT, [[7, 'Estelle'], [8, ''], [9, 'エステル']])]), CLASSES)

    def test_each_number_kind_writes_its_width(self):
        record = struct.pack('<HHIIfQQ', 0x1234, 0x5678, 7, 0xAABBCCDD, 1.5, 0x10, 20)
        self.assert_rebuilds(build_tbl([('Mixed', len(record), [[record]])]), {('Mixed', len(record)): Mixed})

    def test_sections_keep_their_order(self):
        self.assert_rebuilds(build_tbl([('Pair', 2 * SLOT, [[7, 'a']]), ('Other', SLOT, [[1]])]), CLASSES)

    def test_arrays_pad_to_their_element_and_count_their_elements(self):
        block = block_start(1, LISTS_SIZE)
        pool = struct.pack('<H', 3) + b'ab\0\0\0\0' + struct.pack('<I', 9)
        record = [array(block, 1), struct.pack('<Q', block + 2), array(block + 8, 1)]
        self.assert_rebuilds(build_tbl([('Lists', LISTS_SIZE, [record])], pool=pool), LIST_CLASSES)

    def test_an_empty_array_still_pads_the_block(self):
        block = block_start(1, LISTS_SIZE)
        record = [array(block, 0), struct.pack('<Q', block), array(block + 4, 0)]
        self.assert_rebuilds(build_tbl([('Lists', LISTS_SIZE, [record])], pool=b'ab\0\0'), LIST_CLASSES)

    def test_a_longer_string_moves_the_pointers_after_it(self):
        parser = TblParser(build_tbl([('Pair', 2 * SLOT, [[1, 'a'], [2, 'b']])]), CLASSES)
        parser.entries[0].text = 'longer エ'
        edited = TblParser(tbl_bytes(parser.entries), CLASSES)
        self.assertEqual([entry.text for entry in edited.entries], ['longer エ', 'b'])
        self.assertEqual(edited.problems, [])

    def test_counts_that_miss_a_row_are_an_error(self):
        entries = TblParser(build_tbl([('Pair', 2 * SLOT, [[1, 'a'], [2, 'b']])]), CLASSES).entries
        with self.assertRaisesRegex(ValueError, 'counts 1 rows, entries has 2'):
            tbl_bytes(entries, [(Pair, 1)])

    def test_a_row_in_the_wrong_section_is_an_error(self):
        entries = [RawTableEntry('Other', '00 00 00 00 00 00 00 00')]
        with self.assertRaisesRegex(ValueError, 'row of Other, record size 0x8, in section Third, record size 0x8'):
            tbl_bytes(entries, [(RawSection('Third', SLOT), 1)])

    def test_a_raw_row_of_another_length_is_an_error(self):
        entries = [RawTableEntry('Other', '01 02'), RawTableEntry('Other', '03')]
        with self.assertRaisesRegex(ValueError, r'entries\[1\]: Other row of record size 0x1, the rows before it 0x2'):
            tbl_bytes(entries)

    def test_a_row_of_the_wrong_size_is_an_error(self):
        entries = [RawTableEntry('Other', '01 02')]
        with self.assertRaisesRegex(ValueError, 'row of Other, record size 0x2, in section Other, record size 0x8'):
            tbl_bytes(entries, [(RawSection('Other', SLOT), 1)])


class TestRowMistakes(unittest.TestCase):
    def test_an_unknown_field_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'Pair: unknown or missing fields: extra'):
            Pair(id=1, text='a', extra=2)

    def test_a_missing_field_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'Pair: unknown or missing fields: text'):
            Pair(id=1)

    def test_a_number_too_wide_is_an_error(self):
        with self.assertRaisesRegex(ValueError, f'Pair: id = {1 << 64} does not fit its field'):
            Pair(id=1 << 64, text='a')

    def test_an_array_element_too_wide_is_an_error(self):
        with self.assertRaisesRegex(ValueError, r'Lists: shorts = \[70000\] does not fit its field'):
            Lists(shorts=[70000], pad=0, text='', words=[], pad2=0)

    def test_a_float_too_big_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'Mixed: ratio = 1e[+]40 does not fit its field'):
            Mixed(low=0, high=0, count=0, code=0, ratio=1e40, wide=0, big=0)


class TestGeneratedScript(unittest.TestCase):
    def setUp(self):
        self.enterContext(chdir(self.enterContext(tempfile.TemporaryDirectory())))

    def script(self, data: bytes) -> str:
        return TblParser(data, record_classes(sora1_records)).gen_python_script(sora1_records.__name__, 't_x.tbl')

    def generated_entries(self, data: bytes) -> list:
        namespace = {}
        exec(self.script(data), namespace)
        return namespace['entries']

    def assert_writes(self, data: bytes, call: str) -> None:
        script = self.script(data)
        self.assertIn(call, script)
        exec(script, {'__name__': '__main__'})
        self.assertEqual(Path('t_x.tbl').read_bytes(), data)

    def test_a_script_imports_and_rebuilds_its_entries(self):
        text = "it's \"a\"\\\nエ"
        entry = self.generated_entries(build_tbl([('NameTableData', NAME_TABLE_SIZE, [name_row(0x10, text)])]))[0]
        self.assertIsInstance(entry, sora1_records.NameTableData)
        self.assertEqual((entry.chrId, entry.chrName, entry.uint64_28), (0x10, text, 30))

    def test_a_raw_section_survives_in_the_script(self):
        entries = self.generated_entries(build_tbl([('Other', SLOT, [[1]])]))
        self.assertEqual(entries, [RawTableEntry('Other', '01 00 00 00 00 00 00 00')])

    def test_a_script_writes_its_table(self):
        data = build_tbl([('NameTableData', NAME_TABLE_SIZE, [name_row(1, 'a'), name_row(2, 'b')])])
        self.assert_writes(data, "create_tbl('t_x.tbl', *entries)")

    def test_importing_a_script_writes_nothing(self):
        script = self.script(build_tbl([('NameTableData', NAME_TABLE_SIZE, [name_row(1, 'a')])]))
        exec(script, {'__name__': 'imported_table'})
        self.assertEqual(list(Path('.').iterdir()), [])

    def test_a_repeated_section_is_listed_one_per_line(self):
        rows = [name_row(1, 'a'), name_row(2, 'b')], [name_row(3, 'c')]
        data = build_tbl([('NameTableData', NAME_TABLE_SIZE, section_rows) for section_rows in rows])
        self.assert_writes(data, 'sections=[\n        (NameTableData, 2),\n        (NameTableData, 1),\n    ])')

    def test_an_empty_section_is_listed(self):
        self.assert_writes(build_tbl([('NameTableData', NAME_TABLE_SIZE, [])]), '(NameTableData, 0),')

    def test_an_empty_section_with_no_class_is_listed_by_name_and_size(self):
        data = build_tbl([('NameTableData', NAME_TABLE_SIZE, [name_row(1, 'a')]), ('Other', 10, [])])
        self.assert_writes(data, "(RawSection('Other', 0xa), 0),")

    def test_a_row_mistake_points_at_its_line_in_the_script(self):
        script = self.script(build_tbl([('NameTableData', NAME_TABLE_SIZE, [name_row(1, 'a'), name_row(2, 'b')])]))
        lines = script.splitlines()
        second_row = [number for number, line in enumerate(lines, 1) if 'NameTableData(' in line][1]
        lines[second_row] = lines[second_row].replace('chrId', 'chrIdd')
        try:
            exec(compile('\n'.join(lines), 't_x.py', 'exec'), {})
        except ValueError as error:    # assertRaises drops the traceback
            self.assertIn('unknown or missing fields: chrId, chrIdd', str(error))
            frames = traceback.extract_tb(error.__traceback__)

        self.assertEqual([frame.lineno for frame in frames if frame.filename == 't_x.py'], [second_row])


class TestCorpusTables(unittest.TestCase):
    def test_each_game_reads_with_every_byte_accounted_for(self):
        for game, records in (('sora1', sora1_records), ('sora2', sora2_records)):
            with self.subTest(game=game):
                path = require(NAME_TABLES[game])
                parser = TblParser(path.read_bytes(), record_classes(records))
                self.assertEqual(parser.problems, [])
                self.assertEqual(parser.raw_sections, [])

    def test_every_table_reads_with_every_byte_accounted_for_and_rebuilds(self):
        for game, records in (('sora1', sora1_records), ('sora2', sora2_records)):
            classes = record_classes(records)
            for path in sorted(require(NAME_TABLES[game]).parent.glob('*.tbl')):
                with self.subTest(game=game, table=path.name):
                    data = path.read_bytes()
                    parser = TblParser(data, classes)
                    self.assertEqual(parser.problems, [])
                    self.assertLessEqual(set(parser.raw_sections), UNCHECKED_SECTIONS)
                    sections = [(RawSection(s.name, s.record_size), s.count) for s in parser.sections]
                    self.assertEqual(tbl_bytes(parser.entries, sections), data)

    def test_sora2s_first_row(self):
        path = require(NAME_TABLES['sora2'])
        entry = TblParser(path.read_bytes(), record_classes(sora2_records)).entries[0]
        self.assertEqual((entry.chrId, entry.chrName, entry.model, entry.ani), (0, 'Estelle', 'chr5000_c10', 'chr5000'))


if __name__ == '__main__':
    unittest.main()
