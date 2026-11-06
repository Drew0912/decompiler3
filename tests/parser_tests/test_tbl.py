#!/usr/bin/env python3
"""Unit tests for the .tbl reader (falcom/ed9/parser/tbl.py) on hand-built tables and sora1's and sora2's records"""

from pathlib import Path
import struct
import sys
import types
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.games.sora1 import tbl_records as sora1_records
from falcom.ed9.games.sora2 import tbl_records as sora2_records
from falcom.ed9.parser.tbl import RawTableEntry, TableDataEntry, TblParser, record_classes
from tests.shared.corpus import require

GAMES_DIR = REPO_ROOT / 'falcom' / 'ed9' / 'games'
NAME_TABLES = {
    'sora1': GAMES_DIR / 'sora1' / 'extracted' / 'table_en' / 't_name.tbl',
    'sora2': GAMES_DIR / 'sora2' / 'extracted' / 'table_en' / 't_name.tbl',
}
ENTRY_HEADER_SIZE = 8
SECTION_SIZE      = 0x50
NAME_SIZE         = 64
SLOT              = 8


class Pair(TableDataEntry):
    DESCRIPTOR = (('id', 'X'), ('text', 'S'))


class PairWide(TableDataEntry):
    SECTION = 'Pair'
    DESCRIPTOR = (('id', 'X'), ('text', 'S'), ('more', 'Q'))


CLASSES = {('Pair', Pair.record_size()): Pair}


def build_tbl(sections: list[tuple[str, int, list[list[int | str]]]], pool: bytes = None) -> bytes:
    """sections: (name, record size, records); a record's str slot becomes a pointer to it, placed in record order;
    pool, when given, is the data block, the numeric slots holding its pointers"""
    records_start = ENTRY_HEADER_SIZE + len(sections) * SECTION_SIZE
    block = records_start + sum(size * len(records) for _, size, records in sections)
    strings = bytearray()
    header = bytearray(b'#TBL' + struct.pack('<I', len(sections)))
    body = bytearray()
    start = records_start
    for name, size, records in sections:
        header += name.encode().ljust(NAME_SIZE, b'\0') + struct.pack('<4I', 0, start, size, len(records))
        for record in records:
            for slot in record:
                if isinstance(slot, str):
                    body += struct.pack('<Q', block + len(strings))
                    strings += slot.encode() + b'\0'
                else:
                    body += struct.pack('<Q', slot)
        start += size * len(records)

    return bytes(header + body + (strings if pool is None else pool))


def block_start(section_count: int, record_bytes: int) -> int:
    return ENTRY_HEADER_SIZE + section_count * SECTION_SIZE + record_bytes


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

    def test_a_pointer_at_end_of_file_is_an_empty_string(self):
        size = block_start(1, 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[7, size]])], pool=b'')
        parser = TblParser(data, CLASSES)
        self.assertEqual(parser.entries[0].text, '')
        self.assertEqual(parser.problems, [])

    def test_records_may_share_a_string(self):
        block = block_start(1, 2 * 2 * SLOT)
        data = build_tbl([('Pair', 2 * SLOT, [[1, block], [2, block]])], pool=b'same\0')
        parser = TblParser(data, CLASSES)
        self.assertEqual([e.text for e in parser.entries], ['same', 'same'])
        self.assertEqual(parser.problems, [])


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
        self.assertEqual(record_classes(sora2_records), record_classes(sora1_records))


class TestGeneratedScript(unittest.TestCase):
    def generated_entries(self, data: bytes) -> list:
        classes = record_classes(sora1_records)
        namespace = {}
        exec(TblParser(data, classes).gen_python_script(sora1_records.__name__), namespace)
        return namespace['entries']

    def test_a_script_imports_and_rebuilds_its_entries(self):
        text = "it's \"a\"\\\nエ"
        record = [0x10, text, 'model', 'face', 'ani', 30, 'F', 2, 'npc', 0, '', '', '']
        entry = self.generated_entries(build_tbl([('NameTableData', 13 * SLOT, [record])]))[0]
        self.assertIsInstance(entry, sora1_records.NameTableData)
        self.assertEqual((entry.chrId, entry.chrName, entry.num28), (0x10, text, 30))

    def test_a_raw_section_survives_in_the_script(self):
        entries = self.generated_entries(build_tbl([('Other', SLOT, [[1]])]))
        self.assertEqual(entries, [RawTableEntry('Other', '01 00 00 00 00 00 00 00')])


class TestNameTables(unittest.TestCase):
    def test_each_game_reads_with_every_byte_accounted_for(self):
        for game, records in (('sora1', sora1_records), ('sora2', sora2_records)):
            with self.subTest(game=game):
                path = require(NAME_TABLES[game])
                parser = TblParser(path.read_bytes(), record_classes(records))
                self.assertEqual(parser.problems, [])
                self.assertEqual(parser.raw_sections, [])

    def test_sora2s_first_row(self):
        path = require(NAME_TABLES['sora2'])
        entry = TblParser(path.read_bytes(), record_classes(sora2_records)).entries[0]
        self.assertEqual((entry.chrId, entry.chrName, entry.model, entry.ani), (0, 'Estelle', 'chr5000_c10', 'chr5000'))


if __name__ == '__main__':
    unittest.main()
