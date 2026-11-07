"""Unit tests for falcom/ed9/tools/gen_tables.py: which ID gets which name, and the generated tables both ways"""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.tools.gen_tables import ID_TABLES, NO_CHR_ID, chr_names, id_table_text, item_names, unique_names

CHR_TABLE = ID_TABLES[0]


def chr_rows(*pairs: tuple[int, str]) -> list[SimpleNamespace]:
    return [SimpleNamespace(chrId=chr_id, chrName=name) for chr_id, name in pairs]


class TestUniqueNames(unittest.TestCase):
    def test_the_first_row_of_an_id_wins(self):
        self.assertEqual(unique_names([(0x6C, 'Richard'), (0x6C, 'Richard - Prisoner Uniform')]), {0x6C: 'Richard'})

    def test_a_repeated_name_adds_the_later_ids_in_hex(self):
        names = unique_names([(0, 'Estelle'), (0xA5, 'Estelle'), (0x7D4, 'Estelle')])
        self.assertEqual(names, {0: 'Estelle', 0xA5: 'Estelle_00A5', 0x7D4: 'Estelle_07D4'})

    def test_a_row_of_a_taken_id_does_not_count_as_a_repeat(self):
        self.assertEqual(unique_names([(1, 'Joshua'), (1, 'Agate'), (2, 'Agate')]), {1: 'Joshua', 2: 'Agate'})

    def test_outer_whitespace_is_no_part_of_a_name(self):
        self.assertEqual(unique_names([(1, 'Youth\t'), (2, 'Youth　')]), {1: 'Youth', 2: 'Youth_0002'})

    def test_a_suffixed_name_that_is_already_taken_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'Estelle_0002 is already a name'):
            unique_names([(0, 'Estelle'), (1, 'Estelle_0002'), (2, 'Estelle')])


class TestTableNames(unittest.TestCase):
    def test_a_character_row_with_no_id_is_left_out(self):
        self.assertEqual(chr_names(chr_rows((0, 'Estelle'), (NO_CHR_ID, 'Estelle - Costume'))), {0: 'Estelle'})

    def test_items_name_by_their_id_and_name_fields(self):
        rows = [SimpleNamespace(id=0xFD, name='Platinum Ring'), SimpleNamespace(id=0x6A5, name='Platinum Ring')]
        self.assertEqual(item_names(rows), {0xFD: 'Platinum Ring', 0x6A5: 'Platinum Ring_06A5'})


class TestIdTableText(unittest.TestCase):
    def test_the_table_reads_both_ways(self):
        names = {0: 'Estelle', 0xA5: "Groom's Family"}
        namespace = {}
        exec(id_table_text(CHR_TABLE, names), namespace)
        table = namespace[CHR_TABLE.name]
        self.assertEqual(table, {'Estelle': 0, "Groom's Family": 0xA5, 0: 'Estelle', 0xA5: "Groom's Family"})

    def test_ids_print_in_hex(self):
        text = id_table_text(CHR_TABLE, {0xA5: 'Agate'})
        self.assertIn("'Agate': 0x00A5,", text)
        self.assertIn("0x00A5: 'Agate',", text)


if __name__ == '__main__':
    unittest.main()
