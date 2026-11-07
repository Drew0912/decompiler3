"""Unit tests for falcom/ed9/tools/gen_tables.py: which ID gets which name, and the generated table both ways"""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.tools.gen_tables import CHR_TABLE_NAME, NO_CHR_ID, chr_names, chr_table_text


def rows(*pairs: tuple[int, str]) -> list[SimpleNamespace]:
    return [SimpleNamespace(chrId=chr_id, chrName=name) for chr_id, name in pairs]


class TestChrNames(unittest.TestCase):
    def test_a_row_with_no_id_is_left_out(self):
        self.assertEqual(chr_names(rows((0, 'Estelle'), (NO_CHR_ID, 'Estelle - Costume'))), {0: 'Estelle'})

    def test_the_first_row_of_an_id_wins(self):
        self.assertEqual(chr_names(rows((0x6C, 'Richard'), (0x6C, 'Richard - Prisoner Uniform'))), {0x6C: 'Richard'})

    def test_a_repeated_name_adds_the_later_ids_in_hex(self):
        names = chr_names(rows((0, 'Estelle'), (0xA5, 'Estelle'), (0x7D4, 'Estelle')))
        self.assertEqual(names, {0: 'Estelle', 0xA5: 'Estelle_00A5', 0x7D4: 'Estelle_07D4'})

    def test_a_row_of_a_taken_id_does_not_count_as_a_repeat(self):
        names = chr_names(rows((1, 'Joshua'), (1, 'Agate'), (2, 'Agate')))
        self.assertEqual(names, {1: 'Joshua', 2: 'Agate'})

    def test_outer_whitespace_is_no_part_of_a_name(self):
        self.assertEqual(chr_names(rows((1, 'Youth\t'), (2, 'Youth'))), {1: 'Youth', 2: 'Youth_0002'})

    def test_a_suffixed_name_that_is_already_taken_is_an_error(self):
        with self.assertRaisesRegex(ValueError, 'Estelle_0002 is already a name'):
            chr_names(rows((0, 'Estelle'), (1, 'Estelle_0002'), (2, 'Estelle')))


class TestChrTableText(unittest.TestCase):
    def test_the_table_reads_both_ways(self):
        names = {0: 'Estelle', 0xA5: "Groom's Family"}
        namespace = {}
        exec(chr_table_text(names), namespace)
        table = namespace[CHR_TABLE_NAME]
        self.assertEqual(table, {'Estelle': 0, "Groom's Family": 0xA5, 0: 'Estelle', 0xA5: "Groom's Family"})

    def test_ids_print_in_hex(self):
        text = chr_table_text({0xA5: 'Agate'})
        self.assertIn("'Agate': 0x00A5,", text)
        self.assertIn("0x00A5: 'Agate',", text)


if __name__ == '__main__':
    unittest.main()
