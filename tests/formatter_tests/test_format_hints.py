#!/usr/bin/env python3
"""game_format_hints: the character IDs' IdFormatHint takes the ID -> name half of a game's two-way chr_table.py;
without one, only the pseudo IDs have names; an import failure inside it re-raises. Always run: a stand-in game, not
the generated table"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.logging import log
from falcom.ed9.consts import CHR_ID_KIND, PseudoChrId
from falcom.ed9.formatter.format_hints import game_format_hints
from tests.shared.stand_in_game import FAILING_IMPORT_SOURCE, plant_game

CHR_TABLE_SOURCE = "ChrIdTable = {'Estelle': 0, 0: 'Estelle'}\n"


class TestGameFormatHints(unittest.TestCase):

    def setUp(self):
        game_format_hints.cache_clear()
        self.addCleanup(game_format_hints.cache_clear)

    def test_the_names_are_the_id_to_name_half(self):
        hint = game_format_hints(plant_game(self, {'chr_table': CHR_TABLE_SOURCE}))[CHR_ID_KIND]

        self.assertEqual(hint.names, {0: 'Estelle'})
        self.assertEqual(set(hint.pseudo_names), set(PseudoChrId))

    def test_without_a_chr_table_only_the_pseudo_ids_have_names(self):
        with self.assertLogs(log, 'INFO'):
            hint = game_format_hints(plant_game(self, {}))[CHR_ID_KIND]

        self.assertEqual(hint.names, {})
        self.assertEqual(set(hint.pseudo_names), set(PseudoChrId))

    def test_an_import_failure_inside_the_table_reraises(self):
        game = plant_game(self, {'chr_table': FAILING_IMPORT_SOURCE})

        with self.assertRaises(ModuleNotFoundError):
            game_format_hints(game)


if __name__ == '__main__':
    unittest.main()
