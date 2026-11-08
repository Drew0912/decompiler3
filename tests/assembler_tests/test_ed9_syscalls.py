#!/usr/bin/env python3
"""SyscallArgs: which row a syscall's command and argument count take, and the letters' check; game_syscall_args: a
game's rows, none without its module, an import failure inside it re-raised"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.assembler.ed9_syscalls import ANY_ARGC, Subsystem, SyscallArgs, SyscallEntry, game_syscall_args
from falcom.ed9.consts import CHR_ID_KIND
from tests.shared.stand_in_game import FAILING_IMPORT_SOURCE, plant_game

CMD = 0x19
ARGC = 3
OTHER_ARGC = 5

ROWS_SOURCE = f"""from falcom.ed9.assembler.ed9_syscalls import Subsystem, SyscallEntry

SYSCALL_TABLE = [SyscallEntry(Subsystem.Chr, {CMD}, {ARGC}, 'N')]
"""


class TestRowLookup(unittest.TestCase):

    def test_an_exact_count_wins_over_any_count_in_either_order(self):
        exact = SyscallEntry(Subsystem.Chr, CMD, ARGC, 'N')
        any_count = SyscallEntry(Subsystem.Chr, CMD, ANY_ARGC, '.N')
        for rows in ([exact, any_count], [any_count, exact]):
            with self.subTest(first=rows[0].argc):
                args = SyscallArgs(rows)
                self.assertEqual(args.id_kinds(Subsystem.Chr, CMD, ARGC), {0: CHR_ID_KIND})
                self.assertEqual(args.id_kinds(Subsystem.Chr, CMD, OTHER_ARGC), {1: CHR_ID_KIND})

    def test_a_later_row_wins(self):
        args = SyscallArgs([SyscallEntry(Subsystem.Chr, CMD, ARGC, 'N'), SyscallEntry(Subsystem.Chr, CMD, ARGC, '..N')])

        self.assertEqual(args.id_kinds(Subsystem.Chr, CMD, ARGC), {2: CHR_ID_KIND})

    def test_no_row_no_ids(self):
        args = SyscallArgs([SyscallEntry(Subsystem.Chr, CMD, ARGC, 'N')])

        self.assertEqual(args.id_kinds(Subsystem.Chr, CMD, OTHER_ARGC), {})
        self.assertEqual(args.id_kinds(Subsystem.Mes, CMD, ARGC), {})

    def test_an_unknown_letter_raises_naming_the_row(self):
        entry = SyscallEntry(Subsystem.Chr, CMD, ARGC, 'Nx')

        with self.assertRaises(ValueError) as raised:
            SyscallArgs([entry])

        self.assertIn(repr(entry), str(raised.exception))


class TestGameSyscallArgs(unittest.TestCase):

    def setUp(self):
        game_syscall_args.cache_clear()
        self.addCleanup(game_syscall_args.cache_clear)

    def test_a_games_rows_load(self):
        game = plant_game(self, {'syscall_args': ROWS_SOURCE})

        self.assertEqual(game_syscall_args(game).id_kinds(Subsystem.Chr, CMD, ARGC), {0: CHR_ID_KIND})

    def test_no_module_no_rows(self):
        self.assertIsNone(game_syscall_args(plant_game(self, {})))
        self.assertIsNone(game_syscall_args(None))

    def test_an_import_failure_inside_the_module_reraises(self):
        game = plant_game(self, {'syscall_args': FAILING_IMPORT_SOURCE})

        with self.assertRaises(ModuleNotFoundError):
            game_syscall_args(game)

    def test_sora2s_rows_load(self):
        self.assertTrue(game_syscall_args('sora2').kinds)


if __name__ == '__main__':
    unittest.main()
