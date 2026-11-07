#!/usr/bin/env python3
"""Each game's writer: the first import of a game's script installs it, before the script's hook registers on it"""

from pathlib import Path
from types import ModuleType
import importlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.games import GAMES_PACKAGE, game_names
from falcom.ed9.structs.generated_script import SYS_PATH_SETUP_LINES, game_writer_helper_import
from falcom.ed9.writer import scp_writer_helper
from tests.shared.scp_writer_test_utils import fresh_writer

SCRIPT = """
import script_hook

scena = create_scp_writer('script.dat')


@scena.LLILCode()
def Main():
    RETURN()


scena.run(globals())
"""

HOOK = """
from falcom.ed9.writer.scp_writer_helper import *


def report_writer(g):
    print(type(get_scp_writer()).__module__)


registerRunCallback(report_writer)
"""


def public_names(module: ModuleType) -> set[str]:
    return {name for name in vars(module) if not name.startswith('_')}


class TestGameWriters(unittest.TestCase):
    def test_a_script_and_its_hook_reach_the_game_writer(self):
        """In a process of its own, as every compile runs: the script's first import is what names the game"""
        for game in game_names():
            with self.subTest(game=game), tempfile.TemporaryDirectory() as folder:
                script = Path(folder) / 'script.py'
                header = [*SYS_PATH_SETUP_LINES, game_writer_helper_import(game)]
                script.write_text('\n'.join(header) + SCRIPT, encoding='utf-8')
                (Path(folder) / 'script_hook.py').write_text(HOOK, encoding='utf-8')
                done = subprocess.run([sys.executable, '-B', script.name], cwd=folder, capture_output=True, text=True,
                                      stdin=subprocess.DEVNULL)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout.strip(), f'{GAMES_PACKAGE}.{game}.writer.scp_writer')
                self.assertTrue((Path(folder) / 'script.dat').is_file())

    def test_a_game_helper_gives_a_script_the_shared_names(self):
        """gen_common_library reserves the shared helper's names: one more here would go unchecked"""
        self.addCleanup(fresh_writer)
        for game in game_names():
            with self.subTest(game=game):
                helper = importlib.import_module(f'{GAMES_PACKAGE}.{game}.writer.scp_writer_helper')
                self.assertEqual(public_names(helper), public_names(scp_writer_helper))


if __name__ == '__main__':
    unittest.main()
