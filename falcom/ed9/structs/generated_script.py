"""The lines generated scripts and modules share"""

from dc3.utils import PROJECT_ROOT
from ..games import GAMES_PACKAGE

# First lines of every generated script: the generating checkout's root, so it runs without PYTHONPATH
SYS_PATH_SETUP_LINES = ['import sys', f'sys.path.insert(0, {str(PROJECT_ROOT)!r})']

# PEP 8's two blank lines after each top-level definition of a generated script, and after its header
DEFINITION_SPACING = ['', '']

# Library modules, hook files and a script with no game; one place they all spell it
SCP_WRITER_HELPER_IMPORT = 'from falcom.ed9.writer.scp_writer_helper import *'


def game_writer_helper_import(game: str) -> str:
    """A game's script's first import: the shared helper's names, with the game's writer installed"""
    return f'from {GAMES_PACKAGE}.{game}.writer.scp_writer_helper import *'
