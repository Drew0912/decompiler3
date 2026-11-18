"""The import lines generated scripts and modules share, the names those imports bring, and the spacing after their
definitions"""

import importlib

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


def hlil_dsl_helper_module(game: str) -> str:
    """The module a mixed script star-imports for the HLIL DSL's names: its game's, with the game's own DSL helpers"""
    return f'{GAMES_PACKAGE}.{game}.writer.scp_hlil_dsl_helper'


def hlil_dsl_helper_import(game: str) -> str:
    return f'from {hlil_dsl_helper_module(game)} import *'


def hlil_dsl_namespace(game: str) -> dict[str, object]:
    """The names game's HLIL DSL helper brings into a mixed script, with what they stand for (loading no writer)"""
    module = importlib.import_module(hlil_dsl_helper_module(game))
    return {name: value for name, value in vars(module).items() if not name.startswith('_')}


def hlil_dsl_names(game: str) -> set[str]:
    return set(hlil_dsl_namespace(game))
