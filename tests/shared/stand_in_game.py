#!/usr/bin/env python3
"""A stand-in game whose metadata package holds modules a test writes, for the per-game loaders"""

from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from falcom.ed9.games import GAMES_PACKAGE
from falcom.ed9.structs.common_library import GAME_METADATA_FOLDER

STAND_IN_GAME = 'stand_in_game'

# A module whose own import fails: the loaders re-raise it rather than take it for a missing module
FAILING_IMPORT_SOURCE = 'import module_that_does_not_exist\n'


def plant_game(test: unittest.TestCase, modules: dict[str, str]) -> str:
    """STAND_IN_GAME, whose metadata package holds modules (name -> source) for the rest of test, as a game's
    generated or tracked files would; any other module of it is missing, as for a game without that file"""
    folder = Path(test.enterContext(tempfile.TemporaryDirectory()))
    for name, source in modules.items():
        (folder / f'{name}.py').write_text(source, encoding='utf-8', newline='\n')

    game = types.ModuleType(f'{GAMES_PACKAGE}.{STAND_IN_GAME}')
    game.__path__ = []
    metadata = types.ModuleType(f'{game.__name__}.{GAME_METADATA_FOLDER}')
    metadata.__path__ = [str(folder)]

    # Restored when test ends: the planted packages and every module imported from them go
    test.enterContext(mock.patch.dict(sys.modules, {game.__name__: game, metadata.__name__: metadata}))
    return STAND_IN_GAME
