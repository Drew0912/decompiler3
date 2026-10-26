"""Common-function library support: fingerprints, the generator, and where a game's generated library lives"""

from ..games import GAMES_PACKAGE

# A game's generated data (its common-function library; later its chr table): falcom/ed9/games/<game>/metadata/, a
# tracked package whose generated files are gitignored
GAME_METADATA_FOLDER = 'metadata'

# The library in it: the modules, one per syscall subsystem, in COMMON_LIBRARY_FOLDER; the index (name -> module,
# fingerprint digest); the module re-exporting them all
COMMON_LIBRARY_FOLDER = 'common'
COMMON_INDEX_MODULE   = 'common_index'
COMMON_ALL_MODULE     = 'common_all'

# Logged by the parser, once per game, when a decompile finds no library for its game; noted by the writer on a
# NameError in a script's @scena.CommonImports() manifest, with '<game>' (it knows no game)
COMMON_LIBRARY_MISSING_HINT = ('the common-function library of {game} is not generated - run '
                               'falcom/ed9/metadata/gen_common_library.py '
                               'falcom/ed9/games/{game}/extracted/script_<lang> to build it')

# Every generated module and every emitted script needs this - one place both sides spell it
SCP_WRITER_HELPER_IMPORT = 'from falcom.ed9.writer.scp_writer_helper import *'


def game_metadata_module(game: str, name: str) -> str:
    """The dotted path of name, a module or package in game's metadata package"""
    return f'{GAMES_PACKAGE}.{game}.{GAME_METADATA_FOLDER}.{name}'
