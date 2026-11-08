"""How .ts prints a game's tagged values, as plain data for codegen/typescript.py: each ID kind's names (character IDs
so far) from the game's generated tables"""

import functools
import importlib

from codegen import IdFormatHint
from dc3.logging import log
from ..consts import CHR_ID_KIND, PseudoChrId
from ..structs.common_library import CHR_TABLE_MODULE, game_metadata_module

CHR_ID_TABLE   = 'ChrIdTable'     # the dict chr_table.py defines, and the name .ts indexes it by
CHR_ID_COMMENT = f"Character IDs: the game's names ({CHR_ID_TABLE}, from t_name.tbl) and the VM's pseudo IDs"


@functools.cache
def game_format_hints(game: str) -> dict[str, IdFormatHint]:
    """game's IdFormatHint per ID kind, loaded once per game per process"""
    return {
        CHR_ID_KIND: IdFormatHint(
            CHR_ID_TABLE,
            chr_id_names(game),
            PseudoChrId.__name__,
            {int(pseudo): pseudo.name for pseudo in PseudoChrId},
            CHR_ID_COMMENT,
        ),
    }


def chr_id_names(game: str) -> dict[int, str]:
    """Each character ID's name from game's chr_table.py; {} when it is not generated (the pseudo IDs are the VM's, so
    they keep their names), with a hint logged. An import failure inside it, or a missing game package, re-raises"""
    module = game_metadata_module(game, CHR_TABLE_MODULE)
    try:
        table = getattr(importlib.import_module(module), CHR_ID_TABLE)
    except ModuleNotFoundError as e:
        if e.name != module:
            raise

        log.info(f'Character IDs print as numbers: {game} has no {CHR_TABLE_MODULE}.py - run '
                 f'falcom/ed9/tools/gen_tables.py {game} to build it')
        return {}

    # The table maps both ways: the ID -> name half
    return {chr_id: name for chr_id, name in table.items() if type(chr_id) is int}
