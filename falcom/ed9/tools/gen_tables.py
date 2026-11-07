"""Generate a game's two-way character table from its t_name.tbl, into the game's metadata package:
falcom/ed9/games/<game>/metadata/chr_table.py (gitignored), or the file -o names

Usage:
    python falcom/ed9/tools/gen_tables.py {game} [-o {output_file}]

Every run is a full rewrite: hand edits to the generated file don't survive.
"""

import argparse
import importlib
from pathlib import Path
import sys
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from dc3 import default_indent, quote_string
from dc3.logging import log
from dc3.utils import write_text_lf
from falcom.ed9.games import GAMES_DIR, GAMES_PACKAGE
from falcom.ed9.parser.tbl import TblParser, record_classes

TABLE_GAMES      = ['sora2']
NAME_TABLE       = Path('extracted') / 'table_en' / 't_name.tbl'
CHR_TABLE_FILE   = Path('metadata') / 'chr_table.py'
CHR_TABLE_NAME   = 'ChrIdTable'
NO_CHR_ID        = 0xFFFF        # a row with no ID of its own, mostly a costume


def chr_id_digits(chr_id: int) -> str:
    return f'{chr_id:04X}'


def chr_names(entries: Sequence) -> dict[int, str]:
    """Each ID's name, from the first row of that ID as in the game. The first ID of a name keeps it plain; a later one
    adds its ID, since a name can repeat"""
    names = {}
    taken = set()
    for entry in entries:
        if entry.chrId == NO_CHR_ID or entry.chrId in names:
            continue

        name = entry.chrName.strip()
        if name in taken:
            name = f'{name}_{chr_id_digits(entry.chrId)}'
            if name in taken:
                raise ValueError(f'chrId 0x{chr_id_digits(entry.chrId)}: {name} is already a name')

        taken.add(name)
        names[entry.chrId] = name

    return names


def chr_table_text(names: dict[int, str]) -> str:
    """The table both ways, as a module: every name to its ID, then every ID to its name"""
    pairs = [(f'0x{chr_id_digits(chr_id)}', quote_string(name, "'")) for chr_id, name in names.items()]
    lines = [f'{default_indent()}{name}: {chr_id},' for chr_id, name in pairs]
    lines += [f'{default_indent()}{chr_id}: {name},' for chr_id, name in pairs]
    return '\n'.join(['"""Generated from t_name.tbl by falcom/ed9/tools/gen_tables.py"""', '',
                      f'{CHR_TABLE_NAME} = {{', *lines, '}', ''])


def read_name_table(game: str) -> list:
    records = importlib.import_module(f'{GAMES_PACKAGE}.{game}.tbl.tbl_records')
    parser = TblParser((GAMES_DIR / game / NAME_TABLE).read_bytes(), record_classes(records))
    if parser.problems:
        raise ValueError(f'{NAME_TABLE.name}: {parser.problems}')

    return parser.entries


def main() -> int:
    arg_parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    arg_parser.add_argument('game', choices=TABLE_GAMES)
    arg_parser.add_argument('-o', '--output-file', type=Path, help=f"default: the game's {CHR_TABLE_FILE}")

    args = arg_parser.parse_args()
    output_file = args.output_file or GAMES_DIR / args.game / CHR_TABLE_FILE
    names = chr_names(read_name_table(args.game))
    write_text_lf(output_file, chr_table_text(names))
    log.info(f'{output_file}: {len(names)} characters')
    return 0


if __name__ == '__main__':
    sys.exit(main())
