"""Generate a game's two-way ID tables from its .tbl files, into the game's metadata package (gitignored):
falcom/ed9/games/<game>/metadata/chr_table.py, item_table.py and craft_table.py, or the folder -o names

Usage:
    python falcom/ed9/tools/gen_tables.py {game} [-o {output_dir}]

Every run is a full rewrite: hand edits to the generated files don't survive.
"""

import argparse
import importlib
from pathlib import Path
import sys
from typing import Callable, Iterable, NamedTuple, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from dc3 import default_indent, quote_string
from dc3.logging import log
from dc3.utils import write_text_lf
from falcom.ed9.games import GAMES_DIR, GAMES_PACKAGE
from falcom.ed9.parser.tbl import TblParser, record_classes

TABLE_GAMES   = ['sora2']
TABLES_DIR    = Path('extracted') / 'table_en'
METADATA_DIR  = Path('metadata')
NO_CHR_ID     = 0xFFFF        # a row with no ID of its own, mostly a costume


def id_digits(value: int) -> str:
    return f'{value:04X}'


def unique_names(rows: Iterable[tuple[int, str]]) -> dict[int, str]:
    """Each ID's name, from the first row of that ID, as in the game. The first ID of a name keeps it plain; a later one
    adds its ID, since a name can repeat"""
    names = {}
    taken = set()
    for row_id, text in rows:
        if row_id in names:
            continue

        name = text.strip()
        if name in taken:
            name = f'{name}_{id_digits(row_id)}'
            if name in taken:
                raise ValueError(f'ID 0x{id_digits(row_id)}: {name} is already a name')

        taken.add(name)
        names[row_id] = name

    return names


def chr_names(entries: Sequence) -> dict[int, str]:
    return unique_names((entry.chrId, entry.chrName) for entry in entries if entry.chrId != NO_CHR_ID)


def item_names(entries: Sequence) -> dict[int, str]:
    return unique_names((entry.id, entry.name) for entry in entries)


def craft_names(entries: Sequence) -> dict[int, str]:
    """A craft has a row per character or use, so its ID repeats; an ID with no name is not a craft a script can name"""
    return unique_names((entry.id, entry.name) for entry in entries if entry.name.strip())


class IdTable(NamedTuple):
    name        : str
    module      : str
    tbl_file    : str
    section     : str
    names       : Callable[[Sequence], dict[int, str]]


ID_TABLES = [
    IdTable('ChrIdTable',   'chr_table.py',   't_name.tbl',  'NameTableData', chr_names),
    IdTable('ItemIdTable',  'item_table.py',  't_item.tbl',  'ItemTableData', item_names),
    IdTable('CraftIdTable', 'craft_table.py', 't_skill.tbl', 'SkillParam',    craft_names),
]


def id_table_text(table: IdTable, names: dict[int, str]) -> str:
    """The table both ways, as a module: every name to its ID, then every ID to its name"""
    pairs = [(f'0x{id_digits(row_id)}', quote_string(name, "'")) for row_id, name in names.items()]
    lines = [f'{default_indent()}{name}: {row_id},' for row_id, name in pairs]
    lines += [f'{default_indent()}{row_id}: {name},' for row_id, name in pairs]
    return '\n'.join([f'"""Generated from {table.tbl_file} by falcom/ed9/tools/gen_tables.py"""', '',
                      f'{table.name} = {{', *lines, '}', ''])


def read_section(game: str, table: IdTable) -> list:
    records = importlib.import_module(f'{GAMES_PACKAGE}.{game}.tbl.tbl_records')
    parser = TblParser((GAMES_DIR / game / TABLES_DIR / table.tbl_file).read_bytes(), record_classes(records))
    if parser.problems:
        raise ValueError(f'{table.tbl_file}: {parser.problems}')

    return [entry for entry in parser.entries if entry.section_name() == table.section]


def main() -> int:
    arg_parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    arg_parser.add_argument('game', choices=TABLE_GAMES)
    arg_parser.add_argument('-o', '--output-dir', type=Path, help=f"default: the game's {METADATA_DIR}/")

    args = arg_parser.parse_args()
    output_dir = args.output_dir or GAMES_DIR / args.game / METADATA_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    for table in ID_TABLES:
        names = table.names(read_section(args.game, table))
        write_text_lf(output_dir / table.module, id_table_text(table, names))
        log.info(f'{table.module}: {len(names)} names')

    return 0


if __name__ == '__main__':
    sys.exit(main())
