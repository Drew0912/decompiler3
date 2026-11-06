"""ED9 .tbl tables into Python, read-only: a header, one entry per section, the sections' fixed-size records, then a
data block the records' pointers reach

A game's record classes live in its tbl_records.py. A section is read through the class of its name and record size;
with none, or when a pointer does not fit, it stays raw hex.

Usage, from a game's launcher:
    python falcom/ed9/games/{game}/tbl2py.py {file_path} [-o {output_dir}]
"""

import argparse
from pathlib import Path
import struct
from types import ModuleType
from typing import Callable, NamedTuple

from dc3 import default_encoding, default_indent, fileio, quote_string
from dc3.logging import log
from dc3.utils import float32_bits, write_text_lf
from falcom.ed9.games import GAMES_DIR
from .scp import DEFINITION_SPACING, SYS_PATH_SETUP_LINES

TBL_PATTERN      = '*.tbl'
TBL_OUTPUT_DIR   = Path('out') / 'tables'    # a game's default output folder, beside its launcher

FILE_HEADER      = fileio.struct_layout('4xI')       # magic, section count
SECTION_ENTRY    = fileio.struct_layout('64s4xIII')  # name, name hash, records' offset, record size, record count
UINT16           = fileio.struct_layout('H')
UINT32           = fileio.struct_layout('I')
UINT64           = fileio.struct_layout('Q')
FLOAT32          = fileio.struct_layout('f')
ARRAY_FIELD      = fileio.struct_layout('QI')        # pointer, element count

FLOAT32_MAX_DIGITS  = 9     # enough to name any float32 exactly
STRING_KIND         = 'S'


class FieldKind(NamedTuple):
    layout  : struct.Struct
    format  : Callable
    element : struct.Struct | None = None   # an array's element


def float_literal(value: float) -> str:
    """Shortest float literal that stores the same float32: 0.3, not 0.30000001192092896"""
    bits = float32_bits(value)
    for digits in range(1, FLOAT32_MAX_DIGITS):
        text = repr(float(f'{value:.{digits}g}'))
        if float32_bits(float(text)) == bits:
            return text

    return repr(float(f'{value:.{FLOAT32_MAX_DIGITS}g}'))


# The letters a DESCRIPTOR's (field, kind) pairs use: how a field is stored and how it prints. Integers are unsigned
FIELD_KINDS = {
    'W'         : FieldKind(UINT16, lambda value: f'0x{value:04X}'),                # 2-byte integer, printed in hex
    'I'         : FieldKind(UINT32, str),                                           # 4-byte integer, in decimal
    'L'         : FieldKind(UINT32, lambda value: f'0x{value:08X}'),                # 4-byte integer, printed in hex
    'Q'         : FieldKind(UINT64, str),                                           # 8-byte integer, in decimal
    'X'         : FieldKind(UINT64, lambda value: f'0x{value:04X}'),                # 8-byte integer, printed in hex
    'f'         : FieldKind(FLOAT32, float_literal),                                # 4-byte float
    STRING_KIND : FieldKind(UINT64, lambda value: quote_string(value, "'")),        # 8-byte pointer to a string
    'A2'        : FieldKind(ARRAY_FIELD, str, UINT16),                              # pointer, count: 2-byte integers
    'A4'        : FieldKind(ARRAY_FIELD, str, UINT32),                              # pointer, count: 4-byte integers
}


class TableDataEntry:
    """One record. A subclass's DESCRIPTOR lists (field, kind) in record order; its section is SECTION, or its name"""

    SECTION: str = ''
    DESCRIPTOR: tuple[tuple[str, str], ...] = ()

    def __init__(self, **fields):
        for name, value in fields.items():
            setattr(self, name, value)

    @classmethod
    def section_name(cls) -> str:
        return cls.SECTION or cls.__name__

    @classmethod
    def record_size(cls) -> int:
        return sum(FIELD_KINDS[kind].layout.size for _, kind in cls.DESCRIPTOR)

    def to_python(self) -> list[str]:
        width = max(len(name) for name, _ in self.DESCRIPTOR)
        fields = [f'{default_indent()}{name.ljust(width)} = {FIELD_KINDS[kind].format(getattr(self, name))},'
                  for name, kind in self.DESCRIPTOR]
        return [f'{type(self).__name__}(', *fields, ')']


class RawTableEntry(NamedTuple):
    """A record no class reads: its bytes as hex"""

    section : str
    data    : str

    def to_python(self) -> list[str]:
        return [f'RawTableEntry({quote_string(self.section, "'")}, {quote_string(self.data, "'")})']


class TblSection(NamedTuple):
    name        : str
    start       : int
    record_size : int
    count       : int

    @property
    def end(self) -> int:
        return self.start + self.record_size * self.count

    def record_offsets(self) -> range:
        return range(self.start, self.end, self.record_size)


class RecordMismatch(Exception):
    """A record class whose pointers do not fit the file"""


def record_classes(records: ModuleType) -> dict[tuple[str, int], type[TableDataEntry]]:
    """A tbl_records module's classes, star-imported ones included, by section name and record size"""
    classes = [value for value in vars(records).values()
               if isinstance(value, type) and issubclass(value, TableDataEntry) and value.DESCRIPTOR]
    return {(cls.section_name(), cls.record_size()): cls for cls in classes}


class TblParser:
    """One .tbl read through classes. entries holds every record; raw_sections the sections with records no class read;
    problems what did not fit"""

    def __init__(self, data: bytes, classes: dict[tuple[str, int], type[TableDataEntry]]):
        self.data = data
        self.sections = self._read_sections()
        self.data_block = self.sections[-1].end
        self.entries: list[TableDataEntry | RawTableEntry] = []
        self.raw_sections: list[str] = []
        self.problems: list[str] = []
        self._block_items: set[tuple[int, int, int]] = set()    # start, end, alignment

        for section in self.sections:
            self._read_section(section, classes)

        # A raw section's pointers are unknown, so only a fully read file can account for its data block
        if not self.raw_sections:
            self._check_data_block()

    def _read_sections(self) -> list[TblSection]:
        count = FILE_HEADER.unpack_from(self.data)[0]
        sections = []
        for index in range(count):
            raw_name, start, record_size, records = SECTION_ENTRY.unpack_from(
                self.data, FILE_HEADER.size + index * SECTION_ENTRY.size)
            name = raw_name.split(b'\0')[0].decode(default_encoding())
            sections.append(TblSection(name, start, record_size, records))

        return sections

    def _read_section(self, section: TblSection, classes: dict[tuple[str, int], type[TableDataEntry]]) -> None:
        record_class = classes.get((section.name, section.record_size))
        if record_class is None:
            sizes = ', '.join(f'{size:#x}' for name, size in classes if name == section.name)
            if sizes:
                self.problems.append(f'{section.name}: record size {section.record_size:#x}, classes for {sizes}')

            self._keep_raw(section)
            return

        try:
            self.entries.extend([self._read_record(record_class, at) for at in section.record_offsets()])
        except RecordMismatch as e:
            self.problems.append(f'{section.name}: {record_class.__name__} does not fit: {e}')
            self._keep_raw(section)

    def _keep_raw(self, section: TblSection) -> None:
        if not section.count:
            return

        self.raw_sections.append(section.name)
        for at in section.record_offsets():
            data = self.data[at:at + section.record_size].hex(' ').upper()
            self.entries.append(RawTableEntry(section.name, data))

    def _read_record(self, record_class: type[TableDataEntry], at: int) -> TableDataEntry:
        fields = {}
        for name, kind in record_class.DESCRIPTOR:
            field = FIELD_KINDS[kind]
            stored = field.layout.unpack_from(self.data, at)
            if kind == STRING_KIND:
                fields[name] = self._read_string(stored[0], at)
            elif field.element:
                fields[name] = self._read_array(field.element, *stored, at)
            else:
                fields[name] = stored[0]

            at += field.layout.size

        return record_class(**fields)

    def _read_string(self, pointer: int, field_at: int) -> str:
        # An empty string may point exactly at end of file (t_bgmset.tbl)
        if pointer == len(self.data):
            return ''

        end = self.data.find(b'\0', pointer)
        if not self.data_block <= pointer < len(self.data) or end < 0:
            raise RecordMismatch(f'pointer {pointer:#x} at {field_at:#x} is outside the data block')

        try:
            text = self.data[pointer:end].decode(default_encoding())
        except UnicodeDecodeError:
            raise RecordMismatch(f'pointer {pointer:#x} at {field_at:#x} does not reach a string') from None

        self._block_items.add((pointer, end + 1, 1))
        return text

    def _read_array(self, element: struct.Struct, pointer: int, count: int, field_at: int) -> list[int]:
        end = pointer + count * element.size
        if not self.data_block <= pointer <= end <= len(self.data) or pointer % element.size:
            raise RecordMismatch(f'array {pointer:#x}, {count} elements, at {field_at:#x} does not fit the data block')

        # An empty array still aligns the block, so it counts as an item
        self._block_items.add((pointer, end, element.size))
        return [value for value, in element.iter_unpack(self.data[pointer:end])]

    def _check_data_block(self) -> None:
        """Every byte of the data block belongs to one item or pads the next to its alignment; a wrong pointer field
        leaves a gap or an overlap"""
        cursor = self.data_block
        for start, end, alignment in sorted(self._block_items):
            if start < cursor:
                self.problems.append(f'data block: overlap at {start:#x}')
                return

            padding = self.data[cursor:start]
            if any(padding) or (padding and len(padding) >= alignment):
                self.problems.append(f'data block: gap at {cursor:#x}')
                return

            cursor = end

        if cursor != len(self.data):
            self.problems.append(f'data block: gap at {cursor:#x}')

    def gen_python_script(self, records_module: str) -> str:
        lines = [*SYS_PATH_SETUP_LINES, f'from {records_module} import *', *DEFINITION_SPACING, 'entries = [']
        for entry in self.entries:
            entry_lines = entry.to_python()
            entry_lines[-1] += ','
            lines.extend(default_indent() + line for line in entry_lines)

        return '\n'.join([*lines, ']', ''])


def collect_tbl_paths(paths: list[Path]) -> list[Path]:
    """Directories expanded to their .tbl files, sorted; file paths kept as they are"""
    files = []
    for path in paths:
        files.extend(sorted(path.glob(TBL_PATTERN)) if path.is_dir() else [path])

    return files


def main(game: str, records: ModuleType) -> int:
    arg_parser = argparse.ArgumentParser(description=f'Read {game} .tbl tables into Python entries lists')
    arg_parser.add_argument('paths', nargs='+', type=Path, help='.tbl files or directories')
    arg_parser.add_argument('-o', '--output-dir', type=Path, help=f"output folder (default: {game}'s {TBL_OUTPUT_DIR})")

    args = arg_parser.parse_args()
    output_dir = args.output_dir or GAMES_DIR / game / TBL_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    classes = record_classes(records)
    for path in collect_tbl_paths(args.paths):
        parser = TblParser(path.read_bytes(), classes)
        for problem in parser.problems:
            log.warning(f'{path.name}: {problem}')

        write_text_lf(output_dir / f'{path.stem}.py', parser.gen_python_script(records.__name__))
        log.info(f'{path.name}: {len(parser.entries)} entries, raw sections: {parser.raw_sections or 'none'}')

    return 0
