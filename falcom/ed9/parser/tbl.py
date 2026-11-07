"""ED9 .tbl tables into Python and back: a header, one entry per section, the sections' fixed-size records, then a data
block the records' pointers reach

A game's record classes live in its tbl/tbl_records.py. A section is read through the class of its name and record size;
with none, or when a pointer does not fit, it stays raw hex. Running a generated script writes its table again.

Usage, from a game's launcher:
    python falcom/ed9/games/{game}/tbl2py.py {file_path} [-o {output_dir}]
"""

import argparse
from itertools import islice
from pathlib import Path
import struct
from types import ModuleType
from typing import Callable, NamedTuple, Sequence

from dc3 import default_encoding, default_indent, fileio, quote_string
from dc3.logging import log
from dc3.utils import float32_literal, write_text_lf
from falcom.ed9.games import GAMES_DIR
from ..structs.crc32 import hash_function_name
from ..structs.generated_script import DEFINITION_SPACING, SYS_PATH_SETUP_LINES

TBL_MAGIC        = b'#TBL'
TBL_PATTERN      = '*.tbl'
TBL_OUTPUT_DIR   = Path('out') / 'tbl'       # a game's default output folder, beside its launcher

FILE_HEADER      = fileio.struct_layout('4sI')       # magic, section count
SECTION_ENTRY    = fileio.struct_layout('64sIIII')   # name, name hash, records' offset, record size, record count
INT8             = fileio.struct_layout('b')
INT16            = fileio.struct_layout('h')
INT32            = fileio.struct_layout('i')
UINT8            = fileio.struct_layout('B')
UINT16           = fileio.struct_layout('H')
UINT32           = fileio.struct_layout('I')
UINT64           = fileio.struct_layout('Q')
FLOAT32          = fileio.struct_layout('f')
ARRAY_FIELD      = fileio.struct_layout('QI')        # pointer, element count

STRING_KIND         = 'S'
SECTIONS_COMMENT    = ['# Sections come from entries; a file they cannot describe lists them in order:',
                       '# sections=[(record class, row count), ...]']


class FieldKind(NamedTuple):
    layout  : struct.Struct
    format  : Callable
    element : struct.Struct | None = None   # an array's element


def float32_list(values: list[float]) -> str:
    return f'[{', '.join(map(float32_literal, values))}]'


# Zero bytes after a narrow field, by size: never a row's field, a rebuild writes them again
PADDING_KINDS = {f'P{size}': FieldKind(fileio.struct_layout(f'{size}s'), bytes.hex) for size in range(1, 8)}

# The letters a DESCRIPTOR's (field, kind) pairs use: how a field is stored and how it prints. Integers are unsigned
# but for b, w and i
FIELD_KINDS = {
    'b'         : FieldKind(INT8, str),                                             # 1-byte signed integer, in decimal
    'B'         : FieldKind(UINT8, str),                                            # 1-byte integer, in decimal
    'w'         : FieldKind(INT16, str),                                            # 2-byte signed integer, in decimal
    'W'         : FieldKind(UINT16, lambda value: f'0x{value:04X}'),                # 2-byte integer, printed in hex
    'H'         : FieldKind(UINT16, str),                                           # 2-byte integer, in decimal
    'i'         : FieldKind(INT32, str),                                            # 4-byte signed integer, in decimal
    'I'         : FieldKind(UINT32, str),                                           # 4-byte integer, in decimal
    'L'         : FieldKind(UINT32, lambda value: f'0x{value:08X}'),                # 4-byte integer, printed in hex
    'Q'         : FieldKind(UINT64, str),                                           # 8-byte integer, in decimal
    'X'         : FieldKind(UINT64, lambda value: f'0x{value:04X}'),                # 8-byte integer, printed in hex
    'f'         : FieldKind(FLOAT32, float32_literal),                              # 4-byte float
    STRING_KIND : FieldKind(UINT64, lambda value: quote_string(value, "'")),        # 8-byte pointer to a string
    'A1'        : FieldKind(ARRAY_FIELD, str, UINT8),                               # pointer, count: 1-byte integers
    'A2'        : FieldKind(ARRAY_FIELD, str, UINT16),                              # pointer, count: 2-byte integers
    'A4'        : FieldKind(ARRAY_FIELD, str, UINT32),                              # pointer, count: 4-byte integers
    'AF'        : FieldKind(ARRAY_FIELD, float32_list, FLOAT32),                    # pointer, count: 4-byte floats
    **PADDING_KINDS,
}


class TableDataEntry:
    """One record. A subclass's DESCRIPTOR lists (field, kind) in record order; its section is SECTION, or its name"""

    SECTION: str = ''
    DESCRIPTOR: tuple[tuple[str, str], ...] = ()

    def __init__(self, **fields):
        self._check_fields(fields)
        for name, value in fields.items():
            setattr(self, name, value)

    def _check_fields(self, fields: dict) -> None:
        """A row's mistakes, raised here so the error points at its line in a generated script"""
        wrong_names = fields.keys() ^ {name for name, _ in self.row_fields()}
        if wrong_names:
            raise ValueError(f'{type(self).__name__}: unknown or missing fields: {', '.join(sorted(wrong_names))}')

        for name, kind in self.row_fields():
            field = FIELD_KINDS[kind]
            if kind == STRING_KIND:
                continue

            try:
                for number in fields[name] if field.element else [fields[name]]:
                    (field.element or field.layout).pack(number)
            except (struct.error, OverflowError):
                raise ValueError(f'{type(self).__name__}: {name} = {fields[name]} does not fit its field') from None

    @classmethod
    def row_fields(cls) -> list[tuple[str, str]]:
        return [(name, kind) for name, kind in cls.DESCRIPTOR if kind not in PADDING_KINDS]

    @classmethod
    def section_name(cls) -> str:
        return cls.SECTION or cls.__name__

    @classmethod
    def record_size(cls) -> int:
        return sum(FIELD_KINDS[kind].layout.size for _, kind in cls.DESCRIPTOR)

    def to_python(self) -> list[str]:
        width = max(len(name) for name, _ in self.row_fields())
        fields = [f'{default_indent()}{name.ljust(width)} = {FIELD_KINDS[kind].format(getattr(self, name))},'
                  for name, kind in self.row_fields()]
        return [f'{type(self).__name__}(', *fields, ')']

    def to_bytes(self, block: TblDataBlock) -> bytes:
        record = bytearray()
        for name, kind in self.DESCRIPTOR:
            field = FIELD_KINDS[kind]
            if kind in PADDING_KINDS:
                record += bytes(field.layout.size)
                continue

            value = getattr(self, name)
            if kind == STRING_KIND:
                record += field.layout.pack(block.add_string(value))
            elif field.element:
                record += field.layout.pack(block.add_array(value, field.element), len(value))
            else:
                record += field.layout.pack(value)

        return bytes(record)


class RawTableEntry(NamedTuple):
    """A record no class reads: its bytes as hex"""

    section : str
    data    : str

    def section_name(self) -> str:
        return self.section

    def record_size(self) -> int:
        return len(bytes.fromhex(self.data))

    def to_python(self) -> list[str]:
        return [f'RawTableEntry({quote_string(self.section, "'")}, {quote_string(self.data, "'")})']

    def to_bytes(self, block: TblDataBlock) -> bytes:
        return bytes.fromhex(self.data)


class RawSection(NamedTuple):
    """A section with no class, for a sections= list"""

    name : str
    size : int

    def section_name(self) -> str:
        return self.name

    def record_size(self) -> int:
        return self.size


TblRow         = TableDataEntry | RawTableEntry
RecordClasses  = dict[tuple[str, int], type[TableDataEntry]]
ListedSections = list[tuple[type[TableDataEntry] | RawSection, int]]


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


def record_classes(records: ModuleType) -> RecordClasses:
    """A tbl_records module's classes, star-imported ones included, by section name and record size"""
    classes = [value for value in vars(records).values()
               if isinstance(value, type) and issubclass(value, TableDataEntry) and value.DESCRIPTOR]
    return {(cls.section_name(), cls.record_size()): cls for cls in classes}


class TblParser:
    """One .tbl read through classes. entries holds every record; raw_sections the sections with records no class read;
    problems what did not fit"""

    def __init__(self, data: bytes, classes: RecordClasses):
        self.data = data
        self.sections = self._read_sections()
        self.data_block_start = self.sections[-1].end
        self.classes = classes
        self.entries: list[TblRow] = []
        self.raw_sections: list[str] = []
        self.problems: list[str] = []
        self._block_items: set[tuple[int, int, int]] = set()    # start, end, alignment

        for section in self.sections:
            self._read_section(section)

        # A raw section's pointers are unknown, so only a fully read file can account for its data block
        if not self.raw_sections:
            self._check_data_block()

    def _read_sections(self) -> list[TblSection]:
        _, count = FILE_HEADER.unpack_from(self.data)
        sections = []
        for index in range(count):
            raw_name, _, start, record_size, records = SECTION_ENTRY.unpack_from(
                self.data, FILE_HEADER.size + index * SECTION_ENTRY.size)
            name = raw_name.split(b'\0')[0].decode(default_encoding())
            sections.append(TblSection(name, start, record_size, records))

        return sections

    def _read_section(self, section: TblSection) -> None:
        record_class = self.classes.get((section.name, section.record_size))
        if record_class is None:
            sizes = ', '.join(f'{size:#x}' for name, size in self.classes if name == section.name)
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
            if kind in PADDING_KINDS:
                if any(stored[0]):
                    raise RecordMismatch(f'padding {name} at {at:#x} is not zero')
            elif kind == STRING_KIND:
                fields[name] = self._read_string(stored[0], at)
            elif field.element:
                fields[name] = self._read_array(field.element, *stored, at)
            else:
                fields[name] = stored[0]

            at += field.layout.size

        return record_class(**fields)

    def _read_string(self, pointer: int, field_at: int) -> str:
        end = self.data.find(b'\0', pointer)
        if not self.data_block_start <= pointer < len(self.data) or end < 0:
            raise RecordMismatch(f'pointer {pointer:#x} at {field_at:#x} is outside the data block')

        try:
            text = self.data[pointer:end].decode(default_encoding())
        except UnicodeDecodeError:
            raise RecordMismatch(f'pointer {pointer:#x} at {field_at:#x} does not reach a string') from None

        self._block_items.add((pointer, end + 1, 1))
        return text

    def _read_array(self, element: struct.Struct, pointer: int, count: int, field_at: int) -> list[int]:
        end = pointer + count * element.size
        if not self.data_block_start <= pointer <= end <= len(self.data) or pointer % element.size:
            raise RecordMismatch(f'array {pointer:#x}, {count} elements, at {field_at:#x} does not fit the data block')

        # An empty array still aligns the block, so it counts as an item
        self._block_items.add((pointer, end, element.size))
        return [value for value, in element.iter_unpack(self.data[pointer:end])]

    def _check_data_block(self) -> None:
        """Every byte of the data block belongs to one item or pads the next to its alignment; a wrong pointer field
        leaves a gap or an overlap"""
        cursor = self.data_block_start
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

    def _entries_describe_sections(self) -> bool:
        """False for a file with an empty section or a repeated name"""
        stored = [(section.name, section.record_size, section.count) for section in self.sections]
        return stored == [(name, size, len(rows)) for name, size, rows in sections_from_entries(self.entries)]

    def _listed_section(self, section: TblSection) -> str:
        if record_class := self.classes.get((section.name, section.record_size)):
            return f'({record_class.__name__}, {section.count})'

        return f'(RawSection({quote_string(section.name, "'")}, {section.record_size:#x}), {section.count})'

    def _entries_lines(self) -> list[str]:
        lines = ['entries = [']
        for entry in self.entries:
            entry_lines = entry.to_python()
            entry_lines[-1] += ','
            lines.extend(default_indent() + line for line in entry_lines)

        return [*lines, ']']

    def _write_block_lines(self, filename: str) -> list[str]:
        call = f'create_tbl({quote_string(filename, "'")}, *entries'
        if self._entries_describe_sections():
            create = [f'{call})']
        else:
            listed = [f'{default_indent()}{self._listed_section(section)},' for section in self.sections]
            create = [f'{call}, sections=[', *listed, '])']

        return ["if __name__ == '__main__':", *(default_indent() + line for line in [*SECTIONS_COMMENT, *create])]

    def gen_python_script(self, records_module: str, filename: str) -> str:
        return '\n'.join([*SYS_PATH_SETUP_LINES, f'from {records_module} import *', *DEFINITION_SPACING,
                          *self._entries_lines(), *DEFINITION_SPACING, *self._write_block_lines(filename), ''])


# Rebuilding a table
class TblDataBlock:
    """The data block as a rebuild fills it: each item in the order the records ask for it, nothing shared"""

    def __init__(self, start: int):
        self.start = start
        self.data = bytearray()

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    def add_string(self, text: str) -> int:
        pointer = self.end
        self.data += fileio.str_to_bytes(text)
        return pointer

    def add_array(self, values: list[int], element: struct.Struct) -> int:
        self.data += bytes(-self.end % element.size)
        pointer = self.end
        self.data += b''.join(map(element.pack, values))
        return pointer


class SectionRows(NamedTuple):
    name        : str
    record_size : int
    rows        : list[TblRow]


def sections_from_entries(entries: Sequence[TblRow]) -> list[SectionRows]:
    """Each section's name, record size and rows, in the order the rows first name them"""
    sections = {}
    for row in entries:
        sections.setdefault((row.section_name(), row.record_size()), []).append(row)

    return [SectionRows(name, size, rows) for (name, size), rows in sections.items()]


def check_record_sizes(entries: Sequence[TblRow]) -> None:
    """One size per section name: a raw row's hex can be any length, and a wrong one would start a section of its own"""
    sizes = {}
    for index, row in enumerate(entries):
        name, size = row.section_name(), row.record_size()
        if sizes.setdefault(name, size) != size:
            raise ValueError(f'entries[{index}]: {name} row of record size {size:#x}, '
                             f'the rows before it {sizes[name]:#x}')


def sections_from_counts(entries: Sequence[TblRow], listed: ListedSections) -> list[SectionRows]:
    """Each listed section's name, record size and rows; a wrong count shifts every later row, so each row is checked"""
    listed_count = sum(count for _, count in listed)
    if listed_count != len(entries):
        raise ValueError(f'sections= counts {listed_count} rows, entries has {len(entries)}')

    sections = []
    rows = iter(entries)
    for section, count in listed:
        name, size = section.section_name(), section.record_size()
        section_rows = list(islice(rows, count))
        for row in section_rows:
            if (row.section_name(), row.record_size()) != (name, size):
                raise ValueError(f'row of {row.section_name()}, record size {row.record_size():#x}, '
                                 f'in section {name}, record size {size:#x}')

        sections.append(SectionRows(name, size, section_rows))

    return sections


def tbl_bytes(entries: Sequence[TblRow], listed: ListedSections | None = None) -> bytes:
    if listed is None:
        check_record_sizes(entries)
        sections = sections_from_entries(entries)
    else:
        sections = sections_from_counts(entries, listed)

    records_start = FILE_HEADER.size + len(sections) * SECTION_ENTRY.size
    records_size = sum(size * len(rows) for _, size, rows in sections)
    block = TblDataBlock(records_start + records_size)

    section_entries = bytearray()
    records = bytearray()
    for name, size, rows in sections:
        section_entries += SECTION_ENTRY.pack(name.encode(default_encoding()), hash_function_name(name),
                                              records_start + len(records), size, len(rows))
        for row in rows:
            records += row.to_bytes(block)

    return FILE_HEADER.pack(TBL_MAGIC, len(sections)) + section_entries + records + block.data


def create_tbl(filename: str, *entries: TblRow, sections: ListedSections | None = None) -> None:
    """Write a table to the current folder; sections lists (record class or RawSection, row count) in file order"""
    Path(filename).write_bytes(tbl_bytes(entries, sections))


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

        write_text_lf(output_dir / f'{path.stem}.py', parser.gen_python_script(records.__name__, path.name))
        log.info(f'{path.name}: {len(parser.entries)} entries, raw sections: {parser.raw_sections or 'none'}')

    return 0
