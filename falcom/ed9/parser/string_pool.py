"""The string pool's sections: the strings the code, the function names, the parameter defaults, the debug records and
the global var names reference, in the order the original compiler pooled them (it never deduplicates)"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from common.config import default_encoding, default_endian
from common.enum import IntEnum2
from ir.llil import WORD_SIZE
from .scp import ScpParser
from .types_scp import ScpFunctionCallDebugInfo, ScpGlobalVar

NUL = b'\0'     # ends every pool string


class StringPoolSection(IntEnum2):
    """Order of the original compiler's string pool"""
    Code    = 0
    Name    = 1
    Default = 2
    Debug   = 3
    Global  = 4


@dataclass
class StringRefs:
    """Pool offsets of every string reference, grouped in the original compiler's pool order"""
    code         : list[int]
    names        : list[int]
    defaults     : list[int]
    debug        : list[int]
    global_names : list[int]
    pool_start   : int

    def sections(self) -> Iterator[tuple[StringPoolSection, list[int]]]:
        return zip(StringPoolSection, (self.code, self.names, self.defaults, self.debug, self.global_names))

    @property
    def expected_pool(self) -> list[int]:
        return [offset for _, offsets in self.sections() for offset in offsets]


def read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + WORD_SIZE], default_endian())


def read_text(data: bytes, offset: int) -> str:
    return data[offset:data.find(NUL, offset)].decode(default_encoding(), errors = 'replace')


def pool_strings(data: bytes, start: int) -> list[int]:
    """Offset of every NUL-terminated string from start to the end of the file (an unterminated tail is left out)"""
    offsets = []
    position = start
    while (end := data.find(NUL, position)) >= 0:
        offsets.append(position)
        position = end + 1

    return offsets


def string_offsets(data: bytes, positions: Iterable[int]) -> list[int]:
    """Pool offsets of the String-typed words at positions, in order"""
    offsets = (ScpParser.get_string_offset(read_u32(data, position)) for position in positions)
    return [offset for offset in offsets if offset is not None]


def collect_string_refs(data: bytes, parser: ScpParser, records: list[list[ScpFunctionCallDebugInfo]]) -> StringRefs:
    """Every string reference of a parsed and disassembled file (data = its bytes), records = each function's raw debug
    records in table order. Code strings come in file order and include unreachable code when the parser decoded it
    (keep_unreachable_code); a debug record string that is also a code string is pooled once, with the code."""
    # Each operand once: functions that share code (one starting where another does, a jump into another) decode it twice
    positions = {position for func in parser.functions
                 for position in ScpParser.string_operand_positions(parser.code_instructions(func))}
    code = string_offsets(data, sorted(positions))

    entries = parser.function_entries
    names = [ScpParser.get_string_offset(entry.name_offset) for entry in entries]
    names = [offset for offset in names if offset is not None]
    defaults = string_offsets(data, (entry.default_params_offset + i * WORD_SIZE
                                     for entry in entries for i in range(entry.default_params_count)))

    code_set = set(code)
    record_strings = string_offsets(data, (offset for function_records in records for record in function_records
                                           for offset in record.arg_offsets()))
    debug = [offset for offset in record_strings if offset not in code_set]

    header = parser.header
    global_names = string_offsets(data, (header.global_var_offset + i * ScpGlobalVar.SIZE for i in range(header.global_var_count)))

    pool_start = min(code + names + defaults + debug + global_names, default = len(data))
    return StringRefs(code = code, names = names, defaults = defaults, debug = debug, global_names = global_names, pool_start = pool_start)
