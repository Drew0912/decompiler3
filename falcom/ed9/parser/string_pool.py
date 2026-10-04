"""The string pool's sections: the strings the code, the function names, the parameter defaults, the debug records and
the global var names reference, in the order the original compiler pooled them (it never deduplicates)"""

from collections.abc import Iterable
from dataclasses import dataclass

from common.config import default_endian
from ir.llil import WORD_SIZE
from .scp import ScpParser
from .types_scp import ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpGlobalVar


@dataclass
class StringRefs:
    """Pool offsets of every string reference, grouped in the original compiler's pool order"""
    code         : list[int]
    names        : list[int]
    defaults     : list[int]
    debug        : list[int]
    global_names : list[int]
    pool_start   : int

    @property
    def expected_pool(self) -> list[int]:
        return self.code + self.names + self.defaults + self.debug + self.global_names


def read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + WORD_SIZE], default_endian())


def string_offsets(data: bytes, positions: Iterable[int]) -> list[int]:
    """Pool offsets of the String-typed words at positions, in order"""
    offsets = (ScpParser.get_string_offset(read_u32(data, position)) for position in positions)
    return [offset for offset in offsets if offset is not None]


def collect_string_refs(data: bytes, parser: ScpParser, records: list[list[ScpFunctionCallDebugInfo]]) -> StringRefs:
    """Every string reference of a parsed and disassembled file (data = its bytes), records = each function's raw debug
    records in table order. Code strings come in code order and include unreachable code when the parser decoded it
    (keep_unreachable_code); a debug record string that is also a code string is pooled once, with the code."""
    code = []
    for func in sorted(parser.functions, key = lambda func: func.offset):
        unreachable = [inst for block in func.unreachable_blocks for inst in block.instructions]
        instructions = sorted(parser.get_instructions(func) + unreachable, key = lambda inst: inst.offset)
        code += string_offsets(data, ScpParser.string_operand_positions(instructions))

    entries = parser.function_entries
    names = [ScpParser.get_string_offset(entry.name_offset) for entry in entries]
    names = [offset for offset in names if offset is not None]
    defaults = string_offsets(data, (entry.default_params_offset + i * WORD_SIZE
                                     for entry in entries for i in range(entry.default_params_count)))

    code_set = set(code)
    record_strings = string_offsets(data, (record.info_offset + i * ScpFunctionCallDebugInfoArg.SIZE
                                           for function_records in records for record in function_records
                                           for i in range(record.arg_count)))
    debug = [offset for offset in record_strings if offset not in code_set]

    header = parser.header
    global_names = string_offsets(data, (header.global_var_offset + i * ScpGlobalVar.SIZE for i in range(header.global_var_count)))

    pool_start = min(code + names + defaults + debug + global_names, default = len(data))
    return StringRefs(code = code, names = names, defaults = defaults, debug = debug, global_names = global_names, pool_start = pool_start)
