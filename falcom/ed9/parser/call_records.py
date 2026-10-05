"""Call-site debug records against the calls CallDebugInfoTracker rebuilds: each function's raw records, each record's
raw arguments, and whether a record holds what its call would get (content only - the writer's own rules stay with the
round-trip validator)"""

from ml import fileio

from common.config import default_encoding
from ir.llil import WORD_SIZE
from .scp import ScpParser, TrackedCall
from .string_pool import read_text, read_u32
from .types_scp import ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpValue


def read_debug_records(parser: ScpParser, data: bytes) -> list[list[ScpFunctionCallDebugInfo]]:
    """Each function's raw records in table order, read from the file's bytes (the parser keeps converted ones only)"""
    fs = fileio.FileStream(encoding = default_encoding()).OpenMemory(data)
    return [parser.read_debug_info(fs, entry) for entry in parser.function_entries]


def record_args(data: bytes, record: ScpFunctionCallDebugInfo) -> list[tuple[int, int]]:
    """Each argument's raw type and raw value word, in record order"""
    return [(read_u32(data, offset + WORD_SIZE), read_u32(data, offset)) for offset in record.arg_offsets()]


def record_mismatch(data: bytes, call: TrackedCall, record: ScpFunctionCallDebugInfo) -> str | None:
    """How record differs from the record call gets (call type, callee, argument count, each argument by its raw word,
    strings by text), or None. A local call's record may drop trailing default arguments, so only its first
    record.arg_count arguments are compared."""
    CallType = ScpFunctionCallDebugInfo.CallType
    ArgType = ScpFunctionCallDebugInfoArg.Type
    constant_args = []
    call_args = call.args

    if call.call_type == CallType.Local:
        expected_func_id = call.target
        call_args = call.args[:record.arg_count]

    elif call.call_type == CallType.Syscall:
        expected_func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID
        constant_args = list(call.target)

    else:
        expected_func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID
        module, func = call.target
        constant_args = [f'{module.value}.{func.value}']

    expected = [(ArgType.Constant, value) for value in constant_args] + [(arg.type, arg.payload) for arg in call_args]

    if record.call_type != call.call_type or record.func_id != expected_func_id or record.arg_count != len(expected):
        return f'record ({record.call_type.name}, func_id 0x{record.func_id:X}, {record.arg_count} args) != call ({call.call_type.name}, func_id 0x{expected_func_id:X}, {len(expected)} args)'

    for i, ((arg_type, payload), (raw_type, raw_value)) in enumerate(zip(expected, record_args(data, record))):
        if raw_type != arg_type:
            return f'arg {i}: type {raw_type} != {arg_type}'

        if arg_type != ArgType.Constant:
            matches = raw_value == ScpValue(ScpFunctionCallDebugInfoArg.NON_CONSTANT_VALUE).to_word()

        elif isinstance(payload, str):
            offset = ScpParser.get_string_offset(raw_value)
            matches = offset is not None and read_text(data, offset) == payload

        else:
            matches = raw_value == ScpValue(payload).to_word()

        if not matches:
            return f'arg {i}: value 0x{raw_value:08X} != {ascii(payload)}'

    return None
