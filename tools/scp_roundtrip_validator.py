"""
SCP Round-Trip Validator

Checks that ED9-VM .dat scripts follow the layout rules ScpWriter relies on for a byte-exact
round trip, and optionally decompiles, recompiles and byte-compares each file.

Usage:
    python tools/scp_roundtrip_validator.py sora2_1.0/script_en/scena/e2000.dat
    python tools/scp_roundtrip_validator.py sora2_1.0/script_en --verbose
    python tools/scp_roundtrip_validator.py sora2_1.0/script_en/scena/e0000.dat --round-trip
    python tools/scp_roundtrip_validator.py sora2_1.0/script_en/scena/e0000.dat --logic-round-trip

Checks (FAIL = a rule the writer depends on is broken, WARN = known decompiler limitation):
    layout          default params, param flags, debug records and debug args are contiguous in table
                    order; every per-function offset is the running position (even for count 0);
                    global_var_offset ends the debug args, and the global var table (8 bytes/entry:
                    name ref, type) ends where the code starts
    function order  table sorted by name bytes; code in source order: common functions first (no line
                    numbers), then strictly increasing DEBUG_SET_LINENO
    code            PUSH size byte; PUSH_CURRENT_FUNC_ID value == caller table index;
                    WARN: unreachable code (kept in the .py unless ScpParser.keep_unreachable_code is off)
    string pool     never deduplicated: code refs (code order), names, default strings, debug-only
                    strings, global var names (index order, always last)
    debug records   every record rebuilt from its call site with CallDebugInfoTracker
    round trip      (--round-trip) decompile into a work dir, delete the copy, run the generated .py,
                    byte-compare with the original

--logic-round-trip checks (decompile with round_trip=False, the everyday config; see docs/LLIL_DSL.md
Sec.2 for the full policy - byte-exact fidelity is not required, preserved game logic and a byte-level
fixed point within a few rounds are):
    source preconditions   fields the decompile normalizes away that no check on a recompiled file
                            could see (duplicate names, header dword_14, name_hash, instruction-range
                            validity, call pairing)
    reachability            every dropped byte range is provably dead (see is_range_provably_dead)
    string fidelity         every pooled string re-encodes to exactly its raw bytes
    round N logic preserved  source vs that round's decompile: per-function fingerprint + signature,
                            the global table, and header dword_14 - checked every round, not just once
    logic round trip        PASS once compiled bytes and decompiled text both stop changing, within
                            MAX_CONVERGENCE_ROUNDS rounds; FAIL otherwise
Name inputs <name>.dat: the generated header names its output after the whole file name, so a
two-suffix input (X.original.dat) compiles to X.original.dat and the round is reported as a failed
compile.

Baseline (2026-10-01, format checks, no FAIL; all five byte-identical under --round-trip and
converged at round 2 under --logic-round-trip):
    sora2_1.0/script_en/scena/e0000.dat           PASS, 1 debug record
    sora2_1.0/script_en/scena/e2000.dat           PASS, 235 debug records (42 with dropped default args)
    sora2_1.0/script_en/scena/system.dat          WARN: 63 unreachable ranges, 4806 debug records (740 dropped)
    sora2_1.0/script_en/scena/mp0000_ev.dat       WARN: 3 unreachable JMPs, 19461 debug records (7872 dropped)
    sora2_1.0/script_en/ai/ai_chr0100_e00.dat     WARN: 1 unreachable JMP, 37 debug records
"""

import argparse
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml import fileio
from common.config import default_encoding, default_endian
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9_INSTRUCTION_TABLE, ED9Opcode, Instruction, OperandType
from falcom.ed9.parser.crc32 import hash_func_Name
from falcom.ed9.parser.scp import ScpParser, CallDebugInfoTracker, TrackedCall, PUSH_CONSTANT_OPS
from falcom.ed9.parser.types_parser import Function
from falcom.ed9.parser.types_scp import (
    ScpFunctionCallDebugInfo,
    ScpFunctionCallDebugInfoArg,
    ScpFunctionEntry,
    ScpGlobalVar,
    ScpHeader,
    ScpValue,
)
from falcom.ed9.writer.scp_writer import NON_CONSTANT_ARG_VALUE, PUSH_SIZE_BYTE
from falcom.ed9.writer.metadata.signature import function_fingerprint


DAT_PATTERN             = '*.dat'
UINT8_SIZE              = 1
OPCODE_SIZE             = UINT8_SIZE
PUSH_SIZE_OFFSET        = OPCODE_SIZE                       # PUSH opcode, u8 size, ScpValue
PUSH_VALUE_OFFSET       = PUSH_SIZE_OFFSET + UINT8_SIZE
SCRIPT_MODULE_OFFSET    = OPCODE_SIZE                       # CALL_SCRIPT opcode, module, func, argc
SCRIPT_FUNC_OFFSET      = SCRIPT_MODULE_OFFSET + WORD_SIZE
SCP_VALUE_TYPE_SHIFT    = 30
SCP_VALUE_PAYLOAD_MASK  = (1 << SCP_VALUE_TYPE_SHIFT) - 1
NUL                     = b'\0'
MAX_DETAILS             = 10
DETAIL_INDENT           = ' ' * 10
SCRIPT_CALL_OPS         = (ED9Opcode.CALL_SCRIPT, ED9Opcode.CALL_SCRIPT_NO_RETURN)

# Reachability audit (--logic-round-trip): a dropped byte range is provably dead only when the
# reachable instruction right before it can't fall through - RETURN/JMP/CALL_SCRIPT_NO_RETURN never
# link a continuation at all, and CALL/CALL_SCRIPT only do so via a paired PUSH_RET_ADDR/
# PUSH_CALLER_FRAME (checked separately, per function) - so a range after an unpaired one is unproven.
REACHABLE_TERMINATORS   = (ED9Opcode.RETURN, ED9Opcode.JMP, ED9Opcode.CALL_SCRIPT_NO_RETURN)
PAIRED_CALL_OPS         = {ED9Opcode.CALL: ED9Opcode.PUSH_RET_ADDR, ED9Opcode.CALL_SCRIPT: ED9Opcode.PUSH_CALLER_FRAME}
MAX_CONVERGENCE_ROUNDS  = 4  # --logic-round-trip: give up if compile/decompile hasn't hit a fixed point by then

# Runs a generated script's main() under a fixed run_name, so its own __main__ guard stays off
ROUND_TRIP_RUNNER = "import runpy, sys; runpy.run_path(sys.argv[1], run_name = 'scp_roundtrip')['main']()"


class Status(IntEnum):
    PASS = 0
    WARN = 1
    FAIL = 2


@dataclass
class CheckResult:
    name    : str
    status  : Status
    summary : str
    details : list[str] = field(default_factory = list)

    @classmethod
    def build(cls, name: str, summary: str, failures: list[str], warnings: list[str] | None = None) -> 'CheckResult':
        warnings = warnings or []

        if failures:
            status = Status.FAIL

        elif warnings:
            status = Status.WARN

        else:
            status = Status.PASS

        return cls(name, status, summary, failures + warnings)


@dataclass
class ScriptContext:
    """One parsed + disassembled script shared by every check"""
    path            : Path
    data            : bytes
    fs              : fileio.FileStream
    parser          : ScpParser
    entries         : list[ScpFunctionEntry]                # table order
    records         : list[list[ScpFunctionCallDebugInfo]]  # table order
    instructions    : list[list[Instruction]]               # table order, reachable, offset order
    code_order      : list[int]                             # table indices sorted by code offset

    def read_u32(self, offset: int) -> int:
        return int.from_bytes(self.data[offset:offset + WORD_SIZE], default_endian())

    def read_text(self, offset: int) -> str:
        end = self.data.find(NUL, offset)
        return self.data[offset:end].decode(default_encoding(), errors = 'replace')

    def func_name(self, index: int) -> str:
        return self.parser.functions[index].name


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


def string_offset(value: int) -> int | None:
    """Pool offset of a String-typed raw ScpValue"""
    if value >> SCP_VALUE_TYPE_SHIFT != ScpValue.Type.String:
        return None

    return value & SCP_VALUE_PAYLOAD_MASK


def load_script(path: Path) -> ScriptContext:
    fs = fileio.FileStream(str(path), encoding = default_encoding())
    parser = ScpParser(fs, path.name)

    with contextlib.redirect_stdout(io.StringIO()):
        parser.parse()
        parser.disasm_all_functions()

    fs.Position = parser.header.function_entry_offset
    entries = [ScpFunctionEntry(fs = fs) for _ in range(parser.header.function_count)]

    records = []
    for entry in entries:
        fs.Position = entry.debug_info_offset
        records.append([ScpFunctionCallDebugInfo(fs = fs) for _ in range(entry.debug_info_count)])

    return ScriptContext(
        path            = path,
        data            = path.read_bytes(),
        fs              = fs,
        parser          = parser,
        entries         = entries,
        records         = records,
        instructions    = [parser.get_instructions(func) for func in parser.functions],
        code_order      = sorted(range(len(entries)), key = lambda index: entries[index].offset),
    )


def collect_string_refs(ctx: ScriptContext) -> StringRefs:
    code = []
    for index in ctx.code_order:
        for inst in ctx.instructions[index]:
            if inst.opcode == ED9Opcode.PUSH_STR:
                operand_offsets = (PUSH_VALUE_OFFSET,)

            elif inst.opcode in SCRIPT_CALL_OPS:
                operand_offsets = (SCRIPT_MODULE_OFFSET, SCRIPT_FUNC_OFFSET)

            else:
                continue

            for operand_offset in operand_offsets:
                offset = string_offset(ctx.read_u32(inst.offset + operand_offset))
                if offset is not None:
                    code.append(offset)

    names = [string_offset(entry.name_offset) for entry in ctx.entries]
    names = [offset for offset in names if offset is not None]

    defaults = []
    for entry in ctx.entries:
        for i in range(entry.default_params_count):
            offset = string_offset(ctx.read_u32(entry.default_params_offset + i * WORD_SIZE))
            if offset is not None:
                defaults.append(offset)

    code_set = set(code)
    debug = []
    for records in ctx.records:
        for record in records:
            for i in range(record.arg_count):
                offset = string_offset(ctx.read_u32(record.info_offset + i * ScpFunctionCallDebugInfoArg.SIZE))
                if offset is not None and offset not in code_set:
                    debug.append(offset)

    header = ctx.parser.header
    global_names = []
    for i in range(header.global_var_count):
        offset = string_offset(ctx.read_u32(header.global_var_offset + i * ScpGlobalVar.SIZE))
        if offset is not None:
            global_names.append(offset)

    pool_start = min(code + names + defaults + debug + global_names, default = len(ctx.data))
    return StringRefs(code = code, names = names, defaults = defaults, debug = debug, global_names = global_names, pool_start = pool_start)


def describe_range(ctx: ScriptContext, start: int, end: int) -> str:
    mnemonics = []
    ctx.fs.Position = start

    while ctx.fs.Position < end:
        try:
            inst = ED9_INSTRUCTION_TABLE.decode_instruction(ctx.fs, ctx.fs.Position)

        except ValueError:
            mnemonics.append('??')
            break

        mnemonics.append(inst.mnemonic)

    return ' '.join(mnemonics)


def check_layout(ctx: ScriptContext) -> CheckResult:
    header = ctx.parser.header
    failures = []
    warnings = []

    if header.function_entry_offset != ScpHeader.SIZE:
        failures.append(f'function_entry_offset 0x{header.function_entry_offset:X} != 0x{ScpHeader.SIZE:X}')

    regions = (
        ('default_params_offset',   lambda e: e.default_params_offset,  lambda e: e.default_params_count * WORD_SIZE),
        ('param_flags_offset',      lambda e: e.param_flags_offset,     lambda e: e.param_count * WORD_SIZE),
        ('debug_info_offset',       lambda e: e.debug_info_offset,      lambda e: e.debug_info_count * ScpFunctionCallDebugInfo.SIZE),
    )

    position = header.function_entry_offset + header.function_count * ScpFunctionEntry.SIZE
    for field_name, get_offset, get_size in regions:
        for index, entry in enumerate(ctx.entries):
            if get_offset(entry) != position:
                failures.append(f'{ctx.func_name(index)}: {field_name} 0x{get_offset(entry):X} != running offset 0x{position:X}')

            position += get_size(entry)

    record_count = 0
    arg_count = 0
    for index, records in enumerate(ctx.records):
        for record in records:
            if record.info_offset != position:
                failures.append(f'{ctx.func_name(index)}: record info_offset 0x{record.info_offset:X} != running offset 0x{position:X}')

            position += record.arg_count * ScpFunctionCallDebugInfoArg.SIZE
            record_count += 1
            arg_count += record.arg_count

    if header.global_var_offset != position:
        failures.append(f'global_var_offset 0x{header.global_var_offset:X} != debug args end 0x{position:X}')

    position += header.global_var_count * ScpGlobalVar.SIZE

    first_code = min((entry.offset for entry in ctx.entries), default = position)
    if first_code != position:
        failures.append(f'first code offset 0x{first_code:X} != global var table end 0x{position:X}')

    summary = f'{len(ctx.entries)} functions, {record_count} debug records, {arg_count} debug args, {header.global_var_count} global vars'
    return CheckResult.build('layout', summary, failures, warnings)


def check_function_order(ctx: ScriptContext) -> CheckResult:
    failures = []
    warnings = []
    encoding = default_encoding()

    names = [func.name for func in ctx.parser.functions]
    if names != sorted(names, key = lambda name: name.encode(encoding)):
        failures.append('function table is not sorted by name')

    hashes = [entry.name_hash for entry in ctx.entries]
    hash_note = 'also' if hashes == sorted(hashes) else 'not'

    common_count = 0
    source_count = 0
    previous = None
    for index in ctx.code_order:
        func = ctx.parser.functions[index]
        lines = [inst.operands[0].value for inst in ctx.instructions[index] if inst.opcode == ED9Opcode.DEBUG_SET_LINENO]

        if func.is_common_func:
            common_count += 1

            if source_count:
                failures.append(f'{func.name}: common function code follows a source function')

            if lines:
                failures.append(f'{func.name}: common function has DEBUG_SET_LINENO')

            continue

        source_count += 1

        if not lines:
            warnings.append(f'{func.name}: source function has no DEBUG_SET_LINENO, order not checked')
            continue

        if previous is not None and lines[0] <= previous[1]:
            failures.append(f'{func.name}: first line {lines[0]} <= line {previous[1]} of {previous[0]}')

        previous = (func.name, max(lines))

    summary = f'sorted by name ({hash_note} by hash); {common_count} common + {source_count} source functions'
    return CheckResult.build('function order', summary, failures, warnings)


def check_code(ctx: ScriptContext, pool_start: int) -> CheckResult:
    failures = []
    warnings = []
    starts = [ctx.entries[index].offset for index in ctx.code_order]

    for position, index in enumerate(ctx.code_order):
        name = ctx.func_name(index)
        end = starts[position + 1] if position + 1 < len(starts) else pool_start
        cursor = ctx.entries[index].offset

        for inst in ctx.instructions[index]:
            if inst.offset > cursor:
                warnings.append(f'{name}: unreachable 0x{cursor:X}..0x{inst.offset:X}: {describe_range(ctx, cursor, inst.offset)}')

            cursor = max(cursor, inst.offset + inst.size)

            if ctx.data[inst.offset] == ED9Opcode.PUSH and ctx.data[inst.offset + PUSH_SIZE_OFFSET] != PUSH_SIZE_BYTE:
                failures.append(f'{name} @0x{inst.offset:X}: PUSH size byte {ctx.data[inst.offset + PUSH_SIZE_OFFSET]} != {PUSH_SIZE_BYTE}')

            if inst.opcode == ED9Opcode.PUSH_CURRENT_FUNC_ID:
                func_id = ctx.read_u32(inst.offset + PUSH_VALUE_OFFSET)
                if func_id != index:
                    failures.append(f'{name} @0x{inst.offset:X}: PUSH_CURRENT_FUNC_ID pushes {func_id}, table index is {index}')

        if cursor < end:
            warnings.append(f'{name}: unreachable 0x{cursor:X}..0x{end:X}: {describe_range(ctx, cursor, end)}')

    summary = f'{len(warnings)} unreachable ranges'
    return CheckResult.build('code', summary, failures, warnings)


def check_string_pool(ctx: ScriptContext, refs: StringRefs) -> CheckResult:
    failures = []
    warnings = []

    actual = []
    position = refs.pool_start
    while position < len(ctx.data):
        end = ctx.data.find(NUL, position)
        if end < 0:
            failures.append(f'unterminated string at 0x{position:X}')
            break

        actual.append(position)
        position = end + 1

    expected = refs.expected_pool
    if actual != expected:
        mismatch = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), min(len(actual), len(expected)))
        actual_text = f'0x{actual[mismatch]:X} {ascii(ctx.read_text(actual[mismatch]))}' if mismatch < len(actual) else 'end of file'
        expected_text = f'0x{expected[mismatch]:X} {ascii(ctx.read_text(expected[mismatch]))}' if mismatch < len(expected) else 'end of references'
        failures.append(f'pool string #{mismatch}: found {actual_text}, expected {expected_text} ({len(actual)} strings, {len(expected)} references)')

    summary = f'{len(actual)} strings: {len(refs.code)} code, {len(refs.names)} names, {len(refs.defaults)} defaults, {len(refs.debug)} debug-only, {len(refs.global_names)} global names'
    return CheckResult.build('string pool', summary, failures, warnings)


def compare_record(ctx: ScriptContext, call: TrackedCall, record: ScpFunctionCallDebugInfo) -> str | None:
    CallType = ScpFunctionCallDebugInfo.CallType
    ArgType = ScpFunctionCallDebugInfoArg.Type
    constant_args = []
    call_args = call.args

    if call.call_type == CallType.Local:
        expected_func_id = call.target
        call_args = call.args[:record.arg_count]

        if call.ret_label is None:
            return 'local CALL without a PUSH_RET_ADDR label'

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

    for i, (arg_type, payload) in enumerate(expected):
        arg_offset = record.info_offset + i * ScpFunctionCallDebugInfoArg.SIZE
        raw_value = ctx.read_u32(arg_offset)
        raw_type = ctx.read_u32(arg_offset + WORD_SIZE)

        if raw_type != arg_type:
            return f'arg {i}: type {raw_type} != {arg_type}'

        if arg_type != ArgType.Constant:
            matches = raw_value == ScpValue(NON_CONSTANT_ARG_VALUE).to_word()

        elif isinstance(payload, str):
            offset = string_offset(raw_value)
            matches = offset is not None and ctx.read_text(offset) == payload

        else:
            matches = raw_value == ScpValue(payload).to_word()

        if not matches:
            return f'arg {i}: value 0x{raw_value:08X} != {ascii(payload)}'

    return None


def check_debug_records(ctx: ScriptContext) -> CheckResult:
    failures = []
    rebuilt = 0
    dropped = 0

    for index, func in enumerate(ctx.parser.functions):
        tracker = CallDebugInfoTracker(get_param_count = ctx.parser.get_func_argc)
        for inst in ctx.instructions[index]:
            payload = inst.operands[0].value if inst.opcode in PUSH_CONSTANT_OPS else None
            tracker.on_opcode(inst.opcode, [operand.value for operand in inst.operands], payload)

        calls = tracker.ordered_calls()
        records = ctx.records[index]
        if len(calls) != len(records):
            failures.append(f'{func.name}: {len(calls)} call sites with line info, {len(records)} debug records')
            continue

        for i, (call, record) in enumerate(zip(calls, records)):
            problem = compare_record(ctx, call, record)
            if problem is not None:
                failures.append(f'{func.name} record {i}: {problem}')
                continue

            rebuilt += 1
            if record.arg_count < len(call.args):
                dropped += 1

    summary = f'{rebuilt} records rebuilt ({dropped} with dropped default args)'
    return CheckResult.build('debug records', summary, failures)


def function_extents(ctx: ScriptContext, pool_start: int) -> dict[int, tuple[int, int]]:
    """table index -> (start, end) physical byte range in code order"""
    starts = [ctx.entries[index].offset for index in ctx.code_order]
    ends = starts[1:] + [pool_start]
    return dict(zip(ctx.code_order, zip(starts, ends)))


def dropped_ranges(insts: list[Instruction], start: int, end: int) -> list[tuple[int, int, Instruction | None]]:
    """[start, end) not covered by insts, each paired with the instruction right before it (if any)"""
    ranges = []
    cursor = start
    prev = None

    for inst in insts:
        if inst.offset > cursor:
            ranges.append((cursor, inst.offset, prev))

        cursor = max(cursor, inst.offset + inst.size)
        prev = inst

    if cursor < end:
        ranges.append((cursor, end, prev))

    return ranges


def check_instruction_ranges(insts: list[Instruction], start: int, end: int) -> list[str]:
    """No two reachable instructions overlap, and every branch target lands on a reachable
    instruction start inside [start, end) - never mid-instruction, never outside the function."""
    failures = []
    inst_starts = {inst.offset for inst in insts}

    for a, b in zip(insts, insts[1:]):
        if a.offset + a.size > b.offset:
            failures.append(f'instruction @0x{a.offset:X} (size {a.size}) overlaps @0x{b.offset:X}')

    for inst in insts:
        for op in inst.operands:
            if op.descriptor.type != OperandType.Offset:
                continue

            if not (start <= op.value < end) or op.value not in inst_starts:
                failures.append(f'{inst.mnemonic} @0x{inst.offset:X} targets 0x{op.value:X}, not a reachable instruction in this function')

    return failures


def call_pairing(insts: list[Instruction]) -> dict[int, bool]:
    """Per paired call opcode (CALL/CALL_SCRIPT): does its count match its continuation-push
    opcode's count (PUSH_RET_ADDR/PUSH_CALLER_FRAME)? Used by the reachability audit to know
    whether a dropped range following a call is provably dead."""
    counts = Counter(inst.opcode for inst in insts)
    return {op: counts[op] == counts[ret_op] for op, ret_op in PAIRED_CALL_OPS.items()}


def check_source_preconditions(ctx: ScriptContext, pool_start: int) -> CheckResult:
    """Fields the decompile normalizes away, which no check on a recompiled file could see - e.g. a
    non-canonical PUSH_CURRENT_FUNC_ID value would just get silently corrected by the writer. The
    PUSH_CURRENT_FUNC_ID value itself isn't rechecked here - check_code already validates it on
    every file, source included, and validate_file always runs before this does."""
    failures = []

    names = [func.name for func in ctx.parser.functions]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        failures.append(f'duplicate function names: {duplicates}')

    if ctx.parser.header.dword_14 != 0:
        failures.append(f'header dword_14 = 0x{ctx.parser.header.dword_14:X}, expected 0')

    for func, entry in zip(ctx.parser.functions, ctx.entries):
        expected = hash_func_Name(func.name)
        if entry.name_hash != expected:
            failures.append(f'{func.name}: name_hash 0x{entry.name_hash:X} != hash_func_Name 0x{expected:X}')

    extents = function_extents(ctx, pool_start)
    for index in ctx.code_order:
        func = ctx.parser.functions[index]
        insts = ctx.instructions[index]
        start, end = extents[index]

        failures.extend(f'{func.name}: {message}' for message in check_instruction_ranges(insts, start, end))

        counts = Counter(inst.opcode for inst in insts)
        for call_op, ret_op in PAIRED_CALL_OPS.items():
            if counts[call_op] != counts[ret_op]:
                failures.append(f'{func.name}: {counts[call_op]} {ED9_INSTRUCTION_TABLE.get_descriptor(call_op).mnemonic} vs {counts[ret_op]} {ED9_INSTRUCTION_TABLE.get_descriptor(ret_op).mnemonic}, expected equal')

        if counts[ED9Opcode.CALL] != counts[ED9Opcode.PUSH_CURRENT_FUNC_ID]:
            failures.append(f'{func.name}: {counts[ED9Opcode.CALL]} CALL vs {counts[ED9Opcode.PUSH_CURRENT_FUNC_ID]} PUSH_CURRENT_FUNC_ID, expected equal')

    summary = f'{len(ctx.parser.functions)} functions'
    return CheckResult.build('source preconditions', summary, failures)


def is_range_provably_dead(prev_opcode: int | None, paired: dict[int, bool]) -> bool:
    """Is a dropped range, following an instruction with opcode prev_opcode, safe to drop?

    RETURN/JMP/CALL_SCRIPT_NO_RETURN never link a continuation at all, so anything after them is
    unconditionally dead. CALL/CALL_SCRIPT do link one (via PUSH_RET_ADDR/PUSH_CALLER_FRAME), but a
    dropped range right after them is still dead as long as that call is paired - a paired call's
    own continuation, wherever it resumes, is by construction a real reachable instruction (never
    inside this same range, since every Offset target must land on one), so nothing between the
    call and its continuation can be referenced by anything.
    """
    return prev_opcode in REACHABLE_TERMINATORS or paired.get(prev_opcode, False)


def check_reachability(ctx: ScriptContext, pool_start: int) -> CheckResult:
    """Every dropped byte range must be provably dead - never assumed, and never trusted just
    because it happens to fail to disassemble as instructions."""
    failures = []
    dropped_bytes = 0
    extents = function_extents(ctx, pool_start)

    for index in ctx.code_order:
        func = ctx.parser.functions[index]
        insts = ctx.instructions[index]
        start, end = extents[index]
        paired = call_pairing(insts)

        for range_start, range_end, prev in dropped_ranges(insts, start, end):
            dropped_bytes += range_end - range_start
            prev_opcode = prev.opcode if prev is not None else None

            if is_range_provably_dead(prev_opcode, paired):
                continue

            mnemonic = prev.mnemonic if prev is not None else '<entry>'
            failures.append(f'{func.name}: 0x{range_start:X}..0x{range_end:X} follows {mnemonic}, not provably dead')

    summary = f'{dropped_bytes} dropped bytes'
    return CheckResult.build('reachability', summary, failures)


def check_string_fidelity(ctx: ScriptContext, pool_start: int) -> CheckResult:
    """Every pooled string must re-encode to exactly its raw bytes.

    The parser decodes with errors='ignore' (ReadMultiByte -> _ReadAString), which silently drops
    invalid bytes - a corrupted string would then decode shorter, re-encode without the dropped
    bytes, and still fingerprint the same as its own already-truncated value. Decoding here the same
    way and comparing against the raw pool bytes (not ctx.read_text's errors='replace') is what
    catches that.
    """
    failures = []
    count = 0
    position = pool_start
    encoding = default_encoding()

    while position < len(ctx.data):
        end = ctx.data.find(NUL, position)
        if end < 0:
            break  # unterminated string - already reported by check_string_pool

        raw = ctx.data[position:end]
        text = raw.decode(encoding, errors = 'ignore')
        if text.encode(encoding) != raw:
            failures.append(f'string at 0x{position:X}: {ascii(text)} does not re-encode to its raw bytes')

        count += 1
        position = end + 1

    summary = f'{count} strings checked'
    return CheckResult.build('string fidelity', summary, failures)


def check_common_order(common_orders: dict[Path, list[str]]) -> CheckResult:
    """Common functions come from a shared include, so their relative code order should agree across files"""
    reference = max(common_orders.values(), key = len)
    rank = {name: i for i, name in enumerate(reference)}
    warnings = []

    for path, order in common_orders.items():
        known = [name for name in order if name in rank]
        conflict = next(((a, b) for a, b in zip(known, known[1:]) if rank[a] > rank[b]), None)
        if conflict is not None:
            warnings.append(f'{path}: {conflict[0]} before {conflict[1]}')

    summary = f'{len(common_orders)} files, reference has {len(reference)} common functions'
    return CheckResult.build('common order', summary, [], warnings)


def decompile_to_python(dat_path: Path, py_path: Path, *, round_trip: bool = True, keep_unreachable_code: bool = True) -> tuple[ScpParser, list[Function]]:
    """Same DSL emission as scena2py.py's write_python_dsl. Explicit flags rather than relying on
    ScpParser's class defaults, which happen to match round_trip=True today but aren't guaranteed to.
    Returns the parser and its disassembled functions so callers can fingerprint them without
    re-parsing."""
    with contextlib.redirect_stdout(io.StringIO()):
        parser, functions = ScpParser.load(dat_path, round_trip = round_trip, keep_unreachable_code = keep_unreachable_code)

    py_path.write_text(parser.gen_python_script(functions), encoding = 'utf-8', newline = '\n')
    return parser, functions


def compile_dsl(py_path: Path, run_dir: Path) -> tuple[int, list[str]]:
    """Compile a generated .py in a subprocess. -P keeps run_dir off sys.path, so a script named
    after a top-level package (e.g. common.dat) can't shadow the real one; PYTHONPATH is set to
    exactly PROJECT_ROOT rather than appending an inherited value, which could point at a different
    checkout (e.g. activateVenv.bat sets it to the live tree)."""
    env = dict(os.environ)
    env['PYTHONPATH'] = str(PROJECT_ROOT)
    env['PYTHONIOENCODING'] = 'utf-8'

    result = subprocess.run(
        [sys.executable, '-P', '-c', ROUND_TRIP_RUNNER, py_path.name],
        cwd             = run_dir,
        env             = env,
        stdin           = subprocess.DEVNULL,
        capture_output  = True,
        text            = True,
        encoding        = 'utf-8',
        errors          = 'replace',
    )

    tail = (result.stderr or result.stdout).strip().splitlines()[-MAX_DETAILS:]
    return result.returncode, tail


def check_round_trip(path: Path, work_dir: Path) -> CheckResult:
    stem = path.name.split('.')[0]
    run_dir = Path(tempfile.mkdtemp(prefix = f'{stem}_', dir = work_dir))
    dat_path = run_dir / f'{stem}.dat'
    py_path = run_dir / f'{stem}.py'

    shutil.copyfile(path, dat_path)
    decompile_to_python(dat_path, py_path, round_trip = True, keep_unreachable_code = True)
    dat_path.unlink()

    returncode, tail = compile_dsl(py_path, run_dir)

    if returncode != 0 or not dat_path.exists():
        return CheckResult('round trip', Status.FAIL, f'recompile failed (exit {returncode}), kept {run_dir}', [ascii(line) for line in tail])

    original = path.read_bytes()
    rebuilt = dat_path.read_bytes()
    if original == rebuilt:
        shutil.rmtree(run_dir)
        return CheckResult('round trip', Status.PASS, f'identical ({len(original)} bytes)')

    first_diff = next((i for i, (a, b) in enumerate(zip(original, rebuilt)) if a != b), min(len(original), len(rebuilt)))
    summary = f'differs at 0x{first_diff:X} (original {len(original)} bytes, rebuilt {len(rebuilt)} bytes), kept {run_dir}'
    return CheckResult('round trip', Status.FAIL, summary)


@dataclass
class LogicSnapshot:
    """Everything the 'game logic' definition covers for one decompile: per-function (fingerprint,
    is_common_func) by name, the global table in index order (bytecode refers to globals by index,
    so order matters), and header dword_14."""
    fingerprints: dict[str, tuple]
    globals_table: list[tuple[str, int]]
    dword_14: int

    @classmethod
    def of(cls, parser: ScpParser, functions: list[Function]) -> 'LogicSnapshot':
        fingerprints = {func.name: (function_fingerprint(parser, func), func.is_common_func) for func in functions}
        globals_table = [(g.name, int(g.type)) for g in parser.global_vars]
        return cls(fingerprints, globals_table, parser.header.dword_14)


def compare_logic(source: LogicSnapshot, other: LogicSnapshot) -> CheckResult:
    """Everything the game logic definition covers, source vs one recompiled round"""
    failures = []

    missing = sorted(set(source.fingerprints) - set(other.fingerprints))
    extra = sorted(set(other.fingerprints) - set(source.fingerprints))
    if missing:
        failures.append(f'missing after recompile: {missing}')

    if extra:
        failures.append(f'extra after recompile: {extra}')

    for name in sorted(set(source.fingerprints) & set(other.fingerprints)):
        src_fingerprint, src_common = source.fingerprints[name]
        other_fingerprint, other_common = other.fingerprints[name]

        if src_fingerprint != other_fingerprint:
            failures.append(f'{name}: fingerprint differs after recompile')

        if src_common != other_common:
            failures.append(f'{name}: is_common_func {src_common} != {other_common}')

    if source.globals_table != other.globals_table:
        failures.append(f'global table differs: {source.globals_table} != {other.globals_table}')

    if source.dword_14 != other.dword_14:
        failures.append(f'header dword_14 {source.dword_14} != {other.dword_14}')

    summary = f'{len(source.fingerprints)} functions compared'
    return CheckResult.build('logic preserved', summary, failures)


def compile_and_decompile_round(stem: str, round_dir: Path, py_text: str) -> tuple[int, list[str], Path | None]:
    """One compile -> decompile round: writes py_text, compiles it, and (on success) decompiles the
    result back. Returns (returncode, compile output tail, the round's .dat path or None on failure)."""
    round_dir.mkdir()
    py_path = round_dir / f'{stem}.py'
    py_path.write_text(py_text, encoding = 'utf-8', newline = '\n')

    returncode, tail = compile_dsl(py_path, round_dir)
    dat_path = round_dir / f'{stem}.dat'
    if returncode != 0 or not dat_path.exists():
        return returncode, tail, None

    return returncode, tail, dat_path


def check_logic_round_trip(path: Path, work_dir: Path) -> list[CheckResult]:
    """Decompile with round_trip=False (the everyday config), then iterate compile -> decompile
    until output stabilizes. Game logic must match the source on every round (function order and
    label names may differ); byte layout only needs to reach a fixed point within
    MAX_CONVERGENCE_ROUNDS. Every round runs in its own directory but keeps the same <stem>
    basename, since the generated header embeds it and a changing name would stop out2 == out3 from
    ever holding even at a real fixed point."""
    stem = path.name.split('.')[0]
    results = []

    ctx = load_script(path)
    try:
        pool_start = collect_string_refs(ctx).pool_start
        results.append(check_source_preconditions(ctx, pool_start))
        results.append(check_reachability(ctx, pool_start))
        results.append(check_string_fidelity(ctx, pool_start))
    finally:
        ctx.fs.Close()

    file_dir = Path(tempfile.mkdtemp(prefix = f'{stem}_logic_', dir = work_dir))

    source_parser, source_functions = decompile_to_python(path, file_dir / f'{stem}.py', round_trip = False, keep_unreachable_code = False)
    source_snapshot = LogicSnapshot.of(source_parser, source_functions)
    py_texts = [(file_dir / f'{stem}.py').read_text(encoding = 'utf-8')]
    dat_bytes = []
    converged_round = None

    for round_num in range(1, MAX_CONVERGENCE_ROUNDS + 1):
        round_dir = file_dir / f'r{round_num}'
        returncode, tail, dat_path = compile_and_decompile_round(stem, round_dir, py_texts[-1])
        if dat_path is None:
            results.append(CheckResult('logic round trip', Status.FAIL, f'round {round_num} compile failed, kept {file_dir}', [ascii(line) for line in tail]))
            return results

        dat_bytes.append(dat_path.read_bytes())

        struct_results, _ = validate_file(dat_path)
        for result in struct_results:
            result.name = f'round {round_num} {result.name}'

        results.extend(struct_results)

        round_parser, round_functions = decompile_to_python(dat_path, round_dir / f'{stem}_out.py', round_trip = False, keep_unreachable_code = False)
        py_texts.append((round_dir / f'{stem}_out.py').read_text(encoding = 'utf-8'))

        # Checked every round, not just round 1: a file that only diverges after round 1 but still
        # happens to reach a byte-level fixed point must still fail here.
        logic_result = compare_logic(source_snapshot, LogicSnapshot.of(round_parser, round_functions))
        logic_result.name = f'round {round_num} {logic_result.name}'
        results.append(logic_result)

        if round_num >= 2 and dat_bytes[-2] == dat_bytes[-1] and py_texts[-2] == py_texts[-1]:
            converged_round = round_num
            break

    if converged_round is None:
        results.append(CheckResult('logic round trip', Status.FAIL, f'no fixed point within {MAX_CONVERGENCE_ROUNDS} rounds, kept {file_dir}'))

    else:
        results.append(CheckResult('logic round trip', Status.PASS, f'converged at round {converged_round}'))
        shutil.rmtree(file_dir, ignore_errors = True)

    return results


def validate_file(path: Path) -> tuple[list[CheckResult], list[str]]:
    ctx = load_script(path)

    try:
        refs = collect_string_refs(ctx)
        results = [
            check_layout(ctx),
            check_function_order(ctx),
            check_code(ctx, refs.pool_start),
            check_string_pool(ctx, refs),
            check_debug_records(ctx),
        ]
        common_order = [ctx.func_name(index) for index in ctx.code_order if ctx.parser.functions[index].is_common_func]

    finally:
        ctx.fs.Close()

    return results, common_order


def print_result(result: CheckResult, verbose: bool):
    print(f'  {result.status.name:<4}  {result.name:<14}  {result.summary}')

    if result.status == Status.PASS and not verbose:
        return

    details = result.details if verbose else result.details[:MAX_DETAILS]
    for line in details:
        print(f'{DETAIL_INDENT}{line}')

    if len(details) < len(result.details):
        print(f'{DETAIL_INDENT}... {len(result.details) - len(details)} more (--verbose)')


def collect_paths(paths: list[str]) -> list[Path]:
    files = []
    for name in paths:
        path = Path(name)

        if path.is_dir():
            files.extend(sorted(path.rglob(DAT_PATTERN)))

        else:
            files.append(path)

    return files


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description = 'Validate ED9-VM .dat scripts against the byte-exact round-trip rules')
    parser.add_argument('paths', nargs = '+', help = '.dat files or directories (searched recursively)')
    parser.add_argument('--round-trip', action = 'store_true', help = 'decompile, recompile and byte-compare each file')
    parser.add_argument('--logic-round-trip', action = 'store_true', help = 'decompile with round_trip=False and verify game logic is preserved and compile/decompile reaches a fixed point')
    parser.add_argument('--work-dir', metavar = 'DIR', help = 'where --round-trip / --logic-round-trip write their files (default: a new temp dir)')
    parser.add_argument('--verbose', action = 'store_true', help = 'print every detail, including for passing checks')
    return parser


def main() -> int:
    args = create_parser().parse_args()
    files = collect_paths(args.paths)

    work_dir = None
    if args.round_trip or args.logic_round_trip:
        work_dir = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix = 'scp_roundtrip_'))
        work_dir.mkdir(parents = True, exist_ok = True)
        print(f'work dir: {work_dir}')

    totals = {status: 0 for status in Status}
    common_orders = {}

    for path in files:
        print(f'== {path}')

        try:
            results, common_orders[path] = validate_file(path)

        except Exception as e:
            results = [CheckResult('load', Status.FAIL, f'{type(e).__name__}: {ascii(str(e))}')]

        if args.round_trip:
            try:
                results.append(check_round_trip(path, work_dir))

            except Exception as e:
                results.append(CheckResult('round trip', Status.FAIL, f'{type(e).__name__}: {ascii(str(e))}'))

        if args.logic_round_trip:
            try:
                results.extend(check_logic_round_trip(path, work_dir))

            except Exception as e:
                results.append(CheckResult('logic round trip', Status.FAIL, f'{type(e).__name__}: {ascii(str(e))}'))

        for result in results:
            print_result(result, args.verbose)

        totals[max(result.status for result in results)] += 1

    if len(common_orders) > 1:
        print('== all files')
        print_result(check_common_order(common_orders), args.verbose)

    print(f'== {len(files)} files: ' + ', '.join(f'{totals[status]} {status.name}' for status in Status))
    return 1 if totals[Status.FAIL] else 0


if __name__ == '__main__':
    sys.exit(main())
