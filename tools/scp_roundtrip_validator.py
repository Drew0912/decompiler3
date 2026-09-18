"""
SCP Round-Trip Validator

Checks that ED9-VM .dat scripts follow the layout rules ScpWriter relies on for a byte-exact
round trip, and optionally decompiles, recompiles and byte-compares each file.

Usage:
    python tools/scp_roundtrip_validator.py script_en/scena/e2000.original.dat
    python tools/scp_roundtrip_validator.py script_en --verbose
    python tools/scp_roundtrip_validator.py script_en/scena/e0000.original.dat --round-trip

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

Baseline (2026-09-17, format checks, no FAIL):
    e0000.original.dat      PASS, 1 debug record
    e2000.original.dat      PASS, 235 debug records (42 with dropped default args)
    system.original.dat     WARN: unreachable code - 62 JMPs after RETURN, 1 after a JMP, 2 trailing returns,
                            4805 debug records (747 dropped)
    mp0000_ev.dat           WARN: 3 unreachable JMPs, 19461 debug records (7872 dropped)
    ai_chr0100_e00.dat      WARN: 1 unreachable JMP, 37 debug records
"""

import argparse
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml import fileio
from common.config import default_encoding, default_endian
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9_INSTRUCTION_TABLE, ED9Opcode, Instruction
from falcom.ed9.parser.scp import ScpParser, CallDebugInfoTracker, TrackedCall, PUSH_CONSTANT_OPS
from falcom.ed9.parser.types_scp import (
    ScpFunctionCallDebugInfo,
    ScpFunctionCallDebugInfoArg,
    ScpFunctionEntry,
    ScpGlobalVar,
    ScpHeader,
    ScpValue,
)
from falcom.ed9.writer.scp_writer import NON_CONSTANT_ARG_VALUE, PUSH_SIZE_BYTE


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

# Runs a generated script without Try(main), which pauses for a key press on errors
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
            matches = raw_value == int.from_bytes(ScpValue(NON_CONSTANT_ARG_VALUE).to_bytes(), default_endian())

        elif isinstance(payload, str):
            offset = string_offset(raw_value)
            matches = offset is not None and ctx.read_text(offset) == payload

        else:
            matches = raw_value == int.from_bytes(ScpValue(payload).to_bytes(), default_endian())

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


def decompile_to_python(dat_path: Path, py_path: Path):
    """Same output as tests/test_llil_file.py"""
    with fileio.FileStream(str(dat_path), encoding = default_encoding()) as fs:
        parser = ScpParser(fs, dat_path.name)

        with contextlib.redirect_stdout(io.StringIO()):
            parser.parse()
            functions = parser.disasm_all_functions()

        lines = parser.gen_python_header()
        for func in functions:
            lines.extend(parser.format_function(func))
            lines.append('')

        lines.extend(parser.gen_python_footer())

    py_path.write_text('\n'.join(lines) + '\n', encoding = 'utf-8')


def check_round_trip(path: Path, work_dir: Path) -> CheckResult:
    stem = path.name.split('.')[0]
    run_dir = Path(tempfile.mkdtemp(prefix = f'{stem}_', dir = work_dir))
    dat_path = run_dir / f'{stem}.dat'
    py_path = run_dir / f'{stem}.py'

    shutil.copyfile(path, dat_path)
    decompile_to_python(dat_path, py_path)
    dat_path.unlink()

    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [str(PROJECT_ROOT), env.get('PYTHONPATH')]))
    env['PYTHONIOENCODING'] = 'utf-8'

    result = subprocess.run(
        [sys.executable, '-c', ROUND_TRIP_RUNNER, py_path.name],
        cwd             = run_dir,
        env             = env,
        stdin           = subprocess.DEVNULL,
        capture_output  = True,
        text            = True,
        encoding        = 'utf-8',
        errors          = 'replace',
    )

    if result.returncode != 0 or not dat_path.exists():
        output = (result.stderr or result.stdout).strip().splitlines()
        return CheckResult('round trip', Status.FAIL, f'recompile failed (exit {result.returncode}), kept {run_dir}', [ascii(line) for line in output[-MAX_DETAILS:]])

    original = path.read_bytes()
    rebuilt = dat_path.read_bytes()
    if original == rebuilt:
        shutil.rmtree(run_dir)
        return CheckResult('round trip', Status.PASS, f'identical ({len(original)} bytes)')

    first_diff = next((i for i, (a, b) in enumerate(zip(original, rebuilt)) if a != b), min(len(original), len(rebuilt)))
    summary = f'differs at 0x{first_diff:X} (original {len(original)} bytes, rebuilt {len(rebuilt)} bytes), kept {run_dir}'
    return CheckResult('round trip', Status.FAIL, summary)


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
    parser.add_argument('--work-dir', metavar = 'DIR', help = 'where --round-trip writes its files (default: a new temp dir)')
    parser.add_argument('--verbose', action = 'store_true', help = 'print every detail, including for passing checks')
    return parser


def main() -> int:
    args = create_parser().parse_args()
    files = collect_paths(args.paths)

    work_dir = None
    if args.round_trip:
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
