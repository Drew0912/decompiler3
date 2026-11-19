"""The layout rules ScpWriter relies on for a byte-exact round trip, checked on every file (validate_file) and on
each logic round's rebuilt one"""

from pathlib import Path

from dc3.config import default_encoding
from assembler import Instruction
from falcom.ed9.assembler import ED9_INSTRUCTION_TABLE, ED9Opcode
from falcom.ed9.assembler.vm import WORD_SIZE
from falcom.ed9.structs.call_debug_records import pair_records
from falcom.ed9.parser.code_layout import dropped_ranges
from falcom.ed9.parser.scp import OPCODE_SIZE
from falcom.ed9.structs.string_pool import NUL, StringRefs, collect_string_refs, read_text, read_u32
from falcom.ed9.structs.scp_types import (ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpFunctionEntry,
                                          ScpGlobalVar, ScpHeader)
from falcom.ed9.writer.scp_writer import PUSH_SIZE_BYTE
from .results import CheckResult, first_difference
from .script_context import ScriptContext, load_script


UINT8_SIZE        = 1
PUSH_SIZE_OFFSET  = OPCODE_SIZE  # PUSH opcode, u8 size, ScpValue
PUSH_VALUE_OFFSET = PUSH_SIZE_OFFSET + UINT8_SIZE


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
            offset = get_offset(entry)
            if offset != position:
                failures.append(f'{ctx.func_name(index)}: {field_name} 0x{offset:X} != running offset 0x{position:X}')

            position += get_size(entry)

    record_count = 0
    arg_count = 0
    for index, records in enumerate(ctx.records):
        for record in records:
            if record.info_offset != position:
                failures.append(f'{ctx.func_name(index)}: record info_offset 0x{record.info_offset:X} '
                                f'!= running offset 0x{position:X}')

            position += record.arg_count * ScpFunctionCallDebugInfoArg.SIZE
            record_count += 1
            arg_count += record.arg_count

    if header.global_var_offset != position:
        failures.append(f'global_var_offset 0x{header.global_var_offset:X} != debug args end 0x{position:X}')

    position += header.global_var_count * ScpGlobalVar.SIZE

    first_code = min((entry.offset for entry in ctx.entries), default=position)
    if first_code != position:
        failures.append(f'first code offset 0x{first_code:X} != global var table end 0x{position:X}')

    summary = (f'{len(ctx.entries)} functions, {record_count} debug records, {arg_count} debug args, '
               f'{header.global_var_count} global vars')
    return CheckResult.build('layout', summary, failures)


def check_function_order(ctx: ScriptContext) -> CheckResult:
    failures = []
    warnings = []
    encoding = default_encoding()

    names = [func.name for func in ctx.parser.functions]
    if names != sorted(names, key=lambda name: name.encode(encoding)):
        failures.append('function table is not sorted by name')

    hashes = [entry.name_hash for entry in ctx.entries]
    hash_note = 'also' if hashes == sorted(hashes) else 'not'

    common_count = 0
    source_count = 0
    previous_name, previous_max_line = None, None
    for index in ctx.code_order:
        func = ctx.parser.functions[index]
        line_numbers = [inst.operands[0].value for inst in ctx.instructions[index]
                        if inst.opcode == ED9Opcode.DEBUG_SET_LINENO]

        if func.is_common_func:
            common_count += 1

            if source_count:
                failures.append(f'{func.name}: common function code follows a source function')

            if line_numbers:
                failures.append(f'{func.name}: common function has DEBUG_SET_LINENO')

            continue

        source_count += 1

        if not line_numbers:
            warnings.append(f'{func.name}: source function has no DEBUG_SET_LINENO, order not checked')
            continue

        if previous_name is not None and line_numbers[0] <= previous_max_line:
            failures.append(f'{func.name}: first line {line_numbers[0]} <= line {previous_max_line} of {previous_name}')

        previous_name, previous_max_line = func.name, max(line_numbers)

    summary = f'sorted by name ({hash_note} by hash); {common_count} common + {source_count} source functions'
    return CheckResult.build('function order', summary, failures, warnings)


def push_size_byte(data: bytes, inst: Instruction) -> int | None:
    """A PUSH's size byte, else None; tested on the raw opcode byte, since a decoded PUSH carries its value's
    pseudo-op (PUSH_INT, PUSH_CURRENT_FUNC_ID, ...)"""
    if data[inst.offset] != ED9Opcode.PUSH:
        return None

    return data[inst.offset + PUSH_SIZE_OFFSET]


def check_code(ctx: ScriptContext, pool_start: int) -> CheckResult:
    failures = []
    warnings = []

    for index, func, insts, extent in ctx.functions_in_code_order(pool_start):
        for start, end, _ in dropped_ranges(insts, *extent):
            warnings.append(f'{func.name}: unreachable 0x{start:X}..0x{end:X}: {describe_range(ctx, start, end)}')

        for inst in insts:
            size_byte = push_size_byte(ctx.data, inst)
            if size_byte is not None and size_byte != PUSH_SIZE_BYTE:
                failures.append(f'{func.name} @0x{inst.offset:X}: PUSH size byte {size_byte} != {PUSH_SIZE_BYTE}')

            if inst.opcode == ED9Opcode.PUSH_CURRENT_FUNC_ID:
                func_id = read_u32(ctx.data, inst.offset + PUSH_VALUE_OFFSET)
                if func_id != index:
                    failures.append(f'{func.name} @0x{inst.offset:X}: PUSH_CURRENT_FUNC_ID pushes {func_id}, '
                                    f'table index is {index}')

    summary = f'{len(warnings)} unreachable ranges'
    return CheckResult.build('code', summary, failures, warnings)


def pool_entry_text(data: bytes, positions: list[int], index: int, past_end: str) -> str:
    """positions[index]'s string as a pool mismatch names it, or past_end when the list is shorter"""
    if index >= len(positions):
        return past_end

    return f'0x{positions[index]:X} {ascii(read_text(data, positions[index]))}'


def check_string_pool(ctx: ScriptContext, refs: StringRefs) -> CheckResult:
    failures = []

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
        mismatch = first_difference(actual, expected)
        actual_text = pool_entry_text(ctx.data, actual, mismatch, 'end of file')
        expected_text = pool_entry_text(ctx.data, expected, mismatch, 'end of references')
        failures.append(f'pool string #{mismatch}: found {actual_text}, expected {expected_text} '
                        f'({len(actual)} strings, {len(expected)} references)')

    summary = (f'{len(actual)} strings: {len(refs.code)} code, {len(refs.names)} names, {len(refs.defaults)} defaults, '
               f'{len(refs.debug)} debug-only, {len(refs.global_names)} global names')
    return CheckResult.build('string pool', summary, failures)


def check_debug_records(ctx: ScriptContext) -> CheckResult:
    failures = []
    warnings = []
    rebuilt = 0
    dropped = 0

    for index, func in enumerate(ctx.parser.functions):
        # Dead calls have records too: pair over the code the .py prints, reachable and dead
        pairing = pair_records(ctx.data, func.code_instructions(), ctx.records[index],
                               ctx.parser.get_func_argc, ctx.parser.get_func_index, func.is_common_func)
        if pairing.call_count != pairing.record_count and not pairing.paired:
            failures.append(f'{func.name}: {pairing.call_count} call sites, {pairing.record_count} debug records')
            continue

        # A call the compiler left without a record (aligned): a new one may be a tracker regression
        warnings += [f'{func.name}: call @0x{offset:X} has no record' for offset in pairing.unrecorded]
        failures += [f'{func.name} record {i}: {problem}' for i, problem in pairing.mismatches]
        rebuilt += len(pairing.matches)
        dropped += sum(match.record.arg_count < len(match.call.args) for match in pairing.matches)

    summary = f'{rebuilt} records rebuilt ({dropped} with dropped default args)'
    return CheckResult.build('debug records', summary, failures, warnings)


def check_common_order(common_orders: dict[Path, list[str]]) -> CheckResult:
    """Common functions come from a shared include, so their relative code order should agree across files"""
    reference = max(common_orders.values(), key=len)
    rank = {name: i for i, name in enumerate(reference)}
    warnings = []

    for path, order in common_orders.items():
        known = [name for name in order if name in rank]
        conflict = next(((a, b) for a, b in zip(known, known[1:]) if rank[a] > rank[b]), None)
        if conflict is not None:
            warnings.append(f'{path}: {conflict[0]} before {conflict[1]}')

    summary = f'{len(common_orders)} files, reference has {len(reference)} common functions'
    return CheckResult.build('common order', summary, [], warnings)


def validate_file(path: Path) -> tuple[list[CheckResult], list[str]]:
    with load_script(path) as ctx:
        refs = collect_string_refs(ctx.data, ctx.parser, ctx.records)
        results = [
            check_layout(ctx),
            check_function_order(ctx),
            check_code(ctx, refs.pool_start),
            check_string_pool(ctx, refs),
            check_debug_records(ctx),
        ]
        common_order = [ctx.func_name(index) for index in ctx.code_order if ctx.parser.functions[index].is_common_func]

    return results, common_order
