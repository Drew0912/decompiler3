"""The logic round trip's checks of the source, before any round: what its decompile normalizes away, that every
dropped byte range is provably dead, that every pooled string re-encodes to its raw bytes"""

from collections import Counter

from dc3.config import default_encoding
from assembler import Instruction, OperandType
from falcom.ed9.assembler import ED9Opcode
from falcom.ed9.parser.code_layout import dropped_ranges
from falcom.ed9.structs.crc32 import hash_function_name
from falcom.ed9.structs.string_pool import NUL, pool_strings
from .results import CheckResult
from .script_context import ScriptContext


# A dropped range is provably dead after these (is_range_provably_dead): opcodes that link no continuation, and calls
# each paired with its continuation push (call_pairing)
NO_CONTINUATION_OPS = (ED9Opcode.RETURN, ED9Opcode.JMP, ED9Opcode.CALL_SCRIPT_NO_RETURN)
PAIRED_CALL_OPS     = {ED9Opcode.CALL: ED9Opcode.PUSH_RET_ADDR, ED9Opcode.CALL_SCRIPT: ED9Opcode.PUSH_CALLER_FRAME}

# Opcode pairs a function's code holds equally many of: a call and its continuation push, a CALL and its
# PUSH_CURRENT_FUNC_ID
EQUAL_COUNT_OPS     = (*PAIRED_CALL_OPS.items(), (ED9Opcode.CALL, ED9Opcode.PUSH_CURRENT_FUNC_ID))


def branch_target_failures(insts: list[Instruction], start: int, end: int) -> list[str]:
    """Every branch target lands on a reachable instruction start inside [start, end): never mid-instruction, never
    outside the function"""
    failures = []
    inst_starts = {inst.offset for inst in insts}

    for inst in insts:
        for op in inst.operands:
            if op.descriptor.type != OperandType.Offset:
                continue

            if not (start <= op.value < end) or op.value not in inst_starts:
                failures.append(f'{inst.mnemonic} @0x{inst.offset:X} targets 0x{op.value:X}, '
                                'not a reachable instruction in this function')

    return failures


def call_pairing(insts: list[Instruction]) -> dict[int, bool]:
    """Per call opcode in PAIRED_CALL_OPS: whether its count matches its continuation push's
    (is_range_provably_dead)"""
    counts = Counter(inst.opcode for inst in insts)
    return {op: counts[op] == counts[ret_op] for op, ret_op in PAIRED_CALL_OPS.items()}


def check_source_preconditions(ctx: ScriptContext, pool_start: int) -> CheckResult:
    """Fields the decompile normalizes away, which no check on a recompiled file could see (the writer silently
    corrects a non-canonical value); PUSH_CURRENT_FUNC_ID's value is left to check_code, which the command line runs
    on every file, the source included, first"""
    failures = []

    names = [func.name for func in ctx.parser.functions]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        failures.append(f'duplicate function names: {duplicates}')

    if ctx.parser.header.dword_14 != 0:
        failures.append(f'header dword_14 = 0x{ctx.parser.header.dword_14:X}, expected 0')

    for func, entry in zip(ctx.parser.functions, ctx.entries):
        expected = hash_function_name(func.name)
        if entry.name_hash != expected:
            failures.append(f'{func.name}: name_hash 0x{entry.name_hash:X} != hash_function_name 0x{expected:X}')

    for _, func, insts, extent in ctx.functions_in_code_order(pool_start):
        failures.extend(f'{func.name}: {message}' for message in branch_target_failures(insts, *extent))

        counts = Counter(inst.opcode for inst in insts)
        for opcode, partner in EQUAL_COUNT_OPS:
            if counts[opcode] != counts[partner]:
                failures.append(f'{func.name}: {counts[opcode]} {opcode.name} vs {counts[partner]} {partner.name}, '
                                'expected equal')

    summary = f'{len(ctx.parser.functions)} functions'
    return CheckResult.build('source preconditions', summary, failures)


def is_range_provably_dead(prev_opcode: int | None, paired: dict[int, bool]) -> bool:
    """Whether a dropped range after an instruction with opcode prev_opcode is safe to drop: always after one that
    links no continuation (NO_CONTINUATION_OPS); after CALL / CALL_SCRIPT only when the function's calls of that
    opcode pair (call_pairing), since a paired call's continuation is a reachable instruction outside the range
    (every Offset target lands on one), so nothing reaches the bytes between"""
    return prev_opcode in NO_CONTINUATION_OPS or paired.get(prev_opcode, False)


def check_reachability(ctx: ScriptContext, pool_start: int) -> CheckResult:
    """Every dropped byte range must be provably dead - never assumed, and never trusted just
    because it happens to fail to disassemble as instructions"""
    failures = []
    dropped_bytes = 0

    for _, func, insts, extent in ctx.functions_in_code_order(pool_start):
        paired = call_pairing(insts)

        for range_start, range_end, prev in dropped_ranges(insts, *extent):
            dropped_bytes += range_end - range_start
            prev_opcode = prev.opcode if prev is not None else None

            if is_range_provably_dead(prev_opcode, paired):
                continue

            mnemonic = prev.mnemonic if prev is not None else '<entry>'
            failures.append(f'{func.name}: 0x{range_start:X}..0x{range_end:X} follows {mnemonic}, not provably dead')

    summary = f'{dropped_bytes} dropped bytes'
    return CheckResult.build('reachability', summary, failures)


def check_string_fidelity(ctx: ScriptContext, pool_start: int) -> CheckResult:
    """Every pooled string re-encodes to exactly its raw bytes: the parser decodes with errors='ignore'
    (ReadMultiByte -> _ReadAString), so a corrupted string decodes shorter and fingerprints the same as its truncated
    value; decoding the same way and comparing with the raw pool bytes (not read_text's errors='replace') catches it"""
    failures = []
    encoding = default_encoding()
    positions = pool_strings(ctx.data, pool_start)  # an unterminated tail is left out: check_string_pool reports it

    for position in positions:
        raw = ctx.data[position:ctx.data.index(NUL, position)]
        text = raw.decode(encoding, errors='ignore')
        if text.encode(encoding) != raw:
            failures.append(f'string at 0x{position:X}: {ascii(text)} does not re-encode to its raw bytes')

    summary = f'{len(positions)} strings checked'
    return CheckResult.build('string fidelity', summary, failures)
