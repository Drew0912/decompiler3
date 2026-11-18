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


# Reachability audit (--logic-round-trip): a dropped byte range is provably dead only when the
# reachable instruction right before it can't fall through - RETURN/JMP/CALL_SCRIPT_NO_RETURN never
# link a continuation at all, and CALL/CALL_SCRIPT only do so via a paired PUSH_RET_ADDR/
# PUSH_CALLER_FRAME (checked separately, per function) - so a range after an unpaired one is unproven
REACHABLE_TERMINATORS = (ED9Opcode.RETURN, ED9Opcode.JMP, ED9Opcode.CALL_SCRIPT_NO_RETURN)
PAIRED_CALL_OPS       = {ED9Opcode.CALL: ED9Opcode.PUSH_RET_ADDR, ED9Opcode.CALL_SCRIPT: ED9Opcode.PUSH_CALLER_FRAME}


def check_instruction_ranges(insts: list[Instruction], start: int, end: int) -> list[str]:
    """Every branch target lands on a reachable instruction start inside [start, end) - never mid-instruction, never
    outside the function"""
    failures = []
    inst_starts = {inst.offset for inst in insts}

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
        expected = hash_function_name(func.name)
        if entry.name_hash != expected:
            failures.append(f'{func.name}: name_hash 0x{entry.name_hash:X} != hash_function_name 0x{expected:X}')

    for _, func, insts, extent in ctx.functions_in_code_order(pool_start):
        failures.extend(f'{func.name}: {message}' for message in check_instruction_ranges(insts, *extent))

        counts = Counter(inst.opcode for inst in insts)
        for call_op, ret_op in PAIRED_CALL_OPS.items():
            if counts[call_op] != counts[ret_op]:
                failures.append(f'{func.name}: {counts[call_op]} {call_op.name} vs {counts[ret_op]} {ret_op.name}, expected equal')

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
    """Every pooled string must re-encode to exactly its raw bytes.

    The parser decodes with errors='ignore' (ReadMultiByte -> _ReadAString), which silently drops
    invalid bytes - a corrupted string would then decode shorter, re-encode without the dropped
    bytes, and still fingerprint the same as its own already-truncated value. Decoding here the same
    way and comparing against the raw pool bytes (not ctx.read_text's errors='replace') is what
    catches that.
    """
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
