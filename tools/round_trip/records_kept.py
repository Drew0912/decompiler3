"""Whether a logic round keeps the call-site records the engine reads, call by call (docs/ROUND_TRIP_POLICY.md,
Records the engine reads)"""

from collections import Counter
from dataclasses import dataclass, replace

from falcom.ed9.structs.call_debug_records import (CallDebugInfoTracker, RecordPairing, RecordView, TrackedCall,
                                                    canonical_argc, pair_records)
from falcom.ed9.assembler.function import Function
from falcom.ed9.structs.scp_types import ScpFunctionCallDebugInfo
from .record_comparison import arg_text, file_record_views, view_difference, view_text
from .results import CheckResult
from .script_context import ScriptContext


# The clip walk's functions (of its nine) that don't fall back on their defaults (docs/falcom/ed9/ED9_VM.md, Who reads
# the call-site records): a record that drops a String of theirs drops a name
NO_DEFAULT_FALLBACK = {'chr_play_animeclip', 'chr_attach_load_model'}

# What a rebuild may leave out or add, with its reason: docs/ROUND_TRIP_POLICY.md, Records the engine reads
EXCUSED_COMMON      = 'common'
EXCUSED_DEAD        = 'dead'
EXCUSED_EXTRA       = 'extra'
EXCUSED_NO_CODE     = 'no code'
EXCUSED_SECOND_COPY = 'second copy'


@dataclass(frozen=True, slots=True)
class RecordSlot:
    """A call the rebuilt file keeps: the source's record for it (None: the compiler left it without one), the function
    a local call calls and how many arguments a local record can't drop"""

    record      : RecordView | None
    callee      : str | None
    min_argc    : int


@dataclass
class SourceRecords:
    """A function's records in the source, as each round's are held against them"""

    record_count    : int
    is_common       : bool
    slots           : list[RecordSlot] | None       # one per call kept, in record order; None: the records don't pair
    excused         : Counter[str]                  # source records no rebuild can keep, by reason


def is_doubled(views: list[RecordView]) -> bool:
    """A doubled record list: its second half repeats the first (docs/falcom/ed9/ED9_FORMAT.md, Call-Site Debug
    Records, 8)"""
    half = len(views) // 2
    return views[:half] == views[half:]


def source_records(ctx: ScriptContext) -> dict[str, SourceRecords]:
    """Each function's records by name. The source's bytes are the oracle: the tracker only says which calls are dead
    or left without a record"""
    views = file_record_views(ctx.data)
    return {func.name: function_source_records(ctx, index, views[func.name])
            for index, func in enumerate(ctx.parser.functions)}


def function_source_records(ctx: ScriptContext, index: int, views: list[RecordView]) -> SourceRecords:
    parser = ctx.parser
    func = parser.functions[index]
    records = ctx.records[index]
    instructions = func.code_instructions()
    calls = CallDebugInfoTracker.replay(instructions, parser.get_func_argc)
    source = SourceRecords(len(records), func.is_common_func, [], Counter())

    def pairing_of(kept: list[ScpFunctionCallDebugInfo]) -> RecordPairing:
        return pair_records(ctx.data, instructions, kept, parser.get_func_argc, parser.get_func_index,
                            func.is_common_func)

    # The calls were compiled away, so nothing can hold these records
    if records and not calls:
        source.excused[EXCUSED_NO_CODE] = len(records)
        return source

    pairing = pairing_of(records)
    if not pairing.paired and is_doubled(views):
        half = len(records) // 2
        source.excused[EXCUSED_SECOND_COPY] = half
        records, views = records[:half], views[:half]
        pairing = pairing_of(records)

    # A common function the source holds no records for keeps no slots: a record a rebuild writes for it fails as
    # extra, not excused as a call the compiler left without one
    if not pairing.paired:
        source.slots = None
    elif records or not func.is_common_func:
        source.slots = record_slots(ctx, func, calls, views, pairing, source.excused)

    return source


def record_slots(ctx: ScriptContext, func: Function, calls: list[tuple[TrackedCall, int]], views: list[RecordView],
                 pairing: RecordPairing, excused: Counter[str]) -> list[RecordSlot]:
    """One slot per call the everyday decompile keeps: dead calls go, and their records are excused"""
    parser = ctx.parser
    dead = {inst.offset for inst in func.unreachable_instructions()}
    record_at = {offset: index for index, offset in pairing.record_offsets.items()}
    slots = []
    for call, offset in calls:
        if offset in dead:
            excused[EXCUSED_DEAD] += offset in record_at
            continue

        callee, min_argc = None, 0
        if call.call_type == ScpFunctionCallDebugInfo.CallType.Local:
            callee = parser.functions[call.target].name
            min_argc = canonical_argc(call.args, parser.func_defaults()[call.target])

        slots.append(RecordSlot(views[record_at[offset]] if offset in record_at else None, callee, min_argc))

    return slots


def slot_problem(slot: RecordSlot, rebuilt: RecordView) -> str | None:
    """How rebuilt falls short of its slot; a local record can differ in its trailing arguments, down to
    slot.min_argc"""
    source = slot.record
    if source is None:
        is_local = rebuilt.call_type == ScpFunctionCallDebugInfo.CallType.Local
        return None if is_local and rebuilt.callee == slot.callee else f'{view_text(rebuilt)}, call of {slot.callee}'

    if source.call_type != ScpFunctionCallDebugInfo.CallType.Local:
        return view_difference(source, rebuilt)

    shared = min(len(source.args), len(rebuilt.args))
    difference = view_difference(replace(source, args=source.args[:shared]),
                                 replace(rebuilt, args=rebuilt.args[:shared]))
    if difference is not None:
        return difference

    if shared < min(slot.min_argc, len(source.args)):
        return f'{shared} args, the rule keeps {slot.min_argc}'

    dropped = source.args[shared:]
    if source.callee in NO_DEFAULT_FALLBACK and any(isinstance(word, str) for _, word in dropped):
        return f'{source.callee} dropped a String: {', '.join(arg_text(arg) for arg in dropped)}'

    return None


def first_slot_problem(slots: list[RecordSlot], rebuilt: list[RecordView]) -> str | None:
    for i, (slot, view) in enumerate(zip(slots, rebuilt)):
        problem = slot_problem(slot, view)
        if problem is not None:
            return f'record {i}: {problem}'

    if len(rebuilt) < len(slots):
        slot = slots[len(rebuilt)]
        return f'record {len(rebuilt)}: missing ({view_text(slot.record) if slot.record else slot.callee})'

    if len(rebuilt) > len(slots):
        return f'record {len(slots)}: extra ({view_text(rebuilt[len(slots)])})'

    return None


def check_records_kept(source: dict[str, SourceRecords], rebuilt: dict[str, list[RecordView]]) -> CheckResult:
    """Every rebuilt record against the call it belongs to; the first problem of each function"""
    failures = []
    excused = Counter()
    kept = trimmed = 0

    for name, source_function in source.items():
        views = rebuilt.get(name)
        if views is None:   # check_logic_preserved reports it
            continue

        # The suite tests that kuro's writer keeps these: only the sora writers' rule leaves them out
        if source_function.is_common and source_function.record_count and not views:
            excused[EXCUSED_COMMON] += source_function.record_count
            continue

        excused.update(source_function.excused)
        if source_function.slots is None:
            failures.append(f"{name}: the source's {source_function.record_count} records don't pair with its calls")
            continue

        problem = first_slot_problem(source_function.slots, views)
        if problem is not None:
            failures.append(f'{name} {problem}')
            continue

        for slot, view in zip(source_function.slots, views):
            if slot.record is None:
                excused[EXCUSED_EXTRA] += 1
            else:
                kept += 1
                trimmed += len(view.args) < len(slot.record.args)

    excuses = ''.join(f', {count} {reason}' for reason, count in sorted(excused.items()) if count)
    return CheckResult.build('records kept', f'{kept} kept ({trimmed} trimmed){excuses}', failures)
