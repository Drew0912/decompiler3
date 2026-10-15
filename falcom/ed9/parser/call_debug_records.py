"""Call-site debug records: CallDebugInfoTracker rebuilds the records a function's calls get from its opcodes (shared by
the parser, ScpWriter, the listing and tools/scp_roundtrip_validator.py); each function's raw records, each record's
raw arguments, a script call's callee id and name (script_call_identity, shared by the writer and the check), a
record's view for comparing two files, and whether a record holds what its call would get (content only - the
writer's own rules stay with the round-trip validator)"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from dc3 import fileio
from dc3.logging import log
from ..disasm import ED9_INSTRUCTION_TABLE, ED9Opcode, Instruction, InstructionKind
from ..disasm.ed9_optable import opcodes_of
from ..disasm.stack_effects import CALLEE_OPERAND, REGISTER_OPERAND, RESULT_REGISTER
from .string_pool import read_text, read_u32, string_offset
from .types_scp import ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpValue

# An annotation only: scp.py imports this module
if TYPE_CHECKING:
    from .scp import ScpParser

PUSH_CONSTANT_OPS = opcodes_of(InstructionKind.PUSH_CONST)
SAME_SCRIPT_MODULE = ''     # a script call's module naming a function of the calling script


@dataclass(slots = True)
class TrackedValue:
    """Simulated eval-stack slot; never changed once made, so a register and the stack may share one"""
    type        : ScpFunctionCallDebugInfoArg.Type
    payload     : ScpValue | None = None            # a constant's value
    string      : Any = None                        # the writer's pooled string of a String constant
    calls       : tuple['TrackedCall', ...] = ()    # the outermost calls nested in this value, in evaluation order


@dataclass(eq = False, slots = True)
class TrackedCall:
    """Call site, and its node in its statement's call tree"""
    call_type   : ScpFunctionCallDebugInfo.CallType
    target      : Any                               # CALL operand, (module, func) or (subsystem, cmd)
    ret_label   : Any                               # PUSH_RET_ADDR operand of a local CALL
    args        : list[TrackedValue]                # top of stack first (parameter order)
    recorded    : bool                              # made after line info, so it has a debug record
    children    : list['TrackedCall'] = field(default_factory = list)  # the calls nested in its args, parameter order
    parent      : 'TrackedCall | None' = None


def nested_calls(values) -> tuple[TrackedCall, ...]:
    """The outermost calls nested in values, in their order"""
    calls = ()
    for value in values:
        if value.calls:
            calls += value.calls

    return calls


class CallDebugInfoTracker:
    """Rebuilds call-site debug-info records from opcodes fed in address order.

    A call adopts the calls nested in its arguments, in parameter order. Records are each statement's call tree in
    pre-order (an outer call's record before the calls in its arguments), statements in evaluation order. Registers
    hold the value last stored in them in address order - the compiler's provenance (a tail call's arguments parked in
    registers, a call's result in RESULT_REGISTER), not the VM's path dataflow: both arms of a branch replay in a row.
    """

    def __init__(self, get_param_count: Callable[[Any], int], warn: Callable[[str], None] = log.warning):
        self.get_param_count    = get_param_count
        self.warn               = warn                              # the writer's warn adds the .py line
        self.stack              : list[TrackedValue | None] = []    # None is a call frame slot
        self.frames             : list = []                         # ret_label of each call set up but not made yet
        self.registers          : dict[int, TrackedValue] = {}
        self.calls              : list[TrackedCall] = []            # every call made, in evaluation order
        self.has_line_info      = False

    def on_opcode(self, opcode: int, operands: list | tuple, payload: ScpValue | None = None, string: Any = None):
        """payload (and the writer's pooled string) of a constant push"""
        ArgType = ScpFunctionCallDebugInfoArg.Type
        CallType = ScpFunctionCallDebugInfo.CallType

        # No row (its operand format is unknown) and nothing to track; only a DSL feeds it
        if opcode == ED9Opcode.UNKNOWN_28:
            return

        descriptor = ED9_INSTRUCTION_TABLE.get_descriptor(opcode)
        effect = descriptor.effect

        # Arms in measured frequency order: each case alternative tried before the matching one costs a compare
        match descriptor.kind:
            case InstructionKind.PUSH_CONST:
                self.stack.append(TrackedValue(ArgType.Constant, payload, string))

            case InstructionKind.DEBUG_LINE:
                self.has_line_info = True

            # A call's setup pushes placeholders: its first push opens the call's frame, the return address labels it
            case InstructionKind.PUSH_FUNC_ID | InstructionKind.PUSH_CALLER_FRAME:
                self.frames.append(None)
                self.stack.extend([None] * effect.pushes)

            case InstructionKind.PUSH_RET_ADDR:
                if self.frames:
                    self.frames[-1] = operands[0]

                self.stack.extend([None] * effect.pushes)

            case InstructionKind.CALL:
                args = self.pop(effect.pop_count(operands, self.get_param_count))
                self.pop(effect.setup_pops)
                self.add_call(CallType.Local, operands[CALLEE_OPERAND], self.close_frame(), args, returns = True)

            case InstructionKind.SYSCALL:
                # Args stay on the stack - the following POP removes them
                subsystem, cmd, _ = operands
                args = self.peek(effect.read_count(operands))
                self.add_call(CallType.Syscall, (subsystem, cmd), None, args, returns = True)

            case (InstructionKind.POP | InstructionKind.CONDITIONAL_JUMP | InstructionKind.STORE_SLOT
                  | InstructionKind.STORE_DEREF | InstructionKind.STORE_GLOBAL | InstructionKind.DEBUG_LOG):
                self.pop(effect.pop_count(operands))

            # LOAD_DEREF / LOAD_GLOBAL are unverified - no sample script passes them as call args
            case (InstructionKind.LOAD_SLOT | InstructionKind.SLOT_ADDRESS | InstructionKind.LOAD_DEREF
                  | InstructionKind.LOAD_GLOBAL):
                self.stack.append(TrackedValue(ArgType.Variable))

            case InstructionKind.LOAD_REG:
                # A register nothing stored to before it in address order reads as a result of no call
                value = self.registers.get(operands[REGISTER_OPERAND])
                self.stack.append(value if value is not None else TrackedValue(ArgType.CallResult))

            case InstructionKind.STORE_REG:
                value, = self.pop(effect.pops)
                self.registers[operands[REGISTER_OPERAND]] = value

            case InstructionKind.BINARY | InstructionKind.UNARY:
                # Popped top first: the operand evaluated first (its calls made first) is last
                operand_values = self.pop(effect.pops)
                self.stack.append(TrackedValue(ArgType.Expression, calls = nested_calls(reversed(operand_values))))

            case InstructionKind.JUMP | InstructionKind.RETURN:
                pass

            case InstructionKind.CALL_SCRIPT:
                module, func, _ = operands
                args = self.pop(effect.pop_count(operands))
                # Unreachable code (the compile check skips it) or a branch inside the arguments (the tracker reads
                # straight through both arms): what the pop takes is a guess, and so is the record
                if not self.holds_caller_frame(effect.setup_pops):
                    self.warn(f'CALL_SCRIPT {module}.{func}: no caller frame below its arguments in address order - '
                              'its debug record is a guess')

                self.pop(effect.setup_pops)
                self.close_frame()
                self.add_call(CallType.Script, (module, func), None, args, returns = True)

            case InstructionKind.TAIL_CALL:
                # No caller frame precedes it (the table pops no setup): closing one would take an enclosing call's.
                # It never returns here, so register 0 keeps what it held
                module, func, _ = operands
                args = self.pop(effect.pop_count(operands))
                self.add_call(CallType.ScriptNoReturn, (module, func), None, args, returns = False)

            case kind:
                raise NotImplementedError(f'the tracker never tracks {kind.name}')

    def ordered_calls(self) -> list[TrackedCall]:
        """Recorded calls in debug-info record order: statements in evaluation order, each one's call tree in pre-order"""
        ordered = []
        pending = [call for call in reversed(self.calls) if call.parent is None]
        while pending:
            call = pending.pop()
            if call.recorded:
                ordered.append(call)

            pending.extend(reversed(call.children))

        return ordered

    @classmethod
    def from_instructions(cls, instructions: list[Instruction], get_param_count: Callable[[Any], int],
                          call_offsets: dict[TrackedCall, int] | None = None) -> 'CallDebugInfoTracker':
        """A tracker fed decoded instructions in address order; call_offsets, when given, gets each call's instruction
        offset (the parser's pairing needs none)"""
        tracker = cls(get_param_count)
        for inst in instructions:
            payload = ScpValue(inst.operands[0].value) if inst.opcode in PUSH_CONSTANT_OPS else None
            tracker.on_opcode(inst.opcode, [operand.value for operand in inst.operands], payload)
            if call_offsets is not None and len(tracker.calls) > len(call_offsets):
                call_offsets[tracker.calls[-1]] = inst.offset

        return tracker

    @classmethod
    def replay(cls, instructions: list[Instruction], get_param_count: Callable[[Any], int]) -> list[tuple[TrackedCall, int]]:
        """Each recorded call of decoded instructions in record order, with the offset of its call instruction"""
        call_offsets = {}
        tracker = cls.from_instructions(instructions, get_param_count, call_offsets)
        return [(call, call_offsets[call]) for call in tracker.ordered_calls()]

    def holds_caller_frame(self, slots: int) -> bool:
        """The top slots entries are a caller frame's placeholders. Not a test for a local call's setup: in unreachable
        code the parser doesn't rewrite its PUSH_RAWs, so a well-formed setup arrives as two constants"""
        return self.stack[-slots:] == [None] * slots

    def close_frame(self) -> Any:
        """The return label of the innermost call set up, which is made now"""
        return self.frames.pop() if self.frames else None

    def peek(self, count: int) -> list[TrackedValue]:
        """Top count slots, top first; frame slots and underflow (from branches) become Expression placeholders"""
        top = self.stack[max(0, len(self.stack) - count):] if count else []
        values = [value or TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression) for value in reversed(top)]
        return values + [TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression) for _ in range(count - len(values))]

    def pop(self, count: int) -> list[TrackedValue]:
        values = self.peek(count)
        del self.stack[max(0, len(self.stack) - count):]
        return values

    def add_call(self, call_type: ScpFunctionCallDebugInfo.CallType, target: Any, ret_label: Any,
                 args: list[TrackedValue], returns: bool):
        """A call adopts each call nested in its args that has no parent yet (a result read twice adopts once); a
        returning call's result goes to RESULT_REGISTER. Calls compiled without line info (common functions, calls
        before the first DEBUG_SET_LINENO) get no record, even when a recorded call adopts them."""
        call = TrackedCall(call_type, target, ret_label, args, recorded = self.has_line_info)
        for value in args:
            for child in value.calls:
                if child.parent is None:
                    child.parent = call
                    call.children.append(child)

        self.calls.append(call)
        if returns:
            self.registers[RESULT_REGISTER] = TrackedValue(ScpFunctionCallDebugInfoArg.Type.CallResult, calls = (call,))


def read_debug_records(parser: ScpParser, data: bytes) -> list[list[ScpFunctionCallDebugInfo]]:
    """Each function's raw records in table order, read from the file's bytes (the parser keeps converted ones only)"""
    fs = fileio.FileStream().OpenMemory(data)
    return [parser.read_debug_info(fs, entry) for entry in parser.function_entries]


def record_args(data: bytes, record: ScpFunctionCallDebugInfo) -> list[tuple[int, int]]:
    """Each argument's raw type and raw value word, in record order"""
    return [(read_u32(data, offset + ScpValue.WORD.size), read_u32(data, offset)) for offset in record.arg_offsets()]


@dataclass(frozen = True, slots = True)
class RecordView:
    """A record as two files compare it: the callee by name, every argument as stored (a script call's name and a
    syscall's two constants too) by its type and encoded word, a string constant's word by its text"""
    call_type   : ScpFunctionCallDebugInfo.CallType
    callee      : str | None                        # the table name of the record's func_id, None for NO_FUNC_ID
    args        : tuple[tuple[int, int | str], ...]


def record_view(data: bytes, record: ScpFunctionCallDebugInfo, names: list[str]) -> RecordView:
    """record read from data, its func_id resolved through names (its file's table)"""
    if record.func_id == ScpFunctionCallDebugInfo.NO_FUNC_ID:
        callee = None

    elif record.func_id < len(names):
        callee = names[record.func_id]

    else:
        callee = f'#{record.func_id}'

    args = []
    for arg_type, word in record_args(data, record):
        offset = string_offset(word) if arg_type == ScpFunctionCallDebugInfoArg.Type.Constant else None
        args.append((arg_type, read_text(data, offset) if offset is not None else word))

    return RecordView(record.call_type, callee, tuple(args))


def script_call_identity(call_type: ScpFunctionCallDebugInfo.CallType, module: str, func: str,
                         table_index: Callable[[str], int | None]) -> tuple[int, str]:
    """A script call record's func_id and leading name: a tail call into the same script names the bare function and
    its table index (NO_FUNC_ID when the script doesn't define it); any other script call 'module.func' and
    NO_FUNC_ID"""
    if call_type == ScpFunctionCallDebugInfo.CallType.ScriptNoReturn and module == SAME_SCRIPT_MODULE:
        index = table_index(func)
        return (index if index is not None else ScpFunctionCallDebugInfo.NO_FUNC_ID), func

    return ScpFunctionCallDebugInfo.NO_FUNC_ID, f'{module}.{func}'


def record_mismatch(data: bytes, call: TrackedCall, record: ScpFunctionCallDebugInfo,
                    table_index: Callable[[str], int | None]) -> str | None:
    """How record differs from the record call gets (call type, callee, argument count, each argument by its encoded
    word, strings by text), or None; table_index gives a function's table index by name (script_call_identity). A
    local call's record may drop trailing default arguments, so only its first record.arg_count arguments are
    compared."""
    CallType = ScpFunctionCallDebugInfo.CallType
    ArgType = ScpFunctionCallDebugInfoArg.Type
    leading_constants = []
    call_args = call.args

    if call.call_type == CallType.Local:
        expected_func_id = call.target
        call_args = call.args[:record.arg_count]

    elif call.call_type == CallType.Syscall:
        expected_func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID
        leading_constants = [ScpValue(value) for value in call.target]

    else:
        module, func = call.target
        expected_func_id, name = script_call_identity(call.call_type, module.value, func.value, table_index)
        leading_constants = [ScpValue(name)]

    expected = [(ArgType.Constant, value) for value in leading_constants] + [(arg.type, arg.payload) for arg in call_args]

    if record.call_type != call.call_type or record.func_id != expected_func_id or record.arg_count != len(expected):
        return f'record ({record.call_type.name}, func_id 0x{record.func_id:X}, {record.arg_count} args) != call ({call.call_type.name}, func_id 0x{expected_func_id:X}, {len(expected)} args)'

    for i, ((arg_type, payload), (raw_type, raw_value)) in enumerate(zip(expected, record_args(data, record))):
        if raw_type != arg_type:
            return f'arg {i}: type {raw_type} != {arg_type}'

        if arg_type != ArgType.Constant:
            matches = raw_value == ScpValue(ScpFunctionCallDebugInfoArg.NON_CONSTANT_VALUE).to_word()

        elif payload.type == ScpValue.Type.String:
            offset = string_offset(raw_value)
            matches = offset is not None and read_text(data, offset) == payload.value

        else:
            matches = raw_value == payload.to_word()

        if not matches:
            return f'arg {i}: value 0x{raw_value:08X} != {ascii(payload.value if payload is not None else None)}'

    return None
