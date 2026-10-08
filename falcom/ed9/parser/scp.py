from .types_scp import *
from .types_parser import *
from common import fileio
from ..disasm import *
from ..disasm.ed9_optable import *
from ..disasm.stack_effects import CALLEE_OPERAND, POP_SIZE_OPERAND, SLOT_OFFSET_OPERAND
from ..disasm.llil_dsl_comments import GLOBAL_VAR_INDEX_COMMENT, append_comment
from ..writer.metadata import COMMON_LIBRARY_ALL_IMPORT, SCP_WRITER_HELPER_IMPORT
from ..writer.metadata.common_index import COMMON_FUNCTIONS
from ..writer.metadata.signature import function_fingerprint, fingerprint_digest
from common.config import default_encoding
from common.logging import log
from common.utils import PROJECT_ROOT
from ir.llil import WORD_SIZE
from collections import Counter
from enum import Enum, auto
from typing import Any, Callable, NamedTuple
import bisect
import keyword
import pathlib
import struct
import sys

# First lines of every generated script: the generating checkout's root, so it runs without PYTHONPATH
SYS_PATH_SETUP_LINES = ['import sys', f'sys.path.insert(0, {str(PROJECT_ROOT)!r})']


def is_module_name(name: str) -> bool:
    """An import statement can name it: an identifier that isn't a keyword"""
    return name.isidentifier() and not keyword.iskeyword(name)


def shadows_another_module(name: str) -> bool:
    """Pylance imports a stdlib module or one of this checkout's top-level packages of that name instead of a script
    next to the hook (common.dat today). Renaming the checkout's common/ to dc3/ is the planned root-cause fix"""
    return name in sys.stdlib_module_names or (PROJECT_ROOT / name).is_dir() or (PROJECT_ROOT / f'{name}.py').is_file()


def suggested_module_name(stem: str) -> str:
    """A module name close to stem that no other module takes, for the hook template's rename hint: mon5078+ ->
    mon5078_, common -> common_"""
    name = ''.join(char if f'_{char}'.isidentifier() else '_' for char in stem.strip())
    if not name.isidentifier():
        name = f'_{name}'       # a leading digit

    if keyword.iskeyword(name) or shadows_another_module(name):
        name = f'{name}_'

    return name


# Call-site debug-info rebuilding (shared by the parser, ScpWriter, the listing and tools/scp_roundtrip_validator.py)
PUSH_CONSTANT_OPS = opcodes_of(InstructionKind.PUSH_CONST)

SCRIPT_CALL_OPS = opcodes_of(InstructionKind.CALL_SCRIPT, InstructionKind.TAIL_CALL)

# Every pseudo-op encoded as the real PUSH: one ScpValue word after the size byte
PUSH_ENCODED_OPS = (*PUSH_CONSTANT_OPS, *opcodes_of(InstructionKind.PUSH_FUNC_ID, InstructionKind.PUSH_RET_ADDR))

OPCODE_SIZE             = 1     # every opcode is one byte, followed by its operands

# The kinds the simulation handles alike: what they pop is a plain use, and what they push is the instruction itself.
# Kind groups on the simulation's path are tuples, most frequent first: a tuple compares identities in C, a frozenset
# would call Enum's Python __hash__ for every instruction
PLAIN_VALUE_KINDS = (
    InstructionKind.PUSH_CONST, InstructionKind.DEBUG_LINE, InstructionKind.SYSCALL, InstructionKind.LOAD_SLOT,
    InstructionKind.BINARY, InstructionKind.LOAD_REG, InstructionKind.CONDITIONAL_JUMP, InstructionKind.STORE_REG,
    InstructionKind.JUMP, InstructionKind.UNARY, InstructionKind.DEBUG_LOG, InstructionKind.SLOT_ADDRESS,
    InstructionKind.LOAD_DEREF, InstructionKind.STORE_DEREF, InstructionKind.LOAD_GLOBAL, InstructionKind.STORE_GLOBAL,
)

# Calls that take arguments from the stack; SYSCALL leaves them there for a later POP
ARGUMENT_CALL_KINDS = (
    InstructionKind.CALL, InstructionKind.SYSCALL, InstructionKind.CALL_SCRIPT, InstructionKind.TAIL_CALL,
)


@dataclass
class TrackedValue:
    """Simulated eval-stack slot"""
    type        : ScpFunctionCallDebugInfoArg.Type
    payload     : Any = None                # caller data for constants
    call_key    : tuple | None = None       # key of the earliest call nested in this value


@dataclass
class TrackedCall:
    """Call site, ordered like its debug-info record"""
    call_type   : ScpFunctionCallDebugInfo.CallType
    target      : Any                       # CALL operand, (module, func) or (subsystem, cmd)
    ret_label   : Any                       # PUSH_RET_ADDR operand of a local CALL
    args        : list[TrackedValue]        # top of stack first (parameter order)
    key         : tuple


class CallDebugInfoTracker:
    """Rebuilds call-site debug-info records from opcodes fed in address order.

    Records are in source pre-order: an outer call's record comes before calls nested in its args,
    so each call is keyed by where it starts (its frame push) rather than by its CALL instruction.
    """

    def __init__(self, get_param_count: Callable[[Any], int], warn: Callable[[str], None] = log.warning):
        self.get_param_count    = get_param_count
        self.warn               = warn                              # the writer's warn adds the .py line
        self.stack              : list[TrackedValue | None] = []    # None is a call frame slot
        self.frames             : list[list] = []                   # [key, ret_label] of calls not made yet
        self.calls              : list[TrackedCall] = []
        self.counter            = 0
        self.last_call_key      = None
        self.has_line_info      = False

    def on_opcode(self, opcode: int, operands: list | tuple, payload: Any = None):
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
                self.stack.append(TrackedValue(ArgType.Constant, payload = payload))

            case InstructionKind.DEBUG_LINE:
                self.has_line_info = True

            # A call's setup pushes placeholders: its first push opens the call's frame, the return address labels it
            case InstructionKind.PUSH_FUNC_ID | InstructionKind.PUSH_CALLER_FRAME:
                self.frames.append([self.next_key(), None])
                self.stack.extend([None] * effect.pushes)

            case InstructionKind.PUSH_RET_ADDR:
                if self.frames:
                    self.frames[-1][1] = operands[0]

                self.stack.extend([None] * effect.pushes)

            case InstructionKind.CALL:
                args = self.pop(effect.pop_count(operands, self.get_param_count))
                self.pop(effect.setup_pops)
                key, ret_label = self.close_frame()
                self.add_call(CallType.Local, operands[CALLEE_OPERAND], ret_label, args, key)

            case InstructionKind.SYSCALL:
                # Args stay on the stack - the following POP removes them
                subsystem, cmd, _ = operands
                args = self.peek(effect.read_count(operands))
                self.add_call(CallType.Syscall, (subsystem, cmd), None, args, self.key_before_nested(args))

            case (InstructionKind.POP | InstructionKind.STORE_REG | InstructionKind.CONDITIONAL_JUMP
                  | InstructionKind.STORE_SLOT | InstructionKind.STORE_DEREF | InstructionKind.STORE_GLOBAL
                  | InstructionKind.DEBUG_LOG):
                self.pop(effect.pop_count(operands))

            # LOAD_DEREF / LOAD_GLOBAL are unverified - no sample script passes them as call args
            case (InstructionKind.LOAD_SLOT | InstructionKind.SLOT_ADDRESS | InstructionKind.LOAD_DEREF
                  | InstructionKind.LOAD_GLOBAL):
                self.stack.append(TrackedValue(ArgType.Variable))

            case InstructionKind.LOAD_REG:
                self.stack.append(TrackedValue(ArgType.CallResult, call_key = self.last_call_key))

            case InstructionKind.BINARY | InstructionKind.UNARY:
                self.push_expression(self.pop(effect.pops))

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
                key, _ = self.close_frame()
                self.add_call(CallType.Script, (module, func), None, args, key)

            case InstructionKind.TAIL_CALL:
                # No caller frame precedes it (the table pops no setup): closing one would take an enclosing call's
                module, func, _ = operands
                args = self.pop(effect.pop_count(operands))
                self.add_call(CallType.ScriptNoReturn, (module, func), None, args, self.key_before_nested(args))

            case kind:
                raise NotImplementedError(f'the tracker never tracks {kind.name}')

    def ordered_calls(self) -> list[TrackedCall]:
        """Calls in debug-info record order"""
        return sorted(self.calls, key = lambda call: call.key)

    @classmethod
    def replay(cls, instructions: list[Instruction], get_param_count: Callable[[Any], int]) -> list[tuple[TrackedCall, int]]:
        """Feed decoded instructions in address order; each call in record order, with the offset of its call instruction"""
        tracker = cls(get_param_count)
        call_offsets = {}
        for inst in instructions:
            payload = inst.operands[0].value if inst.opcode in PUSH_CONSTANT_OPS else None
            tracker.on_opcode(inst.opcode, [operand.value for operand in inst.operands], payload)
            if len(tracker.calls) > len(call_offsets):
                call_offsets[id(tracker.calls[-1])] = inst.offset

        return [(call, call_offsets[id(call)]) for call in tracker.ordered_calls()]

    def next_key(self) -> tuple:
        key = (self.counter, 0)
        self.counter += 1
        return key

    @classmethod
    def key_before(cls, key: tuple) -> tuple:
        """Sorts right before key and every call nested inside it"""
        return (key[0], key[1] - 1)

    def key_before_nested(self, args: list[TrackedValue]) -> tuple:
        """A call without a frame of its own: keyed before every call nested in its args (source pre-order), else new"""
        nested_keys = [arg.call_key for arg in args if arg.call_key is not None]
        return self.key_before(min(nested_keys)) if nested_keys else self.next_key()

    def holds_caller_frame(self, slots: int) -> bool:
        """The top slots entries are a caller frame's placeholders. Not a test for a local call's setup: in unreachable
        code the parser doesn't rewrite its PUSH_RAWs, so a well-formed setup arrives as two constants"""
        return self.stack[-slots:] == [None] * slots

    def close_frame(self) -> tuple:
        if self.frames:
            key, ret_label = self.frames.pop()
            return key, ret_label

        return self.next_key(), None

    def push_expression(self, operands: list[TrackedValue]):
        keys = [value.call_key for value in operands if value.call_key is not None]
        self.stack.append(TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression, call_key = min(keys) if keys else None))

    def peek(self, count: int) -> list[TrackedValue]:
        """Top count slots, top first; frame slots and underflow (from branches) become Expression placeholders"""
        top = self.stack[max(0, len(self.stack) - count):] if count else []
        values = [value or TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression) for value in reversed(top)]
        return values + [TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression) for _ in range(count - len(values))]

    def pop(self, count: int) -> list[TrackedValue]:
        values = self.peek(count)
        del self.stack[max(0, len(self.stack) - count):]
        return values

    def add_call(self, call_type: ScpFunctionCallDebugInfo.CallType, target: Any, ret_label: Any, args: list[TrackedValue], key: tuple):
        self.last_call_key = key

        # No record for calls compiled without line info (common functions, calls before the first DEBUG_SET_LINENO)
        if self.has_line_info:
            self.calls.append(TrackedCall(call_type, target, ret_label, args, key))


@dataclass(eq = False)
class ParamEntry:
    """Simulated stack entry for a parameter the caller pushed"""
    index : int


@dataclass(eq = False)
class FrameSlot:
    """One of the CALLER_FRAME_SLOTS entries a PUSH_CALLER_FRAME pushes"""
    frame : Instruction
    index : int


class RoleKind(Enum):
    FUNC_ID     = auto()    # PUSH_CURRENT_FUNC_ID of a local call
    RET_ADDR    = auto()    # PUSH_RET_ADDR of a local call
    FRAME       = auto()    # one slot of a script call's caller frame


class Role(NamedTuple):
    """What a call consumes a group of stack entries as"""
    kind    : RoleKind
    target  : int | None = None     # return offset (RET_ADDR, FRAME)
    slot    : int | None = None     # caller frame slot (FRAME)

    def __str__(self) -> str:
        if self.kind == RoleKind.FUNC_ID:
            return 'the function ID'

        if self.kind == RoleKind.RET_ADDR:
            return f'the return address 0x{self.target:X}'

        return f'caller frame slot {self.slot} returning to 0x{self.target:X}'


def format_stack_entry(entry) -> str:
    if isinstance(entry, ParamEntry):
        return f'param_{entry.index}'

    if isinstance(entry, FrameSlot):
        return f'frame_{entry.index}@0x{entry.frame.offset:X}'

    return f'{entry.mnemonic}@0x{entry.offset:X}'


def format_stack(state) -> str:
    return '[' + ', '.join(format_stack_entry(entry) for entry in state) + ']'


def is_push(entry, opcode: int) -> bool:
    return isinstance(entry, Instruction) and entry.opcode == opcode


def encoded_return(entry) -> int | None:
    """The return offset a return-address push encodes, before or after its rewrite"""
    if isinstance(entry, Instruction) and entry.opcode in (ED9Opcode.PUSH_RAW, ED9Opcode.PUSH_RET_ADDR):
        return int(entry.operands[0].value)

    return None


def addressed_slot(inst: Instruction, sp_before: int) -> int:
    """The absolute slot a slot-addressing opcode addresses: its byte offset counts from sp after its pops"""
    return sp_before - inst.descriptor.effect.pops + inst.operands[SLOT_OFFSET_OPERAND].value // WORD_SIZE


def frame_return(entry) -> int | None:
    """The return offset of the caller frame a frame slot belongs to"""
    return entry.frame.operands[0].value if isinstance(entry, FrameSlot) else None


def edge_source(block: BasicBlock) -> int:
    """The instruction an edge out of block is keyed by: its last real instruction, not a synthetic fall-through JMP"""
    return next(inst.offset for inst in reversed(block.instructions) if inst.size != SYNTHETIC_INSTRUCTION_SIZE)


class StackEntryGroups:
    """Union-find over simulated stack entries. Entries that stand at the same position when two edges meet are one
    group: after the join either may be there. A call that consumes a group gives it a role every member must fit.
    Keyed by identity: Instruction is an unhashable dataclass, and equal-looking pushes are still different pushes."""

    def __init__(self):
        self.parent     : dict[int, int] = {}       # id(entry) -> id(parent entry)
        self.members    : dict[int, list] = {}      # id(root) -> entries
        self.roles      : dict[int, Role] = {}      # id(root) -> the role a call consumed the group as

    def find(self, entry) -> int:
        key = id(entry)
        if key not in self.parent:
            self.parent[key] = key
            self.members[key] = [entry]
            return key

        root = key
        while self.parent[root] != root:
            root = self.parent[root]

        while self.parent[key] != root:
            self.parent[key], key = root, self.parent[key]

        return root

    def role_of(self, entry) -> Role | None:
        """The role entry's group was consumed as, without creating a group for it"""
        if id(entry) not in self.parent:
            return None

        return self.roles.get(self.find(entry))

    def union(self, entry, other) -> tuple[Role | None, Role | None]:
        """Merge two groups; returns the roles either was consumed as (none when they already were one group)"""
        root, other_root = self.find(entry), self.find(other)
        if root == other_root:
            return None, None

        self.parent[other_root] = root
        self.members[root].extend(self.members.pop(other_root))
        return self.roles.pop(root, None), self.roles.pop(other_root, None)


class ScpFunctionError(ValueError):
    """A function that doesn't decompile: the function's name and, when one instruction is to blame, its offset and
    mnemonic"""

    def __init__(self, message: str, function: str | None = None, offset: int | None = None,
                 mnemonic: str | None = None):
        super().__init__(message)
        self.function = function
        self.offset = offset
        self.mnemonic = mnemonic
        self.runs_on = None         # the function's instruction that ran on into the next function's code first

    @classmethod
    def describe(cls, function: str, message, inst: Instruction | None = None) -> str:
        """'function: MNEMONIC at 0x..: message', or 'function: message' with no instruction to blame"""
        where = f' {inst.mnemonic} at 0x{inst.offset:X}:' if inst is not None else ''
        return f'{function}:{where} {message}'

    @classmethod
    def at(cls, function: str, message, inst: Instruction | None = None):
        """The error describe() words"""
        if inst is None:
            return cls(cls.describe(function, message), function)

        return cls(cls.describe(function, message, inst), function, inst.offset, inst.mnemonic)


class ScpDisassemblyError(ScpFunctionError):
    """A function that doesn't disassemble"""


@dataclass
class ScpDisassemblerContext(DisassemblerContext):
    """ED9/SCP disassembler context: the simulated stack and the state recorded for every edge"""
    current_func     : 'Function | None' = None     # Function being disassembled
    code_end         : int | None = None            # Where the next function's code starts (None: last function)
    known_code_end   : int | None = None            # Where the code ends, when known: nothing may run or jump past it
    reject_outside_stack : bool = False             # fail on a slot outside the live stack instead of only warning
    quiet            : bool = False                 # no unusual-slot warnings: the caller reports them itself
    runs_on          : Instruction | None = None    # the first instruction that runs on past code_end
    current_inst     : Instruction | None = None    # Instruction being simulated
    stack_simulation : list = field(default_factory = list)                 # Simulated stack of the block being decoded
    edge_states      : dict[int, tuple] = field(default_factory = dict)     # block start -> state; later edges match its height
    recorded_edges   : list = field(default_factory = list)                 # (source offset, target, kind, state) of every edge
    inst_states      : dict[int, tuple] = field(default_factory = dict)     # instruction offset -> the stack before it
    groups           : StackEntryGroups = field(default_factory = StackEntryGroups)
    plain_uses       : dict[int, object] = field(default_factory = dict)    # id -> entry an ordinary consumer used
    declares_call_returns : bool = True             # CALL and CALL_SCRIPT return their own return edges

    def fail(self, message: str, inst: Instruction | None = None):
        raise ScpDisassemblyError.at(self.current_func.name, message, inst)

    def note_run_on(self, inst: Instruction):
        """An instruction that ends at code_end and may continue with the next one runs on into the next function's
        code - a missing RETURN. Past the end of the code that fails, whichever function's code it is in."""
        end = inst.offset + inst.size
        if end not in (self.code_end, self.known_code_end) or not self.falls_through(inst, end):
            return

        if end == self.known_code_end:
            self.fail('runs past the end of the code without RETURN', inst)

        if self.runs_on is None:
            self.runs_on = inst

    @classmethod
    def falls_through(cls, inst: Instruction, end: int) -> bool:
        """inst may continue at end: it doesn't end its block, or one of its branches is the fall-through"""
        desc = inst.descriptor
        return not desc.is_end_block() or any(target.kind == BranchKind.FALSE for target in desc.get_branch_targets(inst, end))

    def record_edge(self, source: int, target: int, state: tuple, kind: BranchKind):
        """The first edge into a block records its state. Every later edge - also one arriving after the block was
        decoded - must match its height; entries that differ become one group."""
        self.recorded_edges.append((source, target, kind, state))
        recorded = self.edge_states.get(target)
        if recorded is None:
            self.edge_states[target] = state
            return

        if len(state) != len(recorded):
            self.fail(
                f'the stack on the edge 0x{source:X} -> 0x{target:X} is {format_stack(state)}, but an earlier edge '
                f'into 0x{target:X} recorded {format_stack(recorded)}',
                self.current_inst,
            )

        for entry, other in zip(recorded, state):
            if entry is not other:
                for role in self.groups.union(entry, other):
                    if role is not None:
                        self.consume(entry, role)

    def consume(self, entry, role: Role):
        """A call consumes entry's group as role: every member must fit it, and setup pushes are rewritten for it"""
        root = self.groups.find(entry)
        current = self.groups.roles.get(root)
        if current is not None and current != role:
            self.fail(f'{format_stack_entry(entry)} is consumed as {role} and as {current}', self.current_inst)

        for member in self.groups.members[root]:
            self.fit(member, role)

        self.groups.roles[root] = role

    def fit(self, member, role: Role):
        """Check that member can be consumed as role; a setup PUSH_RAW becomes its pseudo-instruction"""
        if id(member) in self.plain_uses:
            self.fail(f'expects {role}, but {format_stack_entry(member)} is also used as a plain value',
                      self.current_inst)

        if role.kind == RoleKind.FRAME:
            fits = isinstance(member, FrameSlot) and member.index == role.slot and frame_return(member) == role.target

        elif role.kind == RoleKind.FUNC_ID:
            fits = is_push(member, ED9Opcode.PUSH_CURRENT_FUNC_ID) or (
                is_push(member, ED9Opcode.PUSH_RAW) and member.operands[0].value == self.current_func.index
            )

        else:
            fits = encoded_return(member) == role.target

        if not fits:
            self.fail(f'expects {role}, found {format_stack_entry(member)}', self.current_inst)

        if not is_push(member, ED9Opcode.PUSH_RAW):
            return

        if role.kind == RoleKind.FUNC_ID:
            self.retarget_push(member, ED9Opcode.PUSH_CURRENT_FUNC_ID)

        else:
            self.retarget_push(member, ED9Opcode.PUSH_RET_ADDR, member.operands[0].value)

    def retarget_push(self, push: Instruction, opcode: int, *values):
        """Turn a setup push into a pseudo-instruction with the given operand values"""
        push.opcode = opcode
        push.descriptor = self.instruction_table.get_descriptor(opcode)
        op_descs = OperandDescriptor.from_format_string(push.descriptor.operand_fmt, ED9_FORMAT_TABLE)
        push.operands = [Operand(descriptor = op_desc, value = value) for op_desc, value in zip(op_descs, values)]

    def return_target(self, entry, target: int | None) -> int:
        """The return offset entry encodes, which must lie in this function's code"""
        if target is None:
            self.fail(f'expects a return address, found {format_stack_entry(entry)}', self.current_inst)

        if target == self.code_end:
            self.fail(f'returns to 0x{target:X}, past its end (no RETURN after its return label)', self.current_inst)

        if target < self.current_func.offset or (self.code_end is not None and target >= self.code_end):
            self.fail(f'return offset 0x{target:X} is outside the function', self.current_inst)

        return target

    def enter_block(self, offset: int):
        """Start a block from the state its edges recorded"""
        recorded = self.edge_states.get(offset)
        if recorded is None:
            self.fail(f'block 0x{offset:X} has no recorded stack state')

        self.stack_simulation = list(recorded)

    def pop_entries(self, count: int) -> list:
        """Pop count entries, bottom first, for an ordinary consumer: their values are read or discarded"""
        popped = self.pop_call_setup(count)
        for entry in popped:
            self.use_plainly(entry)

        return popped

    def use_plainly(self, entry):
        """An ordinary consumer reads or discards entry, so no call may consume it as a setup or frame on any path"""
        if isinstance(entry, FrameSlot):
            self.fail(f'discards caller frame slot {entry.index} of 0x{entry.frame.offset:X} without its CALL_SCRIPT',
                      self.current_inst)

        role = self.groups.role_of(entry)
        if role is not None:
            self.fail(f'uses {format_stack_entry(entry)} as a plain value, but a call consumes it as {role}',
                      self.current_inst)

        self.plain_uses[id(entry)] = entry

    def pop_count(self, inst: Instruction) -> int:
        """How many entries inst pops above a call's setup; a local CALL's are its callee's parameters"""
        effect = inst.descriptor.effect
        if isinstance(effect.pops, int):            # most kinds: no operand list to build
            return effect.pops

        return effect.pop_count([operand.value for operand in inst.operands], self.get_func_argc)

    def call_argc(self, inst: Instruction) -> int:
        """How many arguments a call takes from the stack; SYSCALL reads them in place"""
        effect = inst.descriptor.effect
        if effect.reads:
            return effect.read_count([operand.value for operand in inst.operands])

        return self.pop_count(inst)

    def pop_call_setup(self, count: int) -> list:
        """Pop count entries, bottom first, for the call that consumes them as its setup or caller frame"""
        stack = self.stack_simulation
        if count > len(stack):
            self.fail(f'pops {count} entries, the stack has {len(stack)}: {format_stack(stack)}', self.current_inst)

        popped = stack[len(stack) - count:]
        del stack[len(stack) - count:]
        return popped

    def write_slot(self, position: int):
        """POP_TO's in-place write: the written position now holds the current instruction's value and its old value is
        discarded (at or above sp: a dead store)"""
        stack = self.stack_simulation
        if position < 0:
            self.fail('writes below the stack', self.current_inst)

        if position < len(stack):
            self.use_plainly(stack[position])
            stack[position] = self.current_inst

    def stack_layout(self, entry_block: BasicBlock) -> StackLayout:
        """What the stack holds at each point of the disassembled function. What may stand in each slot at a block start
        is solved over every recorded edge, so a value reaching a slot only through a later join doesn't count for an
        earlier read; a POP_TO stands for the value it overwrote, so a reassigned parameter stays the parameter. Each
        call numbers the pushes that may stand in its argument slots, the same way (arg1 = the last push). An unusual
        slot (SlotRef.unusual) is logged as a warning. Raises only on a broken parser invariant: every reachable
        instruction has a recorded state."""
        blocks = {
            block.offset: [inst for inst in block.instructions if inst.size != SYNTHETIC_INSTRUCTION_SIZE]
            for block in Formatter.collect_blocks(entry_block)
        }
        starts = {start: self.inst_states[insts[0].offset] for start, insts in blocks.items()}
        # A recorded edge leaves from its block's last real instruction (require_recorded_edges checked it)
        source_blocks = {insts[-1].offset: start for start, insts in blocks.items()}

        # Block start -> slot -> the entries that may stand there, by id (Instruction is unhashable)
        held = {start: [{} for _ in state] for start, state in starts.items()}
        held[entry_block.offset] = [{id(entry): entry} for entry in starts[entry_block.offset]]

        def held_at(block: int, state: tuple, slot: int) -> dict:
            """The entries that may stand in slot where block's stack is state"""
            while True:
                entry = state[slot]
                if slot < len(starts[block]) and entry is starts[block][slot]:
                    return held[block][slot]

                if not (isinstance(entry, Instruction) and entry.opcode == ED9Opcode.POP_TO):
                    return {id(entry): entry}

                state = self.inst_states[entry.offset]

        changed = True
        while changed:
            changed = False
            for source, target, _, state in self.recorded_edges:
                for slot, target_entries in enumerate(held[target]):
                    count = len(target_entries)
                    target_entries.update(held_at(source_blocks[source], state, slot))
                    changed = changed or len(target_entries) != count

        layout = StackLayout()
        arguments = {}      # push offset -> (call offset, argN) of each call it may be an argument of
        for start, insts in blocks.items():
            for inst in insts:
                state = self.inst_states[inst.offset]
                layout.sp_before[inst.offset] = len(state)
                effect = inst.descriptor.effect
                if effect.addresses_slot:
                    slot = addressed_slot(inst, len(state))
                    live = 0 <= slot < len(state) - effect.pops
                    entries = held_at(start, state, slot) if live else {}
                    ref = self.slot_ref(slot, entries, layout.local_slots)
                    if not live and self.reject_outside_stack:
                        self.fail(f'addresses {ref}', inst)

                    if ref.unusual and not self.quiet:
                        log.warning(f'{self.current_func.name}: {inst.mnemonic} at 0x{inst.offset:X} addresses {ref}')

                    layout.slot_refs[inst.offset] = ref

                if inst.descriptor.kind in ARGUMENT_CALL_KINDS:
                    for slot in range(max(len(state) - self.call_argc(inst), 0), len(state)):
                        for entry in held_at(start, state, slot).values():
                            # A parameter or caller-frame entry has no line of its own
                            if isinstance(entry, Instruction):
                                arguments.setdefault(entry.offset, []).append((inst.offset, len(state) - slot))

        layout.arg_numbers = {offset: tuple(number for _, number in sorted(calls)) for offset, calls in arguments.items()}
        return layout

    def slot_ref(self, slot: int, entries: dict, local_slots: dict[int, int]) -> SlotRef:
        """What slot may hold, from the entries that may stand there (by id); each local's instruction goes into
        local_slots"""
        params, local, caller_frame, call_setup = [], False, False, False
        for entry in entries.values():
            if isinstance(entry, ParamEntry):
                params.append(len(self.current_func.params) - entry.index)

            elif isinstance(entry, FrameSlot):
                caller_frame = True

            elif entry.opcode in (ED9Opcode.PUSH_CURRENT_FUNC_ID, ED9Opcode.PUSH_RET_ADDR):
                call_setup = True

            else:
                local = True
                local_slots[entry.offset] = slot

        return SlotRef(slot, tuple(sorted(params)), local, caller_frame, call_setup)


class ScpParser(StrictBase):
    # Keep data only needed for a byte-exact round trip: zero-arg debug records and the explicit
    # arg count of each local CALL (debug_argc). Source function order is always kept - it's a free
    # reordering of already-parsed data, not extra fidelity data, so it isn't gated by this flag.
    round_trip      : bool = True

    # Decode code no branch reaches (e.g. a JMP right after RETURN) so the .py keeps it for a byte-exact round trip
    keep_unreachable_code : bool = True

    # The compile check's stricter reading of bytes it just compiled: a slot outside the live stack fails instead of
    # only warning, and no code may run or jump past the known end of the code
    reject_outside_stack : bool = False
    known_code_end  : int | None = None

    fs              : fileio.FileStream
    name            : str
    header          : ScpHeader
    function_entries: list[ScpFunctionEntry]
    functions       : list[Function]
    global_vars     : list[GlobalVar]
    function_map    : dict[str, Function]

    def __init__(self, fs: fileio.FileStream, name: str = ''):
        self.fs = fs
        self.name = name

    @classmethod
    def load(
        cls,
        path: pathlib.Path,
        *,
        round_trip: bool,
        keep_unreachable_code: bool,
        filter_func: Callable[[Function], bool] | None = None,
    ) -> tuple['ScpParser', list[Function]]:
        """Read path, parse, and disassemble every function - the setup every caller (scena2py.py,
        the common-function generator, the round-trip validator, tests) otherwise repeats by hand.
        The parser stays fully usable afterward (get_instructions, get_func_name_from_func_id, etc.
        are all in-memory)."""
        return cls.load_bytes(path.read_bytes(), path.name, round_trip = round_trip,
                              keep_unreachable_code = keep_unreachable_code, filter_func = filter_func)

    @classmethod
    def load_bytes(
        cls,
        data: bytes,
        name: str,
        *,
        round_trip: bool,
        keep_unreachable_code: bool,
        filter_func: Callable[[Function], bool] | None = None,
        quiet: bool = False,
        reject_outside_stack: bool = False,
        known_code_end: int | None = None,
    ) -> tuple['ScpParser', list[Function]]:
        """load() for a script already in memory, named name; quiet drops the per-function progress and error lines
        and the unusual-slot warnings, for a caller that reports them itself (the compile check).
        reject_outside_stack and known_code_end are the compile check's (see the class attributes)."""
        with fileio.FileStream(data, encoding = default_encoding()) as fs:
            parser = cls(fs, name)
            parser.round_trip = round_trip
            parser.keep_unreachable_code = keep_unreachable_code
            parser.reject_outside_stack = reject_outside_stack
            parser.known_code_end = known_code_end
            parser.parse()
            functions = parser.disasm_all_functions(filter_func = filter_func, quiet = quiet)

        return parser, functions

    def get_func_by_name(self, name: str) -> Function:
        return self.function_map[name]

    def get_func_name_from_func_id(self, func_id: int) -> str:
        if func_id >= len(self.functions):
            raise ValueError(f'func_id out of range: {func_id} >= {len(self.functions)}')

        return self.functions[func_id].name

    def get_global_name_from_index(self, index: int) -> str | None:
        if 0 <= index < len(self.global_vars):
            return self.global_vars[index].name

        return None

    def get_func_argc(self, func_id: int) -> int:
        if func_id >= len(self.functions):
            raise ValueError(f'func_id out of range: {func_id} >= {len(self.functions)}')

        return len(self.functions[func_id].params)

    def parse(self):
        self._read_header()

    def _read_header(self):
        fs = self.fs
        self.header = ScpHeader(fs = fs)

        self.function_entries   = self._read_function_entries(fs)
        self.functions          = self._read_functions(fs, self.function_entries)
        self.global_vars        = self._read_global_vars(fs)

        self.function_map = {func.name: func for func in self.functions}

    def _read_function_entries(self, fs: fileio.FileStream):
        return [ScpFunctionEntry(fs = fs) for _ in range(self.header.function_count)]

    def _read_functions(self, fs: fileio.FileStream, func_entries: list[ScpFunctionEntry]) -> list[Function]:
        functions: list[Function] = []

        # load function

        for index, entry in enumerate(func_entries):
            func = Function()

            func.index = index
            func.is_common_func = entry.is_common_func == 1
            func.offset = entry.offset

            func_name = ScpValue().from_value(entry.name_offset, fs = fs)
            func.name = func_name.value

            fs.Position = entry.param_flags_offset
            param_flags = [ScpParamFlags(fs = fs) for _ in range(entry.param_count)]

            fs.Position = entry.default_params_offset
            default_params = [ScpValue(fs = fs) for _ in range(entry.default_params_count)]
            if len(default_params) > len(param_flags):
                raise ValueError(f'default_params count is greater than param_flags count: {len(default_params)} > {len(param_flags)}')

            while len(default_params) < len(param_flags):
                default_params.insert(0, None)

            for i in range(entry.param_count):
                param = FunctionParam(type = param_flags[i], default_value = default_params[i])
                default = param.default_value
                if default is not None and (default.type == ScpValue.Type.String) != param.type.takes_string():
                    log.warning(f'{func.name}: parameter {i + 1} is {param.type.get_python_type()} but defaults to '
                                f'{default.value!r}: the writer rejects that, so compiling the .py will fail')

                func.params.append(param)

            # func.params.reverse()

            functions.append(func)

        # init debug info

        for i, func in enumerate(functions):
            entry = func_entries[i]
            fs.Position = entry.debug_info_offset
            debug_info_list = self.read_debug_info(fs, entry)

            for dbg_info in debug_info_list:
                # round_trip keeps zero-arg records so records line up 1:1 with call sites
                if dbg_info.arg_count == 0 and not self.round_trip:
                    continue

                info = FunctionCallDebugInfo()
                info.call_type = dbg_info.call_type

                if dbg_info.func_id != 0xFFFFFFFF:
                    if dbg_info.func_id >= len(functions):
                        raise ValueError(f'debug info func_id out of range: {dbg_info.func_id} >= {len(functions)}')

                    info.func_name = functions[dbg_info.func_id].name

                else:
                    info.func_name = f'{dbg_info.call_type}'

                fs.Position = dbg_info.info_offset
                for _ in range(dbg_info.arg_count):
                    arg_value = ScpValue(fs = fs)
                    arg_type = fs.ReadULong()

                    info.args.append(FunctionCallDebugInfo.ArgInfo(arg_type, arg_value))

                func.debug_info.append(info)

        return functions

    def read_debug_info(self, fs: fileio.FileStream, func_entry: ScpFunctionEntry) -> list[ScpFunctionCallDebugInfo]:
        debug_info_list = []

        if func_entry.debug_info_count == 0:
            return debug_info_list

        fs.Position = func_entry.debug_info_offset
        for _ in range(func_entry.debug_info_count):
            dbg_info = ScpFunctionCallDebugInfo(fs = fs)
            debug_info_list.append(dbg_info)

        return debug_info_list

    def _read_global_vars(self, fs: fileio.FileStream) -> list[GlobalVar]:
        hdr = self.header
        fs.Position = hdr.global_var_offset

        global_vars: list[GlobalVar] = []

        for i in range(hdr.global_var_count):
            gvar_info = ScpGlobalVar(fs = fs)

            global_var = GlobalVar(
                index = i,
                name = gvar_info.name,
                type = gvar_info.type,
            )

            global_vars.append(global_var)

        return global_vars


    # disassemble

    def on_disasm_function(self, context: ScpDisassemblerContext, offset: int, name: str):
        """The entry block starts with the caller's parameters"""
        if context.known_code_end is not None and offset >= context.known_code_end:
            context.fail('has no code before the end of the code (no RETURN)')

        context.edge_states[offset] = tuple(ParamEntry(index) for index in range(len(context.current_func.params)))

    def on_block_start(self, context: ScpDisassemblerContext, offset: int):
        """Start the block from its recorded state"""
        context.enter_block(offset)

    def on_pre_add_branch(self, context: ScpDisassemblerContext, target: BranchTarget):
        """Record the state the edge carries into its target (a branch or a fall-through)"""
        if context.known_code_end is not None and target.offset >= context.known_code_end:
            context.fail(f'jumps to 0x{target.offset:X}, past the end of the code (no RETURN after its label)',
                         context.current_inst)

        context.record_edge(context.current_inst.offset, target.offset, tuple(context.stack_simulation), target.kind)

    def on_block_split(self, context: ScpDisassemblerContext, source_offset: int, split_offset: int):
        """The head falls through into the tail with the state the tail's first instruction was simulated with"""
        context.record_edge(source_offset, split_offset, context.inst_states[split_offset], BranchKind.UNCONDITIONAL)

    def on_instruction_decoded(self, context: ScpDisassemblerContext, inst: Instruction, block: BasicBlock) -> list[BranchTarget]:
        """Simulate the instruction's stack effect; a call returns its return edge"""
        stack = context.stack_simulation
        context.current_inst = inst
        context.inst_states[inst.offset] = tuple(stack)
        context.note_run_on(inst)
        effect = inst.descriptor.effect

        match inst.descriptor.kind:
            case kind if kind in PLAIN_VALUE_KINDS:
                if effect.pops:
                    context.pop_entries(context.pop_count(inst))

                if effect.pushes:
                    stack.append(inst)

            case InstructionKind.RETURN:
                if stack:
                    context.fail(f'the stack is not empty: {format_stack(stack)}', inst)

            case InstructionKind.POP:
                size = inst.operands[POP_SIZE_OPERAND].value
                if size % WORD_SIZE:
                    context.fail(f'pops {size} bytes, not whole slots', inst)

                context.pop_entries(context.pop_count(inst))

            case InstructionKind.STORE_SLOT:
                slot = addressed_slot(inst, len(stack))
                context.pop_entries(effect.pops)
                context.write_slot(slot)

            case InstructionKind.PUSH_CALLER_FRAME:
                stack.extend(FrameSlot(inst, index) for index in range(effect.pushes))

            case InstructionKind.CALL:
                return self.simulate_call(context, inst)

            case InstructionKind.CALL_SCRIPT:
                return self.simulate_call_script(context, inst)

            case InstructionKind.TAIL_CALL:
                self.simulate_tail_call(context, inst)

            # PUSH_FUNC_ID / PUSH_RET_ADDR: the parser makes them itself, from a setup's PUSH_RAW
            case kind:
                raise NotImplementedError(f'the parser never simulates {kind.name}')

        return []

    def simulate_call(self, context: ScpDisassemblerContext, inst: Instruction) -> list[BranchTarget]:
        """PUSH(func_id) PUSH(ret_addr) args... CALL: the callee pops the args and both setup pushes and returns to
        the pushed return address. The setup pushes become PUSH_CURRENT_FUNC_ID / PUSH_RET_ADDR. Checked in order: the
        args, the setup's height, the return offset, the function ID, then the return address's group."""
        context.pop_entries(context.call_argc(inst))
        func_id, ret_addr = context.pop_call_setup(inst.descriptor.effect.setup_pops)
        target = context.return_target(ret_addr, encoded_return(ret_addr))
        context.consume(func_id, Role(RoleKind.FUNC_ID))
        context.consume(ret_addr, Role(RoleKind.RET_ADDR, target))
        return [BranchTarget.unconditional(target)]

    def simulate_call_script(self, context: ScpDisassemblerContext, inst: Instruction) -> list[BranchTarget]:
        """PUSH_CALLER_FRAME(ret) args... CALL_SCRIPT: the callee pops the args and the caller frame, and returns to
        the frame's return address. Checked in order: the args, the frame's height, its return address, each slot."""
        context.pop_entries(context.call_argc(inst))
        frame = context.pop_call_setup(inst.descriptor.effect.setup_pops)
        target = context.return_target(frame[0], frame_return(frame[0]))
        for slot, entry in enumerate(frame):
            context.consume(entry, Role(RoleKind.FRAME, target, slot))

        return [BranchTarget.unconditional(target)]

    def simulate_tail_call(self, context: ScpDisassemblerContext, inst: Instruction):
        """CALL_SCRIPT_NO_RETURN: the callee takes over the args, which must be all that is left on the stack"""
        context.pop_entries(context.call_argc(inst))
        if context.stack_simulation:
            context.fail(f'leaves {format_stack(context.stack_simulation)} below its args', inst)

    @classmethod
    def require_recorded_edges(cls, func: Function, context: ScpDisassemblerContext):
        """The CFG's edges must be exactly the recorded ones, kind and count included"""
        cfg_edges = Counter()
        for block in Formatter.collect_blocks(func.entry_block):
            for succ in block.succs:
                kinds = [
                    kind for kind, succs in ((BranchKind.TRUE, block.true_succs), (BranchKind.FALSE, block.false_succs))
                    if succ in succs
                ]
                for kind in kinds or [BranchKind.UNCONDITIONAL]:
                    cfg_edges[(edge_source(block), succ.offset, kind)] += 1

        recorded = Counter((source, target, kind) for source, target, kind, _ in context.recorded_edges)
        if cfg_edges != recorded:
            missing = sorted((hex(src), hex(target), kind.name) for src, target, kind in cfg_edges - recorded)
            extra = sorted((hex(src), hex(target), kind.name) for src, target, kind in recorded - cfg_edges)
            context.fail(f'CFG edges without a recorded stack state {missing}, recorded edges not in the CFG {extra}')

    def require_code_before_strings(self, functions: list[Function]):
        """Every reachable instruction must end before the string pool, whose start is known only from references: the
        function names and the strings decoded code references. Unreachable references count only when
        keep_unreachable_code decoded them; undecoded or filtered-out code does not tighten the bound."""
        code_end = self.get_code_end(functions)
        if self.keep_unreachable_code:
            unreachable = [inst for func in functions for inst in self.unreachable_instructions(func)]
            code_end = min([code_end, *self.get_string_refs(unreachable)])

        for func in functions:
            for inst in self.get_instructions(func):
                if inst.offset + inst.size > code_end:
                    raise ScpDisassemblyError(
                        f'{func.name}: {inst.mnemonic} at 0x{inst.offset:X} runs past the end of the code '
                        f'(0x{code_end:X})', func.name, inst.offset
                    )

    def require_disjoint_instructions(self, functions: list[Function]):
        """Functions may share code - the same instruction at the same offset - but no instruction may partially overlap
        another, and no function may start inside one. Within a function the Disassembler already checks this."""
        sizes = {}
        for func in functions:
            for inst in self.get_instructions(func):
                size = sizes.setdefault(inst.offset, inst.size)
                if size != inst.size:
                    raise ScpDisassemblyError(
                        f'{func.name}: {inst.mnemonic} at 0x{inst.offset:X} decodes differently in another function',
                        func.name, inst.offset
                    )

        offsets = sorted(sizes)
        for offset, next_offset in zip(offsets, offsets[1:]):
            if offset + sizes[offset] > next_offset:
                raise ScpDisassemblyError(
                    f'The instruction at 0x{offset:X} overlaps the instruction at 0x{next_offset:X}', offset = next_offset
                )

        for func in self.functions:
            index = bisect.bisect_right(offsets, func.offset) - 1
            if index >= 0 and offsets[index] < func.offset < offsets[index] + sizes[offsets[index]]:
                raise ScpDisassemblyError(
                    f'{func.name} starts at 0x{func.offset:X}, inside the instruction at 0x{offsets[index]:X}',
                    func.name, offsets[index]
                )

    def disasm_context(self, func: Function, code_end: int | None, quiet: bool = False) -> ScpDisassemblerContext:
        """A fresh context for disassembling func, whose code ends at code_end"""
        return ScpDisassemblerContext(
            get_func_argc           = self.get_func_argc,
            on_disasm_function      = self.on_disasm_function,
            on_block_start          = self.on_block_start,
            on_instruction_decoded  = self.on_instruction_decoded,
            on_pre_add_branch       = self.on_pre_add_branch,
            on_block_split          = self.on_block_split,
            create_fallthrough_jump = ed9_create_fallthrough_jump,
            current_func            = func,
            code_end                = code_end,
            known_code_end          = self.known_code_end,
            reject_outside_stack    = self.reject_outside_stack,
            quiet                   = quiet,
        )

    def disasm_all_functions(self, filter_func = None, quiet: bool = False) -> list[Function]:
        """Disassemble all functions in the SCP file; quiet drops the per-function progress and error lines and the
        unusual-slot warnings. A function's failure is raised as a ScpDisassemblyError naming it."""
        disassembled_functions = []
        starts = sorted({func.offset for func in self.functions})

        for func in self.functions:
            # Apply filter if provided
            if filter_func and not filter_func(func):
                continue

            if not quiet:
                log.info(f'Disassembling {func.name} @ 0x{func.offset:08X}')

            # Create new context for each function; its code ends where the next function starts, the last one's
            # where the code ends when that is known
            next_start = bisect.bisect_right(starts, func.offset)
            context = self.disasm_context(func, starts[next_start] if next_start < len(starts) else self.known_code_end,
                                          quiet)

            disasm = Disassembler(ED9_INSTRUCTION_TABLE, context)
            try:
                func.entry_block = disasm.disasm_function(self.fs, offset = func.offset, name = func.name)
                self.require_recorded_edges(func, context)
                func.stack_layout = context.stack_layout(func.entry_block)
                func.runs_on = context.runs_on
                disassembled_functions.append(func)
            except Exception as e:
                if not quiet:
                    log.error(f'Error disassembling {func.name} @ 0x{func.offset:08X}: {e}')

                error = e if isinstance(e, ScpDisassemblyError) else ScpDisassemblyError.at(func.name, e)
                error.runs_on = context.runs_on
                if error is e:
                    raise

                raise error from e

            if self.round_trip:
                self.pair_call_debug_info(func)

        self.require_disjoint_instructions(disassembled_functions)

        if self.keep_unreachable_code:
            self.find_unreachable_code(disassembled_functions, has_all_functions = filter_func is None)

        self.require_code_before_strings(disassembled_functions)

        # The table is sorted by name, but code is laid out in source order
        disassembled_functions.sort(key = lambda func: func.offset)

        return disassembled_functions

    def get_instructions(self, func: Function) -> list[Instruction]:
        """Reachable instructions of a disassembled function in offset order"""
        return Formatter.reachable_instructions(func.entry_block)

    def code_instructions(self, func: Function) -> list[Instruction]:
        """Reachable instructions and the decoded unreachable code (keep_unreachable_code), in offset order"""
        return sorted(self.get_instructions(func) + self.unreachable_instructions(func), key = lambda inst: inst.offset)

    @classmethod
    def unreachable_instructions(cls, func: Function) -> list[Instruction]:
        """The decoded unreachable code (keep_unreachable_code), block by block"""
        return [inst for block in func.unreachable_blocks for inst in block.instructions]

    def pair_call_debug_info(self, func: Function):
        """Recover each local CALL's explicit arg count - its debug record drops trailing default args"""
        tracker = CallDebugInfoTracker(get_param_count = self.get_func_argc)
        for inst in self.get_instructions(func):
            tracker.on_opcode(inst.opcode, [operand.value for operand in inst.operands])

        calls = tracker.ordered_calls()
        if len(calls) != len(func.debug_info):
            log.warning(f'{func.name}: {len(calls)} call sites but {len(func.debug_info)} debug records, debug_argc not recovered')
            return

        for call, info in zip(calls, func.debug_info):
            if call.call_type != ScpFunctionCallDebugInfo.CallType.Local or call.ret_label is None:
                continue

            if len(info.args) != len(call.args):
                func.call_debug_argc[f'loc_{call.ret_label:X}'] = len(info.args)

    def find_unreachable_code(self, functions: list[Function], has_all_functions: bool):
        """Linearly decode the bytes no branch reaches (between reachable instructions and up to the next function) into func.unreachable_blocks"""
        if not functions:
            return

        starts = sorted(func.offset for func in self.functions)
        next_starts = dict(zip(starts, starts[1:]))
        code_end = self.get_code_end(functions)

        # Code order, so strings used by earlier unreachable code can lower code_end before the last function's tail
        for func in sorted(functions, key = lambda f: f.offset):
            instructions = self.get_instructions(func)
            blocks = []
            cursor = func.offset

            for inst in instructions:
                if inst.offset > cursor:
                    blocks.append(self._decode_unreachable_block(func, cursor, inst.offset))

                cursor = max(cursor, inst.offset + inst.size)

            blocks = [block for block in blocks if block is not None]
            code_end = min([code_end, *self.get_string_refs([inst for block in blocks for inst in block.instructions])])

            # The last function in code order runs up to the string pool, only known when every function's strings were seen
            end = next_starts.get(func.offset, code_end if has_all_functions else None)
            if end is not None and cursor < end:
                tail = self._decode_unreachable_block(func, cursor, end)
                if tail is not None:
                    blocks.append(tail)
                    code_end = min([code_end, *self.get_string_refs(tail.instructions)])

            func.unreachable_blocks = self._prune_unreachable_blocks(func, instructions, blocks)

    def get_code_end(self, functions: list[Function]) -> int:
        """Where the string pool starts - it holds the code strings first, then the function names"""
        names = [self.get_string_offset(entry.name_offset) for entry in self.function_entries]
        code_strings = self.get_string_refs([inst for func in functions for inst in self.get_instructions(func)])
        return min([offset for offset in names if offset is not None] + code_strings)

    def get_string_refs(self, instructions: list[Instruction]) -> list[int]:
        """String pool offsets referenced by PUSH_STR and CALL_SCRIPT operands"""
        refs = []
        with self.fs.PositionSaver:
            for position in self.string_operand_positions(instructions):
                self.fs.Position = position
                offset = self.get_string_offset(self.fs.ReadULong())
                if offset is not None:
                    refs.append(offset)

        return refs

    @classmethod
    def string_operand_positions(cls, instructions: list[Instruction]) -> list[int]:
        """File positions of the operand words that may reference a string: PUSH_STR's value, CALL_SCRIPT's module and func"""
        return [position for inst in instructions if inst.opcode == ED9Opcode.PUSH_STR or inst.opcode in SCRIPT_CALL_OPS
                for position in cls.value_positions(inst)]

    @classmethod
    def value_positions(cls, inst: Instruction) -> list[int]:
        """File positions of an instruction's ScpValue words: a push's value, CALL_SCRIPT's module and func"""
        if inst.opcode in PUSH_ENCODED_OPS:
            return [inst.offset + inst.size - WORD_SIZE]                            # PUSH ends with its ScpValue

        if inst.opcode in SCRIPT_CALL_OPS:
            return [inst.offset + OPCODE_SIZE, inst.offset + OPCODE_SIZE + WORD_SIZE]  # module, func

        return []

    @classmethod
    def get_string_offset(cls, raw_value: int) -> int | None:
        """String pool offset of a raw ScpValue, None when it isn't a String"""
        if raw_value >> ScpValue.TYPE_SHIFT != ScpValue.Type.String:
            return None

        return raw_value & ScpValue.PAYLOAD_MASK

    def _decode_unreachable_block(self, func: Function, start: int, end: int) -> BasicBlock | None:
        """Linearly decode [start, end), or None (with a warning) when the bytes aren't whole instructions"""
        block = BasicBlock(start_offset = start, end_offset = end)
        fs = self.fs

        with fs.PositionSaver:
            fs.Position = start

            try:
                while fs.Position < end:
                    block.instructions.append(ED9_INSTRUCTION_TABLE.decode_instruction(fs, fs.Position))

            except (ValueError, struct.error) as e:
                log.warning(f'{func.name}: unreachable code 0x{start:X}..0x{end:X} not kept, decode failed: {e}')
                return None

            if fs.Position != end:
                log.warning(f'{func.name}: unreachable code 0x{start:X}..0x{end:X} not kept, last instruction ends at 0x{fs.Position:X}')
                return None

        return block

    @classmethod
    def _prune_unreachable_blocks(cls, func: Function, instructions: list[Instruction], blocks: list[BasicBlock]) -> list[BasicBlock]:
        """Drop unreachable blocks that branch to an offset with no kept instruction - their label would never be emitted"""
        reachable_offsets = {inst.offset for inst in instructions}

        while True:
            offsets = reachable_offsets | {inst.offset for block in blocks for inst in block.instructions}
            dropped_ids = {id(block) for block in blocks if any(target not in offsets for target in Formatter.branch_targets(block))}
            if not dropped_ids:
                return blocks

            for block in blocks:
                if id(block) in dropped_ids:
                    log.warning(f'{func.name}: unreachable code at 0x{block.offset:X} not kept, it branches to an offset with no instruction')

            blocks = [block for block in blocks if id(block) not in dropped_ids]

    def format_function(self, func: Function, comments: CommentOptions = CommentOptions()) -> list[str]:
        """Format a disassembled function"""
        formatter_context = FormatterContext(
            get_func_name_from_func_id  = self.get_func_name_from_func_id,
            get_global_name_from_index  = self.get_global_name_from_index,
            comments                    = comments,
        )
        formatter = Formatter(formatter_context)
        return formatter.format_function(func)

    def gen_python_script(self, functions: list[Function], *, preamble: list[str] = (), comments: CommentOptions = CommentOptions()) -> str:
        """Full generated .py text: header (incl. shared-library imports/manifest), an optional
        preamble (e.g. scena2py.py's common-functions-omitted warning), every function this script
        must still define itself, then the footer. match_library_functions runs exactly once here
        and its result is threaded through the header and the inline-function filter, so the two
        can never disagree about which functions got imported - see write_python_dsl/
        decompile_to_python, which used to compute it separately in each half."""
        matched = self.match_library_functions(functions)

        lines = self.gen_python_header(functions, matched = matched)
        lines.extend(preamble)

        for func in self.get_inline_functions(functions, matched = matched):
            lines.extend(self.format_function(func, comments))
            lines.append('')

        lines.extend(self.gen_python_footer())
        return '\n'.join(lines) + '\n'

    def gen_python_header(self, functions: list[Function] | None = None, *, matched: dict[str, str] | None = None) -> list[str]:
        """Generate Python header lines for output script execution.

        functions, when given, are this script's disassembled functions in code order - used to
        emit the @scena.CommonImports() manifest (see match_library_functions). Leave it as None
        when there's no function list to give (e.g. a caller building just the header on its own);
        matched lets gen_python_script pass in an already-computed match set instead of this
        recomputing it.

        The whole-library import is unconditional - every script gets it, regardless of fidelity
        mode or whether it has a function list at all, so a human editing the script has every
        common function in scope for CALL()/autocomplete even when adding one this script never
        originally used. Unlike the hook import above it, this one needs no try/except of its own:
        common_all.py is a tracked project file (always present) whose own internal imports of the
        gitignored, locally-generated common/ package are what can fail on a fresh checkout - it
        catches that itself and logs a hint to run the generator, so importing common_all here
        always succeeds even when the library behind it doesn't exist yet.
        """
        lines = [*SYS_PATH_SETUP_LINES]
        lines += f'''\
{SCP_WRITER_HELPER_IMPORT}
{self.gen_hook_import()}

{COMMON_LIBRARY_ALL_IMPORT}

scena = create_scp_writer('{self.name}')

'''.splitlines()

        if self.global_vars:
            indent = default_indent()
            lines.append('@scena.GlobalVars()')
            lines.append('def globalvars():')
            for var in self.global_vars:
                declaration = f'GLOBAL_VAR({quote_string(var.name)}, {var.type})'
                lines.append(indent + append_comment(declaration, [f'{GLOBAL_VAR_INDEX_COMMENT} {var.index}']))
            lines.append('')

        if functions is not None:
            lines.extend(self.gen_common_imports(functions, matched = matched))

        return lines

    def match_library_functions(self, functions: list[Function]) -> dict[str, str]:
        """This script's common functions whose body+signature exactly match the shared library's
        canonical variant (falcom/ed9/writer/metadata/common_index.py) - name -> library module key.

        Only meaningful in the everyday (non-fidelity) mode: a byte-exact recompile needs every
        function inline and every byte of it kept, so this always returns {} when self.round_trip
        or self.keep_unreachable_code is True - the library was generated with unreachable code
        dropped, so importing it under keep_unreachable_code=True would silently drop a script's
        own dead bytes even though that flag asked to keep them. A common function whose fingerprint
        diverges from the library (different body, signature, or subsystem) is left out here and
        stays inline as an ordinary @scena.LLILCommonCode() definition, same as a non-common one.

        Also returns {} if the library package itself isn't actually generated on disk yet (fresh
        checkout, generator never run) - common_index.py is tracked and would otherwise claim
        matches that don't actually exist, leaving a matched name referenced by the
        @scena.CommonImports() manifest but never defined anywhere.
        """
        if self.round_trip or self.keep_unreachable_code:
            return {}

        # Deferred import, not module-level (CLAUDE.md rule 2's circular-dependency exception):
        # common_all pulls in the generated library modules, which import scp_writer_helper ->
        # scp_writer, and scp_writer itself imports names from this module (parser.scp) - a
        # module-level import here would fail while parser.scp is still mid-initialization. By the
        # time this method actually runs, parser.scp has already finished loading, so it's safe.
        from ..writer.metadata.common_all import COMMON_LIBRARY_GENERATED
        if not COMMON_LIBRARY_GENERATED:
            return {}

        matched = {}
        for func in functions:
            if not func.is_common_func:
                continue

            entry = COMMON_FUNCTIONS.get(func.name)
            if entry is None:
                continue

            module_key, digest = entry
            if fingerprint_digest(function_fingerprint(self, func)) == digest:
                matched[func.name] = module_key

        return matched

    def get_inline_functions(self, functions: list[Function], *, matched: dict[str, str] | None = None) -> list[Function]:
        """functions this script must still define itself - everything not matched to the shared
        library. Returns functions unchanged when the library isn't active or nothing matched."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return functions

        return [func for func in functions if func.name not in matched]

    def gen_common_imports(self, functions: list[Function], *, matched: dict[str, str] | None = None) -> list[str]:
        """The @scena.CommonImports() manifest, in this script's own code order, for every function
        matched to the shared library. Empty when nothing matched - including strict round-trip
        mode and an ungenerated library, both handled by match_library_functions returning {}.
        The whole-library import itself lives in gen_python_header instead, unconditionally - it's
        pure name resolution for autocomplete/hand-editing, so it doesn't need to track fidelity
        mode or match state the way the manifest (what's actually compiled in) does."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return []

        indent = default_indent()
        lines = ['@scena.CommonImports()', 'def commonImports():', f'{indent}return [']
        for func in functions:
            if func.name in matched:
                lines.append(f'{indent * 2}{func.name},')
        lines.append(f'{indent}]')
        lines.append('')

        return lines

    def hook_module_name(self) -> str:
        """The optional hook module the generated script imports"""
        return f'{pathlib.Path(self.name).stem.strip()}_hook'

    def gen_hook_import(self) -> str:
        """The try/except block importing the optional <stem>_hook module - __import__ when the stem isn't a valid module
        path (e.g. mon5078+). Only a missing hook is ignored (for a dotted stem, also a missing parent package); a failed
        import inside the hook re-raises"""
        module = self.hook_module_name()
        parts = module.split('.')
        if all(is_module_name(part) for part in parts):
            statement = f'import {module}'

        else:
            statement = f'__import__({module!r})'

        if len(parts) == 1:
            check = f'e.name != {module!r}'

        else:
            prefixes = tuple('.'.join(parts[:end]) for end in range(1, len(parts) + 1))  # parents, then the hook
            check = f'e.name not in {prefixes!r}'

        return f'''\
try:
    {statement}
except ModuleNotFoundError as e:
    if {check}:
        raise'''

    def gen_hook_template(self) -> str:
        """A starting <stem>_hook.py: every callback is a no-op even when registered, so it compiles to the same bytes as
        no hook. Its TYPE_CHECKING block shows the script's names to Pylance; when no import can name the .py's stem,
        a rename hint instead"""
        stem = pathlib.Path(self.name).stem
        if is_module_name(stem) and not shadows_another_module(stem):
            type_checking = f'''\
    from {stem} import *  # pyright: ignore[reportAssignmentType]
    import {stem} as original'''

        else:
            reason = 'is also the name of another module' if is_module_name(stem) else "isn't a valid module name"
            suggested = suggested_module_name(stem)
            type_checking = f'''\
    # {stem!r} {reason}, so Pylance can't import the script's names. To get them, rename
    # {stem}.py to a valid name (it still compiles to {self.name}; keep this file's name) and uncomment:
    # from {suggested} import *  # pyright: ignore[reportAssignmentType]
    # import {suggested} as original
    pass'''

        return f'''\
# pyright: basic
from typing import TYPE_CHECKING
{SCP_WRITER_HELPER_IMPORT}
if TYPE_CHECKING:
{type_checking}

# Functions to add
def run_hook(g):
    for func in [
    ]:
        add_function(func)

# registerRunCallback(run_hook)

def func_hook(name, func):
    return None

# registerFuncCallback(func_hook)

def opcode_hook(opcode, *args):
    return None

# registerOpcodeCallback(opcode_hook)
'''

    def gen_python_footer(self) -> list[str]:
        """Generate Python footer lines for output script execution"""
        return '''\
def main():
    scena.run(globals())

if __name__ == '__main__':
    main()'''.splitlines()
