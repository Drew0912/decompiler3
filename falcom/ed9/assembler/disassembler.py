"""The ED9 disassembler: the root assembler's recursive descent driven by a simulated VM stack. Its hooks check every
edge's stack against the block it enters, give each call its return edge, and rewrite a call setup's PUSH_RAW pushes"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

from assembler import (SYNTHETIC_INSTRUCTION_SIZE, BasicBlock, BranchKind, BranchTarget, DisassemblerContext,
                       Instruction, Operand)
from dc3.logging import log
from ir.llil import WORD_SIZE
from .ed9_optable import ED9Opcode
from .function import Function, SlotRef, StackLayout
from .stack_effects import (CALLEE_OPERAND, LOCAL_SETUP_SLOTS, POP_SIZE_OPERAND, SLOT_OFFSET_OPERAND, InstructionKind,
                            PopCarry)


# The kinds the simulation handles alike: what they pop is a plain use, and what they push is the instruction itself
# Kind groups on the simulation's path are tuples, most frequent first: a tuple compares identities in C, a frozenset
# would call Enum's Python __hash__ for every instruction
PLAIN_VALUE_KINDS = (
    InstructionKind.PUSH_CONST, InstructionKind.DEBUG_LINE, InstructionKind.SYSCALL, InstructionKind.LOAD_SLOT,
    InstructionKind.BINARY, InstructionKind.LOAD_REG, InstructionKind.CONDITIONAL_JUMP, InstructionKind.STORE_REG,
    InstructionKind.JUMP, InstructionKind.UNARY, InstructionKind.POPN, InstructionKind.SLOT_ADDRESS,
    InstructionKind.LOAD_DEREF, InstructionKind.STORE_DEREF, InstructionKind.LOAD_GLOBAL, InstructionKind.STORE_GLOBAL,
    InstructionKind.DEBUG_INT,
)

# Calls that take arguments from the stack; SYSCALL leaves them there for a later POP
ARGUMENT_CALL_KINDS = (
    InstructionKind.CALL, InstructionKind.SYSCALL, InstructionKind.CALL_SCRIPT, InstructionKind.TAIL_CALL,
)


@dataclass(eq=False)
class ParamEntry:
    """Simulated stack entry for a parameter the caller pushed"""

    index : int


@dataclass(eq=False)
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


class StackEntryGroups:
    """Union-find over simulated stack entries. Entries that stand at the same position when two edges meet are one
    group: after the join either may be there. A call that consumes a group gives it a role every member must fit.
    Keyed by the entries, which compare and hash by identity: equal-looking pushes are still different pushes."""

    def __init__(self):
        self.parent     : dict = {}                 # entry -> parent entry
        self.members    : dict[object, list] = {}   # root -> entries
        self.roles      : dict[object, Role] = {}   # root -> the role a call consumed the group as

    def find(self, entry):
        if entry not in self.parent:
            self.parent[entry] = entry
            self.members[entry] = [entry]
            return entry

        root = entry
        while self.parent[root] is not root:
            root = self.parent[root]

        while self.parent[entry] is not root:
            self.parent[entry], entry = root, self.parent[entry]

        return root

    def role_of(self, entry) -> Role | None:
        """The role entry's group was consumed as, without creating a group for it"""
        if entry not in self.parent:
            return None

        return self.roles.get(self.find(entry))

    def union(self, entry, other) -> tuple[Role | None, Role | None]:
        """Merge two groups; returns the roles either was consumed as (none when they already were one group)"""
        root, other_root = self.find(entry), self.find(other)
        if root is other_root:
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
        self.backward_returns = {}  # the function's calls returning at or before themselves, as on Function

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

    current_func     : Function | None = None     # Function being disassembled
    functions        : list[Function] = field(default_factory=list)       # the script's, by table index
    code_end         : int | None = None            # Where the next function's code starts (None: last function)
    known_code_end   : int | None = None            # Where the code ends, when known: nothing may run or jump past it
    reject_outside_stack : bool = False             # fail on a slot outside the live stack, a read past it
    quiet            : bool = False                 # the caller reports the unusual-slot and backward-return warnings
    runs_on          : Instruction | None = None    # the first instruction that runs on past code_end
    backward_returns : dict = field(default_factory=dict)                   # call offset -> (call, warning)
    current_inst     : Instruction | None = None    # Instruction being simulated
    stack_simulation : list = field(default_factory=list)                   # Simulated stack of the block being decoded
    edge_states      : dict[int, tuple] = field(default_factory=dict)       # block start -> state; later edges match its height
    recorded_edges   : list = field(default_factory=list)                   # (source offset, target, state) of every edge
    inst_states      : dict[int, tuple] = field(default_factory=dict)       # instruction offset -> the stack before it
    groups           : StackEntryGroups = field(default_factory=StackEntryGroups)
    plain_uses       : set = field(default_factory=set)                     # entries an ordinary consumer used
    pop_carry        : PopCarry = field(default_factory=PopCarry)           # bytes the last POP left inside a slot
    split_pop_start  : Instruction | None = None    # the split pop's first POP, while it ends inside a slot
    carried_before   : dict[int, int] = field(default_factory=dict)         # bytes a split pop carries into a POP
    split_pop_starts : dict[int, Instruction] = field(default_factory=dict)  # a split pop's later POP -> its first
    declares_call_returns : bool = True             # CALL and CALL_SCRIPT return their own return edges

    def fail(self, message: str, inst: Instruction | None = None):
        raise ScpDisassemblyError.at(self.current_func.name, message, inst)

    def continue_split_pop(self, inst: Instruction):
        """inst comes right after a POP that ended inside a slot: only a POP may complete it"""
        if inst.descriptor.kind != InstructionKind.POP:
            self.fail_split_pop(self.split_pop_start, f'{inst.mnemonic} at 0x{inst.offset:X} comes')

        self.carried_before[inst.offset] = self.pop_carry.carried
        self.split_pop_starts[inst.offset] = self.split_pop_start

    def fail_split_pop(self, start: Instruction, event: str):
        """A split pop that ends inside a slot, blamed on its first POP"""
        size = start.operands[POP_SIZE_OPERAND].value
        self.fail(f'pops {size} bytes, not whole slots, and {event} before a POP completes the slot', start)

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
        return not desc.ends_block or any(target.kind == BranchKind.FALSE
                                          for target in desc.get_branch_targets(inst, end))

    def record_edge(self, source: int, target: int, state: tuple):
        """The first edge into a block records its state. Every later edge - also one arriving after the block was
        decoded - must match its height; entries that differ become one group."""
        self.recorded_edges.append((source, target, state))
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
        if member in self.plain_uses:
            self.fail(f'expects {role}, but {format_stack_entry(member)} is also used as a plain value',
                      self.current_inst)

        if role.kind == RoleKind.FRAME:
            fits = isinstance(member, FrameSlot) and member.index == role.slot and frame_return(member) == role.target
        elif role.kind == RoleKind.FUNC_ID:
            fits = self.is_function_id(member)
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

    def is_function_id(self, entry) -> bool:
        """A local call setup's function ID: PUSH_CURRENT_FUNC_ID, or the PUSH_RAW of this function's index"""
        return is_push(entry, ED9Opcode.PUSH_CURRENT_FUNC_ID) or (
            is_push(entry, ED9Opcode.PUSH_RAW) and entry.operands[0].value == self.current_func.index
        )

    def is_inside(self, target: int) -> bool:
        """target lies in this function's code"""
        return self.current_func.offset <= target and (self.code_end is None or target < self.code_end)

    def setup_return(self, start: int) -> int | None:
        """The return offset of the local call setup at stack[start] - a function ID under a return address inside this
        function, as a call's own checks accept them; None when there is none"""
        stack = self.stack_simulation
        if not 0 <= start <= len(stack) - LOCAL_SETUP_SLOTS:
            return None

        func_id, ret_addr = stack[start:start + LOCAL_SETUP_SLOTS]
        target = encoded_return(ret_addr)
        if not self.is_function_id(func_id) or target is None or not self.is_inside(target):
            return None

        return target

    def retarget_push(self, push: Instruction, opcode: int, *values):
        """Turn a setup push into a pseudo-instruction with the given operand values"""
        push.opcode = opcode
        push.descriptor = self.instruction_table.get_descriptor(opcode)
        push.operands = [Operand(descriptor=op_desc, value=value)
                         for op_desc, value in zip(push.descriptor.operand_descriptors, values)]

    def return_target(self, entry, target: int | None) -> int:
        """The return offset entry encodes, which must lie in this function's code; one at or before the call only
        warns"""
        if target is None:
            self.fail(f'expects a return address, found {format_stack_entry(entry)}', self.current_inst)

        if target == self.code_end:
            self.fail(f'returns to 0x{target:X}, past its end (no RETURN after its return label)', self.current_inst)

        if not self.is_inside(target):
            self.fail(f'return offset 0x{target:X} is outside the function', self.current_inst)

        if target <= self.current_inst.offset:
            self.note_backward_return(target)

        return target

    def note_backward_return(self, target: int):
        """A call returning at or before itself loops back to its return label - endless unless code in between jumps
        out, and almost always a stale label (no game script or decompiled one has it)"""
        message = f'returns to 0x{target:X}, at or before the call, so it loops back there (a stale return label?)'
        self.backward_returns[self.current_inst.offset] = (self.current_inst, message)
        if not self.quiet:
            log.warning(ScpFunctionError.describe(self.current_func.name, message, self.current_inst))

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

        self.plain_uses.add(entry)

    def pop_count(self, inst: Instruction) -> int:
        """How many entries inst pops above a call's setup; a local CALL's are its callee's parameters, a POP's the
        whole slots it completes, the bytes the POP before it carried counted first"""
        effect = inst.descriptor.effect
        if isinstance(effect.pops, int):            # most kinds: no operand list to build
            return effect.pops

        return effect.pop_count(inst.operand_values, self.get_func_argc, self.pop_carry)

    def call_argc(self, inst: Instruction) -> int:
        """How many arguments a call takes from the stack; SYSCALL reads them in place"""
        effect = inst.descriptor.effect
        if effect.reads:
            return effect.read_count(inst.operand_values)

        return self.pop_count(inst)

    def require_entries(self, count: int, verb: str):
        """The stack holds the count entries the current instruction pops or reads"""
        stack = self.stack_simulation
        if count > len(stack):
            self.fail(f'{verb} {count} entries, the stack has {len(stack)}: {format_stack(stack)}', self.current_inst)

    def pop_call_setup(self, count: int) -> list:
        """Pop count entries, bottom first, for the call that consumes them as its setup or caller frame"""
        stack = self.stack_simulation
        self.require_entries(count, 'pops')
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
            for block in entry_block.reachable_blocks()
        }
        starts = {start: self.inst_states[insts[0].offset] for start, insts in blocks.items()}
        # A recorded edge leaves from its block's last real instruction: the one that branches, or a split head's last
        source_blocks = {insts[-1].offset: start for start, insts in blocks.items()}

        # Block start -> slot -> the entries that may stand there
        held = {start: [set() for _ in state] for start, state in starts.items()}
        held[entry_block.offset] = [{entry} for entry in starts[entry_block.offset]]

        def held_at(block: int, state: tuple, slot: int) -> set:
            """The entries that may stand in slot where block's stack is state"""
            while True:
                entry = state[slot]
                if slot < len(starts[block]) and entry is starts[block][slot]:
                    return held[block][slot]

                if not (isinstance(entry, Instruction) and entry.opcode == ED9Opcode.POP_TO):
                    return {entry}

                state = self.inst_states[entry.offset]

        changed = True
        while changed:
            changed = False
            for source, target, state in self.recorded_edges:
                for slot, target_entries in enumerate(held[target]):
                    count = len(target_entries)
                    target_entries.update(held_at(source_blocks[source], state, slot))
                    changed = changed or len(target_entries) != count

        layout = StackLayout(carried_before=self.carried_before)
        arguments = {}      # push offset -> (call offset, argN) of each call it may be an argument of
        for start, insts in blocks.items():
            for inst in insts:
                state = self.inst_states[inst.offset]
                layout.sp_before[inst.offset] = len(state)
                effect = inst.descriptor.effect
                if effect.addresses_slot:
                    slot = addressed_slot(inst, len(state))
                    live = 0 <= slot < len(state) - effect.pops
                    entries = held_at(start, state, slot) if live else set()
                    ref = self.slot_ref(slot, entries, layout.local_slots)
                    if not live and self.reject_outside_stack:
                        self.fail(f'addresses {ref}', inst)

                    if ref.unusual and not self.quiet:
                        log.warning(f'{self.current_func.name}: {inst.mnemonic} at 0x{inst.offset:X} addresses {ref}')

                    layout.slot_refs[inst.offset] = ref

                if inst.descriptor.kind in ARGUMENT_CALL_KINDS:
                    for slot in range(max(len(state) - self.call_argc(inst), 0), len(state)):
                        for entry in held_at(start, state, slot):
                            # A parameter or caller-frame entry has no line of its own
                            if isinstance(entry, Instruction):
                                arguments.setdefault(entry.offset, []).append((inst.offset, len(state) - slot))

        layout.arg_numbers = {offset: tuple(number for _, number in sorted(calls))
                              for offset, calls in arguments.items()}
        return layout

    def slot_ref(self, slot: int, entries: set, local_slots: dict[int, int]) -> SlotRef:
        """What slot may hold, from the entries that may stand there; each local's instruction goes into local_slots"""
        params, local, caller_frame, call_setup = [], False, False, False
        for entry in entries:
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


def on_disasm_function(context: ScpDisassemblerContext, offset: int, name: str):
    """The entry block starts with the caller's parameters"""
    if context.known_code_end is not None and offset >= context.known_code_end:
        context.fail('has no code before the end of the code (no RETURN)')

    context.edge_states[offset] = tuple(ParamEntry(index) for index in range(len(context.current_func.params)))


def on_block_start(context: ScpDisassemblerContext, offset: int):
    """Start the block from its recorded state"""
    context.enter_block(offset)


def on_pre_add_branch(context: ScpDisassemblerContext, target: BranchTarget):
    """Record the state the edge carries into its target (a branch or a fall-through)"""
    # Only a POP's fall-through into a block start gets here inside a split pop: something else lands on its
    # next POP
    if context.pop_carry.carried:
        context.fail_split_pop(context.split_pop_start, f'a branch lands at 0x{target.offset:X}')

    if context.known_code_end is not None and target.offset >= context.known_code_end:
        context.fail(f'jumps to 0x{target.offset:X}, past the end of the code (no RETURN after its label)',
                     context.current_inst)

    context.record_edge(context.current_inst.offset, target.offset, tuple(context.stack_simulation))


def on_block_split(context: ScpDisassemblerContext, source_offset: int, split_offset: int):
    """The head falls through into the tail with the state the tail's first instruction was simulated with"""
    start = context.split_pop_starts.get(split_offset)
    if start is not None:
        context.fail_split_pop(start, f'a branch lands at 0x{split_offset:X}')

    context.record_edge(source_offset, split_offset, context.inst_states[split_offset])


def on_instruction_decoded(context: ScpDisassemblerContext, inst: Instruction, block: BasicBlock) -> list[BranchTarget]:
    """Simulate the instruction's stack effect; a call returns its return edge"""
    stack = context.stack_simulation
    context.current_inst = inst
    context.inst_states[inst.offset] = tuple(stack)
    if context.pop_carry.carried:
        context.continue_split_pop(inst)

    context.note_run_on(inst)
    effect = inst.descriptor.effect

    # Before anything rounds it down to a slot (addressed_slot, the lifter)
    if effect.addresses_slot:
        offset = inst.operands[SLOT_OFFSET_OPERAND].value
        if offset % WORD_SIZE:
            context.fail(f'addresses byte offset {offset}, not a whole slot ({WORD_SIZE} bytes each), which '
                         "the VM allows (it reaches across two slots) but the decompiler can't follow - "
                         'offsets count bytes', inst)

    match inst.descriptor.kind:
        case kind if kind in PLAIN_VALUE_KINDS:
            # SYSCALL's in-place read past the stack fails its lift; the compile check fails it here, at the
            # instruction. Decompiling doesn't: a parse failure would lose the whole file, a lift failure only
            # the function
            if effect.reads and context.reject_outside_stack:
                context.require_entries(context.call_argc(inst), 'reads')

            if effect.pops:
                context.pop_entries(context.pop_count(inst))

            if effect.pushes:
                stack.append(inst)

        case InstructionKind.RETURN:
            if stack:
                context.fail(f'the stack is not empty: {format_stack(stack)}', inst)

        case InstructionKind.POP:
            if not context.pop_carry.carried:
                context.split_pop_start = inst

            context.pop_entries(context.pop_count(inst))
            # A split pop can't go on into the next function's code
            if context.pop_carry.carried and inst.offset + inst.size == context.code_end:
                context.fail_split_pop(context.split_pop_start, 'the function ends')

        case InstructionKind.STORE_SLOT:
            slot = addressed_slot(inst, len(stack))
            context.pop_entries(effect.pops)
            context.write_slot(slot)

        case InstructionKind.PUSH_CALLER_FRAME:
            stack.extend(FrameSlot(inst, index) for index in range(effect.pushes))

        case InstructionKind.CALL:
            return simulate_call(context, inst)

        case InstructionKind.CALL_SCRIPT:
            return simulate_call_script(context, inst)

        case InstructionKind.TAIL_CALL:
            simulate_tail_call(context, inst)

        # PUSH_FUNC_ID / PUSH_RET_ADDR: the parser makes them itself, from a setup's PUSH_RAW
        case kind:
            raise NotImplementedError(f'the parser never simulates {kind.name}')

    return []


def simulate_call(context: ScpDisassemblerContext, inst: Instruction) -> list[BranchTarget]:
    """PUSH(func_id) PUSH(ret_addr) args... CALL: the callee pops the args and both setup pushes and returns to
    the pushed return address. The setup pushes become PUSH_CURRENT_FUNC_ID / PUSH_RET_ADDR. Checked in order: the
    argument count, the args, the setup's height, the return offset, the function ID, then the return address's
    group."""
    argc = context.call_argc(inst)
    require_argument_count(context, inst, argc)
    context.pop_entries(argc)
    func_id, ret_addr = context.pop_call_setup(inst.descriptor.effect.setup_pops)
    target = context.return_target(ret_addr, encoded_return(ret_addr))
    context.consume(func_id, Role(RoleKind.FUNC_ID))
    context.consume(ret_addr, Role(RoleKind.RET_ADDR, target))
    return [BranchTarget.unconditional(target)]


def require_argument_count(context: ScpDisassemblerContext, inst: Instruction, argc: int):
    """No setup right below the args, but this call's own setup - the one returning right after the call - lower or
    higher: the mistake is the argument count, so say that instead of what stands where the setup should be. Only
    the setup returning here counts, so an outer call's pending setup is never taken for this call's."""
    stack = context.stack_simulation
    if context.setup_return(len(stack) - argc - LOCAL_SETUP_SLOTS) is not None:
        return

    returns_here = inst.offset + inst.size
    starts = [start for start in range(len(stack)) if context.setup_return(start) == returns_here]
    if not starts:
        return

    start = starts[-1]
    found = len(stack) - start - LOCAL_SETUP_SLOTS
    callee = context.functions[inst.operands[CALLEE_OPERAND].value]
    arguments = 'argument' if argc == 1 else 'arguments'
    message = (f'{callee.name} takes {argc} {arguments}, found {found} above its call setup '
               f'{format_stack(stack[start:start + LOCAL_SETUP_SLOTS])}')
    if found < argc and all(param.default_value is not None for param in callee.params[found:]):
        message += ('; a local CALL passes every argument - defaults apply only when the engine calls the function '
                    'by name')

    context.fail(message, inst)


def simulate_call_script(context: ScpDisassemblerContext, inst: Instruction) -> list[BranchTarget]:
    """PUSH_CALLER_FRAME(ret) args... CALL_SCRIPT: the callee pops the args and the caller frame, and returns to
    the frame's return address. Checked in order: the args, the frame's height, its return address, each slot."""
    context.pop_entries(context.call_argc(inst))
    frame = context.pop_call_setup(inst.descriptor.effect.setup_pops)
    target = context.return_target(frame[0], frame_return(frame[0]))
    for slot, entry in enumerate(frame):
        context.consume(entry, Role(RoleKind.FRAME, target, slot))

    return [BranchTarget.unconditional(target)]


def simulate_tail_call(context: ScpDisassemblerContext, inst: Instruction):
    """CALL_SCRIPT_NO_RETURN: the callee takes over the args, which must be all that is left on the stack"""
    context.pop_entries(context.call_argc(inst))
    if context.stack_simulation:
        context.fail(f'leaves {format_stack(context.stack_simulation)} below its args, which the VM allows (it '
                     "discards them, setting sp to 0) but the decompiler can't follow - pass the args through "
                     'registers (SET_REG, POP, GET_REG)', inst)
