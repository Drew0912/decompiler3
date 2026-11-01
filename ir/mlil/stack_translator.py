"""Symbolic-stack LLIL -> MLIL translator: exact, non-SSA MLIL from the LLIL and its stack layout alone (each block's
sp_in, each stack access's slot_index, the SpAdds), never the bytecode.

A pushed value stays a pending expression on a pile and folds into the statement or expression that consumes it.
A push becomes a named local when its slot is read by offset, written in place or has its address taken, when it is
never consumed and is no call's setup (a declared slot, kept) and when it is consumed twice. An address-taken local
or parameter is read and written through its address, *(&v) (memory form). Before a statement that writes storage,
every pending leaf the write may change is copied into a fresh temporary, so each pending expression keeps the value
it had when pushed. A call's continuation (the call's return target, reached from the call alone) is translated into
the call's own MLIL block, the pile carried over.

The canonical form: every register is storage (MLILLoadReg / MLILStoreReg); a call with a result writes it to the
result register through a temporary (t = f(); REG[r] = t); a return reads the result register (return REG[r]); a
condition stays as the LLIL has it. Shaping passes run after the translator, each exact and removable.

The function's translation_counts record the shapes the translator met (docs/mlil/MLIL_DESIGN.md), for the corpus
runs to compare with the side-effect census."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

from ir.core import reverse_post_order
from ir.llil.llil import (
    LowLevelILBasicBlock, LowLevelILCall, LowLevelILConst, LowLevelILDebug, LowLevelILFrameAddr, LowLevelILFrameLoad,
    LowLevelILFrameStore, LowLevelILFunction, LowLevelILIf, LowLevelILInstruction, LowLevelILJmp, LowLevelILLoad,
    LowLevelILRegLoad, LowLevelILRegStore, LowLevelILRet, LowLevelILSpAdd, LowLevelILStackAddr, LowLevelILStackLoad,
    LowLevelILStackStore, LowLevelILStore, LowLevelILSyscall, walk as walk_llil,
)
from ir.pipeline import Pass
from .llil_ops import BINARY_OP_TYPES, UNARY_OP_TYPES
from .mlil import (
    MediumLevelILBasicBlock, MediumLevelILCall, MediumLevelILFunction, MediumLevelILInstruction, MLILAddressOf,
    MLILCall, MLILConst, MLILDeref, MLILLoadGlobal, MLILLoadReg, MLILStoreReg, MLILVar, MLILVariable, map_operands,
    mlil_arg_var_name, mlil_stack_var_name, walk,
)
from .mlil_builder import MLILBuilder

__all__ = ['StackTranslator', 'StackTranslatorPass', 'UnsupportedStackShape']


class UnsupportedStackShape(NotImplementedError):
    """A stack shape the translator does not translate yet: a value pending where control reaches a block other than
    its call's continuation, a block entry slot two pushes may hold, an address of a slot no push holds, or a shape a
    VM's subclass refuses"""


@dataclass(eq=False)
class Push:
    """A push (a stack store at or above sp) and how the function reads it, from the pre-pass"""

    store: LowLevelILStackStore
    consumers: set[LowLevelILInstruction] = field(default_factory=set)  # the statements reading it as their operand
    read_by_offset: bool = False
    written_in_place: bool = False
    address_taken: bool = False
    setup: bool = False                                                 # never consumed, removed by a call's cleanup
    variable: MLILVariable | None = None                                # a local's, named by the pre-pass

    @property
    def is_local(self) -> bool:
        if self.read_by_offset or self.written_in_place or self.address_taken or len(self.consumers) > 1:
            return True

        return not self.consumers and not self.setup     # a declared slot nothing reads


@dataclass(eq=False)
class PileEntry:
    """What a slot holds while a block is translated: a pending expression, a local, or (neither) a call's setup"""

    expr: MediumLevelILInstruction | None = None
    var: MLILVariable | None = None
    consumed: bool = False


class WriteKind(Enum):
    """What a statement may change, so the pending leaves it may change are copied before it"""

    CALL     = auto()   # a clobbering call: every register, global and dereference, address-taken variables too
    REGISTER = auto()   # one register
    GLOBAL   = auto()   # one global
    VARIABLE = auto()   # one local or parameter
    MEMORY   = auto()   # every dereference, address-taken variables too


class Write(NamedTuple):
    kind: WriteKind
    target: int | MLILVariable | None = None    # the register or global index, or the variable


class StackTranslator:
    """One function's translation. A VM's subclass gives its result register, its calling convention
    (parameter_position), its call nodes (make_call) and its own statements and expressions, falling back to these"""

    # Where a call leaves its result (None: a call gives none), and the statements reading their arguments in place
    RESULT_REGISTER: int | None          = None
    IN_PLACE_ARGUMENTS: tuple[type, ...] = (LowLevelILCall, LowLevelILSyscall)

    def __init__(self, llil_func: LowLevelILFunction):
        self.llil_func = llil_func
        self.entry = llil_func.get_block_by_addr(llil_func.start_addr)
        self.builder = MLILBuilder()
        self.pushes: dict[LowLevelILStackStore, Push] = {}
        self.entry_pushes: dict[LowLevelILBasicBlock, dict[int, set[Push]]] = {}
        self.continuations: set[LowLevelILBasicBlock] = set()
        self.refusals: list[str] = []
        self.address_taken_parameters: set[int] = set()     # the frame offsets whose address is taken
        self.memory_vars: set[MLILVariable] = set()         # the address-taken locals and parameters, read as *(&v)
        self.block_map: dict[LowLevelILBasicBlock, MediumLevelILBasicBlock] = {}
        self.pile: dict[int, PileEntry] = {}
        self.sp = 0
        self.statement: LowLevelILInstruction | None = None   # the LLIL statement being translated
        self.temp_count = 0

    def translate(self) -> MediumLevelILFunction:
        func = self.llil_func
        self.builder.create_function(func.name, func.start_addr, func.params)
        self.builder.function.llil_function = func
        self.builder.function.result_register = self.RESULT_REGISTER
        self.prepass()

        # Every reached block but the continuations, which their calls' blocks take in
        blocks = [block for block in func.basic_blocks
                  if block in self.entry_pushes and block not in self.continuations]
        for block in blocks:
            self.block_map[block] = self.builder.create_block(block.start, block.label)

        for block in blocks:
            self.builder.set_current_block(self.block_map[block])
            self.pile = {slot: PileEntry(var=next(iter(pushes)).variable)
                         for slot, pushes in self.entry_pushes[block].items()}
            current = block
            while current is not None:
                current = self.translate_block(current)

        function = self.builder.finalize()
        self.count_unwritten_register_reads(function)
        return function

    # === The pre-pass: which push each slot holds, and how each push is read ===

    def prepass(self):
        self.find_continuations()
        self.entry_pushes = {self.entry: {}}
        pending = [self.entry]
        while pending:
            block = pending.pop()
            exit_pushes = self.scan_block(block, self.entry_pushes[block])
            for successor in block.outgoing_edges:
                incoming = {slot: pushes for slot, pushes in exit_pushes.items() if slot < successor.sp_in}
                current = self.entry_pushes.get(successor)
                if current is None:
                    self.entry_pushes[successor] = {slot: set(pushes) for slot, pushes in incoming.items()}
                    pending.append(successor)
                elif self.merge(current, incoming):
                    pending.append(successor)

        self.name_locals()
        self.find_memory_vars()
        self.check_shapes()
        self.count_pushes()

    def find_continuations(self):
        """The return targets reached from their call's block alone"""
        for block in self.llil_func.basic_blocks:
            terminal = block.instructions[-1]
            if isinstance(terminal, LowLevelILCall) and terminal.returns:
                target = terminal.return_target
                if target is not self.entry and target.incoming_edges == [block]:
                    self.continuations.add(target)

    @classmethod
    def merge(cls, current: dict[int, set[Push]], incoming: dict[int, set[Push]]) -> bool:
        """incoming's pushes added to current's; whether any was new"""
        changed = False
        for slot, pushes in incoming.items():
            held = current.setdefault(slot, set())
            if not pushes <= held:
                held |= pushes
                changed = True
        return changed

    def scan_block(self, block: LowLevelILBasicBlock, entry_pushes: dict[int, set[Push]]) -> dict[int, set[Push]]:
        """The pushes block's statements read and how; the pushes holding each slot at its exit. A popped slot keeps its
        push until the next push there: the opcode that pops a value reads it in the statement after its SpAdd"""
        sp = block.sp_in
        holding = {slot: set(pushes) for slot, pushes in entry_pushes.items()}
        for inst in block.instructions:
            if isinstance(inst, LowLevelILSpAdd):
                sp += inst.delta
                continue

            in_place = isinstance(inst, self.IN_PLACE_ARGUMENTS)
            for operand in inst.operands():
                for node in walk_llil(operand):
                    if isinstance(node, LowLevelILStackLoad):
                        consumed = (in_place and node is operand) or node.slot_index >= sp
                        for push in holding.get(node.slot_index, ()):
                            if consumed:
                                push.consumers.add(inst)
                            else:
                                push.read_by_offset = True
                    elif isinstance(node, LowLevelILStackAddr):
                        holders = holding.get(node.slot_index, ())
                        if not holders:
                            self.refuse('an address of a slot no push holds')
                        for push in holders:
                            push.address_taken = True
                    elif isinstance(node, LowLevelILFrameAddr):
                        self.address_taken_parameters.add(node.offset)

            if isinstance(inst, LowLevelILStackStore):
                if inst.slot_index >= sp:
                    if inst not in self.pushes:
                        self.pushes[inst] = Push(inst)
                    holding[inst.slot_index] = {self.pushes[inst]}
                else:
                    for push in holding.get(inst.slot_index, ()):
                        push.written_in_place = True
            elif isinstance(inst, LowLevelILCall) and inst.returns:
                # The callee removes its arguments and the call's setup: the slots from the return target's sp_in
                for slot, pushes in holding.items():
                    if inst.return_target.sp_in <= slot < sp:
                        for push in pushes:
                            if not push.consumers:
                                push.setup = True

        return holding

    def name_locals(self):
        """Each local per declaring push: the slot's first in address order var_s<slot>, the n-th var_s<slot>_<n>"""
        by_slot: dict[int, list[Push]] = {}
        for push in self.pushes.values():
            if push.is_local:
                by_slot.setdefault(push.store.slot_index, []).append(push)

        for slot, pushes in by_slot.items():
            pushes.sort(key=lambda push: (push.store.address, push.store.inst_index))
            for n, push in enumerate(pushes):
                name = mlil_stack_var_name(slot) if n == 0 else f'{mlil_stack_var_name(slot)}_{n}'
                push.variable = self.builder.get_or_create_local(name, slot)
            if len(pushes) > 1:
                self.count('sibling slots')
                self.count('sibling locals', len(pushes))

    def find_memory_vars(self):
        """The variables read and written in memory form: each address-taken push's local, and each address-taken
        parameter (a parameter lives the whole function)"""
        self.memory_vars = {push.variable for push in self.pushes.values() if push.address_taken}
        self.memory_vars |= {self.parameter_var(offset) for offset in self.address_taken_parameters}

    def check_shapes(self):
        """Values cross only a call's return split: at any other block entry, a slot held by one local"""
        for block, holding in self.entry_pushes.items():
            if block is self.entry or block in self.continuations:
                continue
            for pushes in holding.values():
                if len(pushes) > 1:
                    self.refuse('a block entry slot two pushes may hold')
                elif not next(iter(pushes)).is_local:
                    self.refuse('a value or call setup pending at a block boundary')

        if self.refusals:
            raise UnsupportedStackShape(f'{self.llil_func.name}: {", ".join(dict.fromkeys(self.refusals))}')

    def refuse(self, reason: str):
        self.refusals.append(reason)

    def count_pushes(self):
        """A push nothing reads (declared: a local), and one read twice (a local too)"""
        for push in self.pushes.values():
            if len(push.consumers) > 1:
                self.count('push read twice')
            elif not (push.consumers or push.setup or push.read_by_offset or push.written_in_place
                      or push.address_taken):
                self.count('push never read')

    # === Translation ===

    def translate_block(self, block: LowLevelILBasicBlock) -> LowLevelILBasicBlock | None:
        """block's statements into the current MLIL block; the continuation the pile carries into, if any"""
        self.sp = block.sp_in
        for inst in block.instructions:
            self.builder.set_current_source(inst.address, inst.inst_index)
            self.statement = inst
            continuation = self.translate_statement(inst)
            if continuation is not None:
                return continuation

        return None

    def translate_statement(self, inst: LowLevelILInstruction) -> LowLevelILBasicBlock | None:
        builder = self.builder
        if isinstance(inst, LowLevelILSpAdd):
            self.sp += inst.delta
        elif isinstance(inst, LowLevelILDebug):
            builder.debug(inst.debug_type, inst.value)
        elif isinstance(inst, LowLevelILStackStore):
            self.translate_stack_store(inst)
        elif isinstance(inst, LowLevelILFrameStore):
            self.write_var(self.parameter_var(inst.offset), self.translate_expr(inst.value))
        elif isinstance(inst, LowLevelILStore):
            dest, value = self.translate_expr(inst.dest), self.translate_expr(inst.value)
            self.copy_out(Write(WriteKind.MEMORY))
            builder.store_deref(dest, value)
        elif isinstance(inst, LowLevelILRegStore):
            value = self.translate_expr(inst.value)
            self.copy_out(Write(WriteKind.REGISTER, inst.reg_index))
            builder.store_reg(inst.reg_index, value)
        elif isinstance(inst, LowLevelILSyscall):
            args = [self.translate_expr(arg) for arg in inst.args]
            self.copy_out(Write(WriteKind.CALL))
            output = self.result_temp()
            builder.syscall(inst.subsystem, inst.cmd, args, output)
            self.store_result(output)
        elif isinstance(inst, LowLevelILCall):
            return self.translate_call(inst)
        elif isinstance(inst, LowLevelILJmp):
            builder.goto(self.block_map[inst.target])
        elif isinstance(inst, LowLevelILIf):
            condition = self.translate_expr(inst.condition)
            builder.branch_if(condition, self.block_map[inst.true_target], self.block_map[inst.false_target])
        elif isinstance(inst, LowLevelILRet):
            builder.ret(self.result_read())
        else:
            raise NotImplementedError(f'{self.llil_func.name}: no stack translation of {type(inst).__name__}')

        return None

    def translate_stack_store(self, inst: LowLevelILStackStore):
        """A push (at or above sp): a pending entry, or a local's declaring store (kept); below sp, a local's write"""
        if inst.slot_index < self.sp:
            self.write_var(self.pile[inst.slot_index].var, self.translate_expr(inst.value))
            return

        push = self.pushes[inst]
        if inst.slot_index > self.sp:       # no push puts a value there: a store into a dead slot (a POP_TO)
            self.count('store above sp')
        if push.variable is not None:
            self.write_var(push.variable, self.translate_expr(inst.value))
            self.pile[inst.slot_index] = PileEntry(var=push.variable)
        elif push.setup:
            self.pile[inst.slot_index] = PileEntry()
        else:
            self.pile[inst.slot_index] = PileEntry(expr=self.translate_expr(inst.value))

    def translate_call(self, inst: LowLevelILCall) -> LowLevelILBasicBlock | None:
        """t = call(args); REG[r] = t; then the continuation, a goto to the return target, or (a tail call) the return
        that passes the callee's result on"""
        args = [self.translate_expr(arg) for arg in inst.args]
        self.copy_out(Write(WriteKind.CALL))
        output = self.result_temp()
        self.builder.add_instruction(self.make_call(inst, args, output))
        self.store_result(output)
        if not inst.returns:
            self.builder.ret(self.result_read())
            return None

        target = inst.return_target
        for slot in [slot for slot in self.pile if slot >= target.sp_in]:
            del self.pile[slot]
        if target in self.continuations:
            return target

        self.builder.goto(self.block_map[target])
        return None

    def translate_expr(self, node: LowLevelILInstruction) -> MediumLevelILInstruction:
        """node as an MLIL expression, every node it builds stamped with the current statement's source"""
        stamp = self.builder.stamp
        if isinstance(node, LowLevelILStackLoad):
            return self.take(node.slot_index)
        if isinstance(node, LowLevelILFrameLoad):
            return self.read_var(self.parameter_var(node.offset))
        if isinstance(node, LowLevelILStackAddr):
            return self.address_of(self.pile[node.slot_index].var)
        if isinstance(node, LowLevelILFrameAddr):
            return self.address_of(self.parameter_var(node.offset))
        if isinstance(node, LowLevelILLoad):
            return stamp(MLILDeref(self.translate_expr(node.src)))
        if isinstance(node, LowLevelILRegLoad):
            return stamp(MLILLoadReg(node.reg_index))
        if isinstance(node, LowLevelILConst):
            return stamp(MLILConst(node.value))
        if type(node) in BINARY_OP_TYPES:
            lhs = self.translate_expr(node.lhs)
            return stamp(BINARY_OP_TYPES[type(node)](lhs, self.translate_expr(node.rhs)))
        if type(node) in UNARY_OP_TYPES:
            return stamp(UNARY_OP_TYPES[type(node)](self.translate_expr(node.operand)))

        raise NotImplementedError(f'{self.llil_func.name}: no stack translation of {type(node).__name__}')

    def take(self, slot: int) -> MediumLevelILInstruction:
        """A read of slot: its local, or its pending expression, which only its one consumer reads"""
        entry = self.pile[slot]
        if entry.var is not None:
            return self.read_var(entry.var)
        if entry.expr is None or entry.consumed:
            raise RuntimeError(f'{self.llil_func.name}: slot {slot} read where the pre-pass found no pending value')

        entry.consumed = True
        return entry.expr

    # === Variables ===

    def read_var(self, var: MLILVariable) -> MediumLevelILInstruction:
        """A read of var; an address-taken one through its address, *(&v)"""
        if var in self.memory_vars:
            return self.builder.stamp(MLILDeref(self.address_of(var)))

        return self.builder.stamp(MLILVar(var))

    def write_var(self, var: MLILVariable, value: MediumLevelILInstruction):
        """var = value after the copy-out; an address-taken var through its address, *(&v) = value"""
        self.copy_out(Write(WriteKind.VARIABLE, var))
        if var in self.memory_vars:
            self.builder.store_deref(self.address_of(var), value)
        else:
            self.builder.set_var(var, value)

    def address_of(self, var: MLILVariable) -> MLILAddressOf:
        stamp = self.builder.stamp
        return stamp(MLILAddressOf(stamp(MLILVar(var))))

    @classmethod
    def memory_form_var(cls, node: MediumLevelILInstruction) -> MLILVariable | None:
        """v when node reads an address-taken variable, *(&v)"""
        if (isinstance(node, MLILDeref) and isinstance(node.operand, MLILAddressOf)
                and isinstance(node.operand.operand, MLILVar)):
            return node.operand.operand.var

        return None

    # === Writes ===

    def copy_out(self, write: Write):
        """Before a write: every pending leaf it may change copied into a fresh temporary, the pending expression then
        reading the copy, so it keeps the value it had when pushed (it holds only pure operators)"""
        self.count_pending()
        for slot in sorted(self.pile):
            entry = self.pile[slot]
            if entry.expr is not None and not entry.consumed:
                entry.expr = self.copied(entry.expr, write)

    def copied(self, node: MediumLevelILInstruction, write: Write) -> MediumLevelILInstruction:
        if self.may_change(write, node):
            self.count(f'copy at {self.statement_name(self.statement)}: {self.leaf_name(node)}')
            temp = self.new_temp()
            self.builder.set_var(temp, node)
            return MLILVar(temp).copy_metadata_from(node)
        if isinstance(node, MLILAddressOf):     # an address names storage: what is stored there changes, not it
            return node

        return map_operands(node, lambda operand: self.copied(operand, write))

    @classmethod
    def may_change(cls, write: Write, node: MediumLevelILInstruction) -> bool:
        """The write model, one conservative rule for every write"""
        match write.kind:
            case WriteKind.CALL:
                return isinstance(node, (MLILLoadReg, MLILLoadGlobal, MLILDeref))
            case WriteKind.REGISTER:
                return isinstance(node, MLILLoadReg) and node.index == write.target
            case WriteKind.GLOBAL:
                return isinstance(node, MLILLoadGlobal) and node.index == write.target
            case WriteKind.VARIABLE:    # an address-taken one read as *(&v)
                return (isinstance(node, MLILVar) and node.var == write.target
                        or cls.memory_form_var(node) == write.target)
            case WriteKind.MEMORY:      # *(&v) too: a pointer the function holds may be &v
                return isinstance(node, MLILDeref)

        return False

    def new_temp(self) -> MLILVariable:
        """t<n>: one counter per function, a name never reused"""
        self.temp_count += 1
        return self.builder.get_or_create_local(f't{self.temp_count}')

    def result_temp(self) -> MLILVariable | None:
        return None if self.RESULT_REGISTER is None else self.new_temp()

    def store_result(self, output: MLILVariable | None):
        """REG[r] = t: the call's result in the result register, a write the output prints"""
        if output is not None:
            self.builder.store_reg(self.RESULT_REGISTER, self.builder.stamp(MLILVar(output)))

    def result_read(self) -> MediumLevelILInstruction | None:
        """What a return passes on: the result register, or nothing on a VM without one"""
        return None if self.RESULT_REGISTER is None else self.builder.stamp(MLILLoadReg(self.RESULT_REGISTER))

    # === Counts ===

    def count(self, key: str, n: int = 1):
        self.builder.function.translation_counts[key] += n

    @classmethod
    def statement_name(cls, inst: LowLevelILInstruction) -> str:
        """A statement in a count: its operation's name, a register store's with its register"""
        if isinstance(inst, LowLevelILRegStore):
            return f'{inst.operation_name} {inst.reg_index}'

        return inst.operation_name

    @classmethod
    def leaf_name(cls, node: MediumLevelILInstruction) -> str:
        """A copied leaf in a count: each kind may_change can match"""
        if isinstance(node, MLILLoadReg):
            return f'register {node.index}'
        if isinstance(node, MLILLoadGlobal):
            return 'global'
        if cls.memory_form_var(node) is not None:
            return 'variable'
        if isinstance(node, MLILDeref):
            return 'dereference'

        return 'variable'

    def count_pending(self):
        """The current statement, once, when a value is pending below its own operands (read by now); a VM's
        statement that writes nothing calls it too"""
        if any(entry.expr is not None and not entry.consumed for entry in self.pile.values()):
            self.count(f'pending at {self.statement_name(self.statement)}')

    def count_unwritten_register_reads(self, function: MediumLevelILFunction):
        """Each register read that some way reaches with no store to the register since the entry or since a call that
        clobbers: a must-written dataflow over the MLIL's blocks, where the canonical form makes every register write a
        statement"""
        entry = function.basic_blocks[0]
        order = reverse_post_order(entry, lambda block: block.outgoing_edges)
        exits: dict[MediumLevelILBasicBlock, frozenset[int]] = {}

        def written_at_entry(block: MediumLevelILBasicBlock) -> frozenset[int]:
            # A predecessor not reached yet in the iteration counts as writing every register
            known = [exits[predecessor] for predecessor in block.incoming_edges if predecessor in exits]
            return frozenset.intersection(*known) if block is not entry and known else frozenset()

        changed = True
        while changed:
            changed = False
            for block in order:
                written = self.registers_written(block, written_at_entry(block))
                if exits.get(block) != written:
                    exits[block] = written
                    changed = True

        for block in order:
            self.registers_written(block, written_at_entry(block), counting=True)

    def registers_written(self, block: MediumLevelILBasicBlock, written: frozenset[int],
                          counting: bool = False) -> frozenset[int]:
        """The registers written on every way to block's end, from those on every way to its start; counting, each
        read of a register not among them"""
        for inst in block.instructions:
            if counting:
                for operand in inst.operands():
                    for node in walk(operand):
                        if isinstance(node, MLILLoadReg) and node.index not in written:
                            self.count('unwritten register read')
            if isinstance(inst, MLILStoreReg):
                written |= {inst.index}
            elif isinstance(inst, MediumLevelILCall) and inst.clobbers_registers:
                written = frozenset()       # the result store follows the call

        return written

    # === The VM's ===

    def parameter_var(self, frame_offset: int) -> MLILVariable:
        position = self.parameter_position(frame_offset)
        return self.builder.get_or_create_parameter(position, mlil_arg_var_name(position))

    def parameter_position(self, frame_offset: int) -> int:
        """The 1-based parameter in the frame slot at frame_offset: the VM's calling convention"""
        raise NotImplementedError(f'{type(self).__name__} gives no calling convention')

    def make_call(self, inst: LowLevelILCall, args: list[MediumLevelILInstruction],
                  output: MLILVariable | None) -> MediumLevelILCall:
        """The MLIL call of an LLIL call; a VM's own call kinds override it"""
        return MLILCall(inst.target, args, output, tail_call=not inst.returns)


class StackTranslatorPass(Pass):
    """LLIL -> MLIL through a stack translator class"""

    def __init__(self, translator_class: type[StackTranslator] = StackTranslator):
        self.translator_class = translator_class

    def run(self, llil_func: LowLevelILFunction) -> MediumLevelILFunction:
        return self.translator_class(llil_func).translate()
