"""Symbolic-stack LLIL -> MLIL translator: exact, non-SSA MLIL from the LLIL and its stack layout alone (each block's
sp_in, each stack access's slot_index, the SpAdds), never the bytecode.

A pushed value stays a pending expression on a pile and folds into the statement or expression that consumes it.
A push becomes a named local when its slot is read by offset, written in place or has its address taken, when it is
never consumed and is no call's setup (a declared slot, kept) and when it is consumed twice. Before a statement that
writes storage, every pending leaf the write may change is copied into a fresh temporary, so each pending expression
keeps the value it had when pushed. A call's continuation (the call's return target, reached from the call alone) is
translated into the call's own MLIL block, the pile carried over.

The canonical form: every register is storage (MLILLoadReg / MLILStoreReg); a call with a result writes it to the
result register through a temporary (t = f(); REG[r] = t); a return reads the result register (return REG[r]); a
condition stays as the LLIL has it. Shaping passes run after the translator, each exact and removable."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple

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
    MLILCall, MLILConst, MLILDeref, MLILLoadGlobal, MLILLoadReg, MLILVar, MLILVariable, map_operands,
    mlil_arg_var_name, mlil_stack_var_name,
)
from .mlil_builder import MLILBuilder

__all__ = ['StackTranslator', 'StackTranslatorPass', 'UnsupportedStackShape']


class UnsupportedStackShape(NotImplementedError):
    """A stack shape the translator does not translate yet: an address-taken local or parameter, a value pending where
    control reaches a block other than its call's continuation, a block entry slot two pushes may hold, or a shape a
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

    CALL     = auto()   # a clobbering call: every register, global and dereference
    REGISTER = auto()   # one register
    GLOBAL   = auto()   # one global
    VARIABLE = auto()   # one local or parameter
    MEMORY   = auto()   # every dereference


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
        self.block_map: dict[LowLevelILBasicBlock, MediumLevelILBasicBlock] = {}
        self.pile: dict[int, PileEntry] = {}
        self.sp = 0
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

        return self.builder.finalize()

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
        self.check_shapes()

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
                        for push in holding.get(node.slot_index, ()):
                            push.address_taken = True
                        self.refuse('an address-taken local')
                    elif isinstance(node, LowLevelILFrameAddr):
                        self.refuse('an address-taken parameter')

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

    # === Translation ===

    def translate_block(self, block: LowLevelILBasicBlock) -> LowLevelILBasicBlock | None:
        """block's statements into the current MLIL block; the continuation the pile carries into, if any"""
        self.sp = block.sp_in
        for inst in block.instructions:
            self.builder.set_current_source(inst.address, inst.inst_index)
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
            var = self.parameter_var(inst.offset)
            value = self.translate_expr(inst.value)
            self.copy_out(Write(WriteKind.VARIABLE, var))
            builder.set_var(var, value)
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
            var = self.pile[inst.slot_index].var
            value = self.translate_expr(inst.value)
            self.copy_out(Write(WriteKind.VARIABLE, var))
            self.builder.set_var(var, value)
            return

        push = self.pushes[inst]
        if push.variable is not None:
            value = self.translate_expr(inst.value)
            self.copy_out(Write(WriteKind.VARIABLE, push.variable))
            self.builder.set_var(push.variable, value)
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
            return stamp(MLILVar(self.parameter_var(node.offset)))
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
            return self.builder.stamp(MLILVar(entry.var))
        if entry.expr is None or entry.consumed:
            raise RuntimeError(f'{self.llil_func.name}: slot {slot} read where the pre-pass found no pending value')

        entry.consumed = True
        return entry.expr

    # === Writes ===

    def copy_out(self, write: Write):
        """Before a write: every pending leaf it may change copied into a fresh temporary, the pending expression then
        reading the copy, so it keeps the value it had when pushed (it holds only pure operators)"""
        for slot in sorted(self.pile):
            entry = self.pile[slot]
            if entry.expr is not None and not entry.consumed:
                entry.expr = self.copied(entry.expr, write)

    def copied(self, node: MediumLevelILInstruction, write: Write) -> MediumLevelILInstruction:
        if self.may_change(write, node):
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
            case WriteKind.VARIABLE:
                return isinstance(node, MLILVar) and node.var == write.target
            case WriteKind.MEMORY:
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
