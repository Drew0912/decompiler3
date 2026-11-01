"""Call result pass - the stack translator writes each call's result to the result register through a temporary
(t = f(); REG[r] = t); this takes those stores out where nothing reads them. Exact and removable: no evaluation moves,
every value stays as written, and the translator's canonical form stays its input. HLIL's CallResultFolder then folds
each temporary into its one reader"""

from collections import Counter

from ir.pipeline import Pass
from ..mlil import (
    map_operands,
    walk,
    UNASSIGNED_SLOT_INDEX,
    MediumLevelILBasicBlock,
    MediumLevelILCall,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILDebug,
    MLILLoadReg,
    MLILSetVar,
    MLILStoreReg,
    MLILVar,
    MLILVariable,
)


class CallResultPass(Pass):
    """On the function's result register, in order:
    - after a call's result store, each read of the register in the call's block, up to the first statement that may
      write it (its own operands are read first), reads the call's temporary;
    - a result store the register is dead after is dropped, and a call whose temporary nothing reads then gives no
      output, the call kept;
    - the translator's copy of a call's temporary into a temporary of its own (t2 = t1, line markers allowed between)
      becomes the call's output, t2 = f().
    A function without a result register is left as it is."""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        if func.result_register is None:
            return func

        self.func = func
        self.register = func.result_register
        self.unused: set[MLILVariable] = set()      # temporaries the pass leaves nothing referring to
        for block in func.basic_blocks:
            block.instructions = self.forwarded(block.instructions)
        live_out = self.live_out(func)
        for block in func.basic_blocks:
            block.instructions = self.retargeted(self.without_dead_stores(block.instructions, live_out[block]))
        for var in self.unused:
            del func.locals[var.name]
        return func

    # === The register ===

    def is_result_store(self, insts: list[MediumLevelILInstruction], index: int) -> bool:
        """insts[index] is the translator's REG[r] = t right after the call whose output t is"""
        inst = insts[index]
        if not (index and isinstance(inst, MLILStoreReg) and inst.index == self.register
                and isinstance(inst.value, MLILVar)):
            return False

        call = insts[index - 1]
        return isinstance(call, MediumLevelILCall) and call.output is not None and call.output == inst.value.var

    def reads(self, inst: MediumLevelILInstruction) -> bool:
        return any(isinstance(node, MLILLoadReg) and node.index == self.register
                   for operand in inst.operands() for node in walk(operand))

    def writes(self, inst: MediumLevelILInstruction) -> bool:
        if isinstance(inst, MLILStoreReg):
            return inst.index == self.register

        return isinstance(inst, MediumLevelILCall) and inst.clobbers_registers

    # === Reads forwarded ===

    def forwarded(self, insts: list[MediumLevelILInstruction]) -> list[MediumLevelILInstruction]:
        result = []
        temp = None

        def read_temp(node: MediumLevelILInstruction) -> MediumLevelILInstruction:
            if isinstance(node, MLILLoadReg) and node.index == self.register:
                return MLILVar(temp).copy_metadata_from(node)

            return map_operands(node, read_temp)

        for index, inst in enumerate(insts):
            store = self.is_result_store(insts, index)
            if temp is not None and not store:
                inst = map_operands(inst, read_temp)
            result.append(inst)
            if store:
                temp = inst.value.var
            elif self.writes(inst):
                temp = None

        return result

    # === Dead stores ===

    def live_out(self, func: MediumLevelILFunction) -> dict[MediumLevelILBasicBlock, bool]:
        """Whether the register is live where each block ends: some way on reads it before a write (a backward
        dataflow; a return reads it, a call writes it)"""
        reads_first, written = {}, {}
        for block in func.basic_blocks:
            reads_first[block] = written[block] = False
            for inst in block.instructions:
                if not written[block] and self.reads(inst):
                    reads_first[block] = True
                if self.writes(inst):
                    written[block] = True

        live_in = dict.fromkeys(func.basic_blocks, False)
        live_out = dict.fromkeys(func.basic_blocks, False)
        changed = True
        while changed:
            changed = False
            for block in reversed(func.basic_blocks):
                out = any(live_in[successor] for successor in block.outgoing_edges)
                into = reads_first[block] or (out and not written[block])
                if (out, into) != (live_out[block], live_in[block]):
                    live_out[block], live_in[block] = out, into
                    changed = True

        return live_out

    def without_dead_stores(self, insts: list[MediumLevelILInstruction],
                            live_out: bool) -> list[MediumLevelILInstruction]:
        """The dead result stores dropped; a call whose temporary nothing reads then gives no output, as SSA dead-code
        elimination clears an unread output"""
        kept = []
        calls = []
        for index, inst in enumerate(insts):
            if self.is_result_store(insts, index) and not self.live_after(insts, index, live_out):
                calls.append(insts[index - 1])
                continue
            kept.append(inst)

        reads = self.var_reads(kept)
        for call in calls:
            if not reads[call.output]:
                self.unused.add(call.output)
                call.output = None

        return kept

    def live_after(self, insts: list[MediumLevelILInstruction], index: int, live_out: bool) -> bool:
        for at in range(index + 1, len(insts)):         # no slice: a copy of the rest per store is quadratic
            if self.reads(insts[at]):
                return True
            if self.writes(insts[at]):
                return False

        return live_out

    # === The translator's copies ===

    def retargeted(self, insts: list[MediumLevelILInstruction]) -> list[MediumLevelILInstruction]:
        """t2 = t1 after t1 = f() (its result store, if kept, and line markers between) becomes t2 = f() when nothing
        else reads t1: one temporary written once instead of two. The reads are counted once: a retarget changes only
        its own two temporaries' counts, and no later call's output is one of them"""
        reads = self.var_reads(insts)
        copies = set()
        for index, call in enumerate(insts):
            if not isinstance(call, MediumLevelILCall) or call.output is None:
                continue

            store = index + 1 if index + 1 < len(insts) and self.is_result_store(insts, index + 1) else None
            at = (index if store is None else store) + 1
            while at < len(insts) and isinstance(insts[at], MLILDebug):
                at += 1
            own_reads = 1 if store is None else 2      # the copy's, the kept store's
            if not (self.is_copy(insts, at, call.output) and reads[call.output] == own_reads):
                continue

            temp, call.output = call.output, insts[at].var
            if store is not None:
                insts[store] = insts[store].rebuild(MLILVar(call.output).copy_metadata_from(insts[store].value))
            copies.add(at)
            self.unused.add(temp)

        return [inst for index, inst in enumerate(insts) if index not in copies]

    def is_copy(self, insts: list[MediumLevelILInstruction], at: int, temp: MLILVariable) -> bool:
        """insts[at] copies temp into a temporary of its own"""
        copy = insts[at] if at < len(insts) else None
        return (isinstance(copy, MLILSetVar) and isinstance(copy.value, MLILVar) and copy.value.var == temp
                and self.is_temporary(copy.var))

    def is_temporary(self, var: MLILVariable) -> bool:
        """A translator temporary: a local without a stack slot"""
        return var.slot_index == UNASSIGNED_SLOT_INDEX and var.name in self.func.locals

    @classmethod
    def var_reads(cls, insts: list[MediumLevelILInstruction]) -> Counter[MLILVariable]:
        """How often insts read each variable (a temporary is read only in its own block)"""
        return Counter(node.var for inst in insts for operand in inst.operands() for node in walk(operand)
                       if isinstance(node, MLILVar))
