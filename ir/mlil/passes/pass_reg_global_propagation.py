"""REG/GLOBAL value propagation pass"""

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ir.core import constant_values_equal
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MediumLevelILInstruction,
    MLILConst, MLILVar, MLILBinaryOp, MLILUnaryOp, MLILSetVar,
    MLILIf, MLILRet, MediumLevelILCall,
    MLILLoadGlobal, MLILStoreGlobal, MLILLoadReg, MLILStoreReg,
    MLILDeref, MLILStoreDeref,
)


# Each tracked slot (a register or global index) -> its closed-form value, or None once unknown
SlotValues = Dict[int, Optional[MediumLevelILInstruction]]


@dataclass
class RegGlobalState:
    """State for REG/GLOBAL value tracking"""

    reg: SlotValues = field(default_factory=dict)
    global_: SlotValues = field(default_factory=dict)

    def copy(self) -> 'RegGlobalState':
        return RegGlobalState(
            reg=dict(self.reg),
            global_=dict(self.global_)
        )


class RegGlobalValuePropagator:
    """Propagate values through REG/GLOBAL storage"""

    def __init__(self, func: MediumLevelILFunction):
        self.func = func

    def run(self) -> bool:
        """Run propagation and return True if any changes made"""
        if not self.func.basic_blocks:
            return False

        block_in_states = self._analyze()
        return self._transform(block_in_states)

    def _analyze(self) -> Dict[MediumLevelILBasicBlock, RegGlobalState]:
        """Phase 1: Dataflow analysis"""
        block_in: Dict[MediumLevelILBasicBlock, RegGlobalState] = {}
        block_out: Dict[MediumLevelILBasicBlock, RegGlobalState] = {}

        entry = self.func.basic_blocks[0]
        block_in[entry] = RegGlobalState()

        worklist: deque = deque([entry])
        in_worklist: Set[MediumLevelILBasicBlock] = {entry}

        while worklist:
            block = worklist.popleft()
            in_worklist.discard(block)

            # Compute in_state
            if block is entry:
                in_state = RegGlobalState()
            elif block.incoming_edges:
                pred_outs = [block_out[p] for p in block.incoming_edges if p in block_out]
                in_state = self._merge_states(pred_outs) if pred_outs else RegGlobalState()
            else:
                in_state = RegGlobalState()

            # Simulate block execution
            out_state = self._simulate_block(block, in_state)

            # Retain the latest input even when the block's output is already stable.
            block_in[block] = in_state

            # Check if out_state changed - only this decides whether successors need revisiting
            if block not in block_out or not self._state_equal(block_out[block], out_state):
                block_out[block] = out_state

                for succ in block.outgoing_edges:
                    if succ not in in_worklist:
                        worklist.append(succ)
                        in_worklist.add(succ)

        return block_in

    def _transform(self, block_in_states: Dict[MediumLevelILBasicBlock, RegGlobalState]) -> bool:
        """Phase 2: Transform instructions"""
        changed = False

        for block in self.func.basic_blocks:
            in_state = block_in_states.get(block, RegGlobalState())
            state = in_state.copy()
            new_instructions = []

            for inst in block.instructions:
                new_inst, state = self._transform_inst(inst, state)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _merge_states(self, pred_states: List[RegGlobalState]) -> RegGlobalState:
        """Merge states from predecessors"""
        return RegGlobalState(reg=self._merge_slots([s.reg for s in pred_states]),
                              global_=self._merge_slots([s.global_ for s in pred_states]))

    def _merge_slots(self, pred_slots: List[SlotValues]) -> SlotValues:
        """One kind of slot merged: a slot keeps its value only where every predecessor holds the same one"""
        merged = {}
        for key in set().union(*pred_slots):
            values = [slots.get(key) for slots in pred_slots]
            known = all(v is not None for v in values) and self._all_expr_equal(values)
            merged[key] = values[0] if known else None

        return merged

    def _simulate_block(self, block: MediumLevelILBasicBlock,
                        in_state: RegGlobalState) -> RegGlobalState:
        """Simulate block execution to compute out_state"""
        state = in_state.copy()

        for inst in block.instructions:
            state = self._simulate_inst(inst, state)

        return state

    def _simulate_inst(self, inst: MediumLevelILInstruction,
                       state: RegGlobalState) -> RegGlobalState:
        """Simulate single instruction"""
        if isinstance(inst, MLILStoreReg):
            resolved = self._substitute(inst.value, state)
            new_state = state.copy()
            new_state.reg[inst.index] = resolved if self._is_closed_form(resolved) else None
            return new_state
        elif isinstance(inst, MLILStoreGlobal):
            resolved = self._substitute(inst.value, state)
            new_state = state.copy()
            new_state.global_[inst.index] = resolved if self._is_closed_form(resolved) else None
            return new_state
        elif isinstance(inst, MediumLevelILCall):
            new_state = state.copy()
            for k in new_state.reg:
                new_state.reg[k] = None
            for k in new_state.global_:
                new_state.global_[k] = None
            return new_state
        else:
            return state

    def _transform_inst(self, inst: MediumLevelILInstruction,
                        state: RegGlobalState) -> Tuple[MediumLevelILInstruction, RegGlobalState]:
        """Transform instruction and update state"""
        if isinstance(inst, MLILStoreReg):
            new_value = self._substitute(inst.value, state)
            new_state = state.copy()
            new_state.reg[inst.index] = new_value if self._is_closed_form(new_value) else None

            if new_value is not inst.value:
                return (MLILStoreReg(inst.index, new_value).copy_metadata_from(inst), new_state)

            return (inst, new_state)
        elif isinstance(inst, MLILStoreGlobal):
            new_value = self._substitute(inst.value, state)
            new_state = state.copy()
            new_state.global_[inst.index] = new_value if self._is_closed_form(new_value) else None

            if new_value is not inst.value:
                return (MLILStoreGlobal(inst.index, new_value).copy_metadata_from(inst), new_state)

            return (inst, new_state)
        elif isinstance(inst, MLILStoreDeref):
            # Dereference stores cannot affect closed-form cached values.
            new_dest = self._substitute(inst.dest, state)
            new_value = self._substitute(inst.value, state)

            if new_dest is not inst.dest or new_value is not inst.value:
                return (inst.rebuild(new_dest, new_value), state)

            return (inst, state)
        elif isinstance(inst, MediumLevelILCall):
            new_args = [self._substitute(arg, state) for arg in inst.args]
            new_state = state.copy()
            for k in new_state.reg:
                new_state.reg[k] = None
            for k in new_state.global_:
                new_state.global_[k] = None

            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                return (inst.rebuild(new_args), new_state)

            return (inst, new_state)
        elif isinstance(inst, MLILSetVar):
            new_value = self._substitute(inst.value, state)

            if new_value is not inst.value:
                return (MLILSetVar(inst.var, new_value).copy_metadata_from(inst), state)

            return (inst, state)
        elif isinstance(inst, MLILIf):
            new_cond = self._substitute(inst.condition, state)

            if new_cond is not inst.condition:
                return (MLILIf(new_cond, inst.true_target, inst.false_target).copy_metadata_from(inst), state)

            return (inst, state)
        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._substitute(inst.value, state)

                if new_value is not inst.value:
                    return (MLILRet(new_value).copy_metadata_from(inst), state)

            return (inst, state)
        else:
            return (inst, state)

    def _substitute(self, expr: MediumLevelILInstruction, state: RegGlobalState) -> MediumLevelILInstruction:
        """Substitute LoadReg/LoadGlobal with known values (closed forms: they hold no load of their own)"""
        if isinstance(expr, MLILLoadReg):
            known = state.reg.get(expr.index)
            return expr if known is None else known
        elif isinstance(expr, MLILLoadGlobal):
            known = state.global_.get(expr.index)
            return expr if known is None else known
        elif isinstance(expr, MLILBinaryOp):
            new_lhs = self._substitute(expr.lhs, state)
            new_rhs = self._substitute(expr.rhs, state)

            if new_lhs is not expr.lhs or new_rhs is not expr.rhs:
                return expr.rebuild(new_lhs, new_rhs)
        elif isinstance(expr, MLILUnaryOp):
            new_operand = self._substitute(expr.operand, state)

            if new_operand is not expr.operand:
                return expr.rebuild(new_operand)

        return expr

    def _is_closed_form(self, expr: MediumLevelILInstruction) -> bool:
        """Return whether expr is a constant expression with no mutable inputs."""
        if isinstance(expr, MLILConst):
            return True
        elif isinstance(expr, MLILDeref):
            return False
        elif isinstance(expr, MLILBinaryOp):
            return self._is_closed_form(expr.lhs) and self._is_closed_form(expr.rhs)
        elif isinstance(expr, MLILUnaryOp):
            return self._is_closed_form(expr.operand)
        else:
            return False

    def _state_equal(self, s1: RegGlobalState, s2: RegGlobalState) -> bool:
        """Check if two states are equal"""
        return (s1.reg.keys() == s2.reg.keys() and s1.global_.keys() == s2.global_.keys()
                and all(self._expr_equal(s1.reg[k], s2.reg[k]) for k in s1.reg)
                and all(self._expr_equal(s1.global_[k], s2.global_[k]) for k in s1.global_))

    def _all_expr_equal(self, values: List[Optional[MediumLevelILInstruction]]) -> bool:
        """Check if all values are equal"""
        return all(self._expr_equal(values[0], v) for v in values[1:])

    def _expr_equal(self, a: Optional[MediumLevelILInstruction],
                    b: Optional[MediumLevelILInstruction]) -> bool:
        """Check if two expressions are equal"""
        if a is None and b is None:
            return True

        if a is None or b is None:
            return False

        if type(a) != type(b):
            return False

        if isinstance(a, MLILConst):
            # NaN reflexive, so a NaN constant doesn't count as a change on every fixpoint pass
            return constant_values_equal(a.value, b.value)
        elif isinstance(a, MLILVar):
            return a.var.name == b.var.name
        elif isinstance(a, (MLILLoadReg, MLILLoadGlobal)):
            return a.index == b.index
        elif isinstance(a, (MLILBinaryOp, MLILUnaryOp)):
            # The same type is the same operation: each op subclass fixes its own
            return all(self._expr_equal(x, y) for x, y in zip(a.operands(), b.operands()))
        else:
            return False


class RegGlobalValuePropagationPass(Pass):
    """Propagate values through REG/GLOBAL storage"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Run REG/GLOBAL value propagation"""
        propagator = RegGlobalValuePropagator(func)
        propagator.run()
        return func
