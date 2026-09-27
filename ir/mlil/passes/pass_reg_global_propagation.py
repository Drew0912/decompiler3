'''REG/GLOBAL value propagation pass'''

from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ir.core import constant_values_equal
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MediumLevelILInstruction,
    MLILConst, MLILVar, MLILBinaryOp, MLILUnaryOp, MLILSetVar,
    MLILIf, MLILRet, MLILCall, MLILSyscall, MLILCallScript,
    MLILLoadGlobal, MLILStoreGlobal, MLILLoadReg, MLILStoreReg,
    MLILDeref, MLILStoreDeref,
)


class StorageKind(Enum):
    '''Kind of storage location'''
    REG = auto()
    GLOBAL = auto()


@dataclass(frozen = True)
class StorageKey:
    '''Key for cycle detection in substitute'''
    kind: StorageKind
    index: int


@dataclass
class RegGlobalState:
    '''State for REG/GLOBAL value tracking'''
    reg: Dict[int, Optional[MediumLevelILInstruction]] = field(default_factory = dict)
    global_: Dict[int, Optional[MediumLevelILInstruction]] = field(default_factory = dict)

    def copy(self) -> 'RegGlobalState':
        return RegGlobalState(
            reg = dict(self.reg),
            global_ = dict(self.global_)
        )


class RegGlobalValuePropagator:
    '''Propagate values through REG/GLOBAL storage'''

    def __init__(self, func: MediumLevelILFunction):
        self.func = func

    def run(self) -> bool:
        '''Run propagation and return True if any changes made'''
        if not self.func.basic_blocks:
            return False

        block_in_states = self._analyze()
        return self._transform(block_in_states)

    def _analyze(self) -> Dict[MediumLevelILBasicBlock, RegGlobalState]:
        '''Phase 1: Dataflow analysis'''
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
        '''Phase 2: Transform instructions'''
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
        '''Merge states from predecessors'''
        if not pred_states:
            return RegGlobalState()

        if len(pred_states) == 1:
            return pred_states[0].copy()

        result = RegGlobalState()

        # Merge reg
        all_reg_keys: Set[int] = set()
        for s in pred_states:
            all_reg_keys.update(s.reg.keys())

        for key in all_reg_keys:
            values = [s.reg.get(key) for s in pred_states]
            if all(v is not None for v in values) and self._all_expr_equal(values):
                result.reg[key] = values[0]

            else:
                result.reg[key] = None

        # Merge global_
        all_global_keys: Set[int] = set()
        for s in pred_states:
            all_global_keys.update(s.global_.keys())

        for key in all_global_keys:
            values = [s.global_.get(key) for s in pred_states]
            if all(v is not None for v in values) and self._all_expr_equal(values):
                result.global_[key] = values[0]

            else:
                result.global_[key] = None

        return result

    def _simulate_block(self, block: MediumLevelILBasicBlock,
                        in_state: RegGlobalState) -> RegGlobalState:
        '''Simulate block execution to compute out_state'''
        state = in_state.copy()

        for inst in block.instructions:
            state = self._simulate_inst(inst, state)

        return state

    def _simulate_inst(self, inst: MediumLevelILInstruction,
                       state: RegGlobalState) -> RegGlobalState:
        '''Simulate single instruction'''
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

        elif isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
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
        '''Transform instruction and update state'''
        if isinstance(inst, MLILStoreReg):
            new_value = self._substitute(inst.value, state)
            new_state = state.copy()
            new_state.reg[inst.index] = new_value if self._is_closed_form(new_value) else None

            if new_value is not inst.value:
                new_inst = MLILStoreReg(inst.index, new_value)
                self._copy_metadata(inst, new_inst)
                return (new_inst, new_state)

            return (inst, new_state)

        elif isinstance(inst, MLILStoreGlobal):
            new_value = self._substitute(inst.value, state)
            new_state = state.copy()
            new_state.global_[inst.index] = new_value if self._is_closed_form(new_value) else None

            if new_value is not inst.value:
                new_inst = MLILStoreGlobal(inst.index, new_value)
                self._copy_metadata(inst, new_inst)
                return (new_inst, new_state)

            return (inst, new_state)

        elif isinstance(inst, MLILStoreDeref):
            # Dereference stores cannot affect closed-form cached values.
            new_dest = self._substitute(inst.dest, state)
            new_value = self._substitute(inst.value, state)

            if new_dest is not inst.dest or new_value is not inst.value:
                return (inst.rebuild(new_dest, new_value), state)

            return (inst, state)

        elif isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
            new_args = [self._substitute(arg, state) for arg in inst.args]
            new_state = state.copy()
            for k in new_state.reg:
                new_state.reg[k] = None
            for k in new_state.global_:
                new_state.global_[k] = None

            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                new_inst = self._rebuild_call(inst, new_args)
                self._copy_metadata(inst, new_inst)
                return (new_inst, new_state)

            return (inst, new_state)

        elif isinstance(inst, MLILSetVar):
            new_value = self._substitute(inst.value, state)

            if new_value is not inst.value:
                new_inst = MLILSetVar(inst.var, new_value)
                self._copy_metadata(inst, new_inst)
                return (new_inst, state)

            return (inst, state)

        elif isinstance(inst, MLILIf):
            new_cond = self._substitute(inst.condition, state)

            if new_cond is not inst.condition:
                new_inst = MLILIf(new_cond, inst.true_target, inst.false_target)
                self._copy_metadata(inst, new_inst)
                return (new_inst, state)

            return (inst, state)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._substitute(inst.value, state)

                if new_value is not inst.value:
                    new_inst = MLILRet(new_value)
                    self._copy_metadata(inst, new_inst)
                    return (new_inst, state)

            return (inst, state)

        else:
            return (inst, state)

    def _substitute(self, expr: MediumLevelILInstruction, state: RegGlobalState,
                    path: FrozenSet[StorageKey] = frozenset()) -> MediumLevelILInstruction:
        '''Substitute LoadReg/LoadGlobal with known values'''
        if isinstance(expr, MLILLoadReg):
            key = StorageKey(StorageKind.REG, expr.index)
            if key in path:
                return expr
            value = state.reg.get(expr.index)
            if value is not None:
                return self._substitute(value, state, path | {key})
            return expr

        elif isinstance(expr, MLILLoadGlobal):
            key = StorageKey(StorageKind.GLOBAL, expr.index)
            if key in path:
                return expr
            value = state.global_.get(expr.index)
            if value is not None:
                return self._substitute(value, state, path | {key})
            return expr

        elif isinstance(expr, MLILBinaryOp):
            new_lhs = self._substitute(expr.lhs, state, path)
            new_rhs = self._substitute(expr.rhs, state, path)

            if new_lhs is not expr.lhs or new_rhs is not expr.rhs:
                return expr.rebuild(new_lhs, new_rhs)

            return expr

        elif isinstance(expr, MLILUnaryOp):
            new_operand = self._substitute(expr.operand, state, path)

            if new_operand is not expr.operand:
                return expr.rebuild(new_operand)

            return expr

        elif isinstance(expr, (MLILConst, MLILVar)):
            return expr

        else:
            return expr

    def _is_closed_form(self, expr: MediumLevelILInstruction) -> bool:
        '''Return whether expr is a constant expression with no mutable inputs.'''
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
        '''Check if two states are equal'''
        if s1.reg.keys() != s2.reg.keys():
            return False

        if s1.global_.keys() != s2.global_.keys():
            return False

        for k in s1.reg:
            if not self._expr_equal(s1.reg[k], s2.reg[k]):
                return False

        for k in s1.global_:
            if not self._expr_equal(s1.global_[k], s2.global_[k]):
                return False

        return True

    def _all_expr_equal(self, values: List[Optional[MediumLevelILInstruction]]) -> bool:
        '''Check if all values are equal'''
        if len(values) <= 1:
            return True

        first = values[0]
        return all(self._expr_equal(first, v) for v in values[1:])

    def _expr_equal(self, a: Optional[MediumLevelILInstruction],
                    b: Optional[MediumLevelILInstruction]) -> bool:
        '''Check if two expressions are equal'''
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

        elif isinstance(a, MLILLoadReg):
            return a.index == b.index

        elif isinstance(a, MLILLoadGlobal):
            return a.index == b.index

        elif isinstance(a, MLILBinaryOp):
            return (a.operation == b.operation and
                    self._expr_equal(a.lhs, b.lhs) and
                    self._expr_equal(a.rhs, b.rhs))

        elif isinstance(a, MLILUnaryOp):
            return (a.operation == b.operation and
                    self._expr_equal(a.operand, b.operand))

        else:
            return False

    def _copy_metadata(self, src: MediumLevelILInstruction,
                       dst: MediumLevelILInstruction) -> None:
        '''Copy metadata from source to destination instruction'''
        dst.copy_metadata_from(src)

    def _rebuild_call(self, inst: MediumLevelILInstruction,
                      new_args: List[MediumLevelILInstruction]) -> MediumLevelILInstruction:
        '''Rebuild call instruction with new arguments'''
        return inst.rebuild(new_args)


class RegGlobalValuePropagationPass(Pass):
    '''Propagate values through REG/GLOBAL storage'''

    def run(self, mlil_func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Run REG/GLOBAL value propagation'''
        propagator = RegGlobalValuePropagator(mlil_func)
        propagator.run()
        return mlil_func
