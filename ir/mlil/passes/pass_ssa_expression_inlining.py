'''Expression Inlining Pass

Inline expressions that are only used once.
Pattern: x#n = expr; ... use(x#n) -> ... use(expr)
'''

from typing import Dict, List, Optional, Tuple
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
    MLILConst,
    MLILBinaryOp,
    MLILUnaryOp,
    MLILAdd,
    MLILSub,
    MLILMul,
    MLILDiv,
    MLILMod,
    MLILAnd,
    MLILOr,
    MLILXor,
    MLILShl,
    MLILShr,
    MLILLogicalAnd,
    MLILLogicalOr,
    MLILEq,
    MLILNe,
    MLILLt,
    MLILLe,
    MLILGt,
    MLILGe,
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILTestZero,
    MLILRet,
    MediumLevelILCall,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILLoadGlobal,
    MLILLoadReg,
    MLILDeref,
    MLILStoreDeref,
)
from ..mlil_ssa import (
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILIf,
    MLILUndef,
)
from .pass_ssa_copy_propagation import reaches_without_redefinition


class ExpressionInliningPass(Pass):
    '''Inline single-use expressions'''

    def __init__(self):
        self.ssa_defs: Dict[MLILVariableSSA, MLILSetVarSSA] = {}
        self.def_positions: Dict[MLILVariableSSA, Tuple[MediumLevelILBasicBlock, int]] = {}
        self.ssa_uses: Dict[MLILVariableSSA, List[MediumLevelILInstruction]] = {}
        self.use_positions: Dict[MLILVariableSSA, List[Tuple[MediumLevelILBasicBlock, int]]] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Inline single-use expressions'''
        changed = True

        while changed:
            self._build_def_use_chains(func)
            changed = self._inline_once(func)

        return func

    def _build_def_use_chains(self, func: MediumLevelILFunction):
        '''Build SSA def-use chains, tracking each def's and use's (block, index) position'''
        self.ssa_defs = {}
        self.def_positions = {}
        self.ssa_uses = {}
        self.use_positions = {}

        for block in func.basic_blocks:
            for idx, inst in enumerate(block.instructions):
                if isinstance(inst, MLILSetVarSSA):
                    self.ssa_defs[inst.var] = inst
                    self.def_positions[inst.var] = (block, idx)

                elif isinstance(inst, MLILPhi):
                    self.ssa_defs[inst.dest] = inst
                    self.def_positions[inst.dest] = (block, idx)

                self._collect_uses_in_inst(inst, block, idx)

    def _record_use(self, var: MLILVariableSSA, use: MediumLevelILInstruction,
                    block: MediumLevelILBasicBlock, idx: int):
        self.ssa_uses.setdefault(var, []).append(use)
        self.use_positions.setdefault(var, []).append((block, idx))

    def _collect_uses_in_inst(self, inst: MediumLevelILInstruction,
                              block: MediumLevelILBasicBlock, idx: int):
        '''Collect SSA variable uses in a top-level instruction, at its own position'''
        if isinstance(inst, MLILVarSSA):
            self._record_use(inst.var, inst, block, idx)

        elif isinstance(inst, MLILSetVarSSA):
            self._collect_uses_in_expr(inst.value, block, idx)

        elif isinstance(inst, MLILPhi):
            for source_var, _ in inst.sources:
                self._record_use(source_var, inst, block, idx)

        elif isinstance(inst, MLILBinaryOp):
            self._collect_uses_in_expr(inst.lhs, block, idx)
            self._collect_uses_in_expr(inst.rhs, block, idx)

        elif isinstance(inst, MLILUnaryOp):
            self._collect_uses_in_expr(inst.operand, block, idx)

        elif isinstance(inst, MLILIf):
            self._collect_uses_in_expr(inst.condition, block, idx)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                self._collect_uses_in_expr(inst.value, block, idx)

        elif isinstance(inst, MediumLevelILCall):
            for arg in inst.args:
                self._collect_uses_in_expr(arg, block, idx)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            self._collect_uses_in_expr(inst.value, block, idx)

        elif isinstance(inst, MLILStoreDeref):
            self._collect_uses_in_expr(inst.dest, block, idx)
            self._collect_uses_in_expr(inst.value, block, idx)

    def _collect_uses_in_expr(self, expr: MediumLevelILInstruction,
                              block: MediumLevelILBasicBlock, idx: int):
        self._collect_uses_in_inst(expr, block, idx)

    def _inline_once(self, func: MediumLevelILFunction) -> bool:
        '''Single inlining pass'''
        inlinable: Dict[MLILVariableSSA, MediumLevelILInstruction] = {}

        for ssa_var, defn in self.ssa_defs.items():
            if not isinstance(defn, MLILSetVarSSA):
                continue

            # Skip var-to-var copies (handled by CopyPropagation)
            if isinstance(defn.value, MLILVarSSA):
                continue

            # Skip constants (handled by ConstantPropagation)
            if isinstance(defn.value, MLILConst):
                continue

            # Undefined values mark a variable a call may have written; inlining one
            # would turn a real read into <undef>
            if isinstance(defn.value, MLILUndef):
                continue

            uses = self.ssa_uses.get(ssa_var, [])
            if len(uses) != 1:
                continue

            use = uses[0]

            # Skip if used in Phi (may require duplication across branches)
            if isinstance(use, MLILPhi):
                continue

            def_pos = self.def_positions.get(ssa_var)
            use_pos = self.use_positions.get(ssa_var, [None])[0]

            if self._has_side_effects(defn.value):
                # A call's own side effect must not move relative to anything else in the
                # function, not just the specific storage an impure read cares about - keep
                # the strict adjacency requirement for this case.
                if def_pos is None or use_pos is None or not self._is_immediate_use(def_pos, use_pos, use):
                    continue

            elif self._is_impure_read(defn.value, func):
                if def_pos is None or use_pos is None:
                    continue

                storages = self._impure_read_storages(defn.value, func)

                if not storages:
                    # None means a deref is present somewhere (no trackable storage to check
                    # reachability against). An empty list should not happen when
                    # _is_impure_read was true - _impure_read_storages mirrors its dispatch -
                    # but treat that the same defensively rather than assume the invariant.
                    # Either way, fall back to the original strict "must be the immediately
                    # next instruction" requirement instead of refusing to inline at all.
                    if not self._is_immediate_use(def_pos, use_pos, use):
                        continue

                else:
                    def_block, def_idx = def_pos
                    use_block, use_idx = use_pos
                    if not all(
                        reaches_without_redefinition(func, storage, def_block, def_idx, use_block, use_idx)
                        for storage in storages
                    ):
                        continue

            inlinable[ssa_var] = defn.value

        if not inlinable:
            return False

        changed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = self._inline_in_inst(inst, inlinable)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _has_side_effects(self, expr: MediumLevelILInstruction) -> bool:
        '''Check if expression has side effects'''
        if isinstance(expr, MediumLevelILCall):
            return True

        if isinstance(expr, MLILBinaryOp):
            return self._has_side_effects(expr.lhs) or self._has_side_effects(expr.rhs)

        if isinstance(expr, MLILUnaryOp):
            return self._has_side_effects(expr.operand)

        return False

    def _is_impure_read(self, expr: MediumLevelILInstruction, func: MediumLevelILFunction) -> bool:
        '''Check if expression reads from mutable storage (register/global/pointer target)

        In SSA form, a STORED register/global's read is an ordinary MLILVarSSA wrapping a
        register/global-kind base variable - MLILLoadReg/MLILLoadGlobal are normally the
        pre-SSA and post-de-SSA node shapes only. But a global that is only ever READ in this
        function (never stored) is never raised into a variable at all (mlil_ssa.py's
        _raise_globals leaves it alone), so its MLILLoadGlobal survives unchanged into SSA
        form - it must still be treated as impure here, the same as MLILDeref, since it has
        no SSA version for reaches_without_redefinition to track.
        '''
        if isinstance(expr, MLILVarSSA):
            return func.is_register_var(expr.var.base_var) or func.is_global_var(expr.var.base_var)

        if isinstance(expr, (MLILLoadReg, MLILLoadGlobal, MLILDeref)):
            return True

        if isinstance(expr, MLILBinaryOp):
            return self._is_impure_read(expr.lhs, func) or self._is_impure_read(expr.rhs, func)

        if isinstance(expr, MLILUnaryOp):
            return self._is_impure_read(expr.operand, func)

        return False

    def _impure_read_storages(self, expr: MediumLevelILInstruction, func: MediumLevelILFunction) -> Optional[List]:
        '''Every distinct register/global base variable an impure expression reads (e.g.
        `reg0 + global3` reads two, both need their own reachability check - a hazard on
        either one alone makes forwarding this expression unsafe).

        Returns None (not an empty list) if the expression contains an MLILDeref anywhere -
        checked before the generic MLILUnaryOp case, since MLILDeref subclasses it - or a
        surviving MLILLoadReg/MLILLoadGlobal (an unraised, read-only global; see
        _is_impure_read). None of these have an SSA base variable this reachability check can
        track, so each poisons the whole expression as unsafe for this relaxed check, the same
        way one untrackable term in a sum can't be dropped without losing its hazard.
        '''
        if isinstance(expr, (MLILLoadReg, MLILLoadGlobal, MLILDeref)):
            return None

        if isinstance(expr, MLILVarSSA):
            if func.is_register_var(expr.var.base_var) or func.is_global_var(expr.var.base_var):
                return [expr.var.base_var]

            return []

        if isinstance(expr, MLILBinaryOp):
            lhs = self._impure_read_storages(expr.lhs, func)
            rhs = self._impure_read_storages(expr.rhs, func)
            if lhs is None or rhs is None:
                return None

            return lhs + rhs

        if isinstance(expr, MLILUnaryOp):
            return self._impure_read_storages(expr.operand, func)

        return []

    def _is_immediate_use(self, def_pos: Tuple[MediumLevelILBasicBlock, int],
                          use_pos: Tuple[MediumLevelILBasicBlock, int],
                          use: MediumLevelILInstruction) -> bool:
        '''Check if use immediately follows definition in the same block'''
        def_block, def_idx = def_pos
        use_block, use_idx = use_pos

        if def_block is not use_block or use_idx != def_idx + 1:
            return False

        return self._inst_contains(def_block.instructions[def_idx + 1], use)

    def _inst_contains(self, inst: MediumLevelILInstruction, target: MediumLevelILInstruction) -> bool:
        '''Check if inst is or contains target'''
        if inst is target:
            return True

        if isinstance(inst, MLILSetVarSSA):
            return self._expr_contains(inst.value, target)

        if isinstance(inst, MLILIf):
            return self._expr_contains(inst.condition, target)

        if isinstance(inst, MLILRet):
            return inst.value is not None and self._expr_contains(inst.value, target)

        if isinstance(inst, MediumLevelILCall):
            return any(self._expr_contains(arg, target) for arg in inst.args)

        if isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            return self._expr_contains(inst.value, target)

        if isinstance(inst, MLILStoreDeref):
            return self._expr_contains(inst.dest, target) or self._expr_contains(inst.value, target)

        return False

    def _expr_contains(self, expr: MediumLevelILInstruction, target: MediumLevelILInstruction) -> bool:
        '''Check if expr is or contains target'''
        if expr is target:
            return True

        if isinstance(expr, MLILBinaryOp):
            return self._expr_contains(expr.lhs, target) or self._expr_contains(expr.rhs, target)

        if isinstance(expr, MLILUnaryOp):
            return self._expr_contains(expr.operand, target)

        return False

    def _inline_in_inst(self, inst: MediumLevelILInstruction,
                        inlinable: Dict[MLILVariableSSA, MediumLevelILInstruction]) -> MediumLevelILInstruction:
        '''Inline expressions in instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._inline_in_expr(inst.value, inlinable)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_condition = self._inline_in_expr(inst.condition, inlinable)
            if new_condition is not inst.condition:
                return MLILIf(new_condition, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._inline_in_expr(inst.value, inlinable)
                if new_value is not inst.value:
                    return MLILRet(new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MediumLevelILCall):
            new_args = [self._inline_in_expr(arg, inlinable) for arg in inst.args]
            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                return inst.rebuild(new_args)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._inline_in_expr(inst.value, inlinable)
            if new_value is not inst.value:
                if isinstance(inst, MLILStoreGlobal):
                    return MLILStoreGlobal(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

                else:
                    return MLILStoreReg(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._inline_in_expr(inst.dest, inlinable)
            new_value = self._inline_in_expr(inst.value, inlinable)
            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _inline_in_expr(self, expr: MediumLevelILInstruction,
                        inlinable: Dict[MLILVariableSSA, MediumLevelILInstruction]) -> MediumLevelILInstruction:
        '''Inline single-use expressions'''
        if isinstance(expr, MLILVarSSA):
            if expr.var in inlinable:
                return inlinable[expr.var]

        elif isinstance(expr, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod,
                               MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr,
                               MLILLogicalAnd, MLILLogicalOr,
                               MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe)):
            lhs = self._inline_in_expr(expr.lhs, inlinable)
            rhs = self._inline_in_expr(expr.rhs, inlinable)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return expr.rebuild(lhs, rhs)

        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILTestZero, MLILDeref)):
            operand = self._inline_in_expr(expr.operand, inlinable)
            if operand is not expr.operand:
                return expr.rebuild(operand)

        return expr
