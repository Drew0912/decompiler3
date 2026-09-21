'''Expression Inlining Pass

Inline expressions that are only used once.
Pattern: x#n = expr; ... use(x#n) -> ... use(expr)
'''

from typing import Dict, List
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILBasicBlock,
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
    MLILCall,
    MLILSyscall,
    MLILCallScript,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILLoadReg,
    MLILLoadGlobal,
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


class ExpressionInliningPass(Pass):
    '''Inline single-use expressions'''

    def __init__(self):
        self.ssa_defs: Dict[MLILVariableSSA, MLILSetVarSSA] = {}
        self.ssa_uses: Dict[MLILVariableSSA, List[MediumLevelILInstruction]] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Inline single-use expressions'''
        changed = True

        while changed:
            self._build_def_use_chains(func)
            changed = self._inline_once(func)

        return func

    def _build_def_use_chains(self, func: MediumLevelILFunction):
        '''Build SSA def-use chains'''
        self.ssa_defs = {}
        self.ssa_uses = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    self.ssa_defs[inst.var] = inst

                elif isinstance(inst, MLILPhi):
                    self.ssa_defs[inst.dest] = inst

                self._collect_uses_in_inst(inst)

    def _collect_uses_in_inst(self, inst: MediumLevelILInstruction):
        '''Collect SSA variable uses in instruction'''
        if isinstance(inst, MLILVarSSA):
            if inst.var not in self.ssa_uses:
                self.ssa_uses[inst.var] = []
            self.ssa_uses[inst.var].append(inst)

        elif isinstance(inst, MLILSetVarSSA):
            self._collect_uses_in_expr(inst.value)

        elif isinstance(inst, MLILPhi):
            for source_var, _ in inst.sources:
                if source_var not in self.ssa_uses:
                    self.ssa_uses[source_var] = []
                self.ssa_uses[source_var].append(inst)

        elif isinstance(inst, MLILBinaryOp):
            self._collect_uses_in_expr(inst.lhs)
            self._collect_uses_in_expr(inst.rhs)

        elif isinstance(inst, MLILUnaryOp):
            self._collect_uses_in_expr(inst.operand)

        elif isinstance(inst, MLILIf):
            self._collect_uses_in_expr(inst.condition)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                self._collect_uses_in_expr(inst.value)

        elif isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
            for arg in inst.args:
                self._collect_uses_in_expr(arg)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            self._collect_uses_in_expr(inst.value)

        elif isinstance(inst, MLILStoreDeref):
            self._collect_uses_in_expr(inst.dest)
            self._collect_uses_in_expr(inst.value)

    def _collect_uses_in_expr(self, expr: MediumLevelILInstruction):
        self._collect_uses_in_inst(expr)

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

            # For expressions with side effects or impure reads,
            # only inline if use is immediately after def in same block
            if self._has_side_effects(defn.value) or self._is_impure_read(defn.value):
                if not self._is_immediate_use(func, defn, use):
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
        if isinstance(expr, (MLILCall, MLILSyscall, MLILCallScript)):
            return True

        if isinstance(expr, MLILBinaryOp):
            return self._has_side_effects(expr.lhs) or self._has_side_effects(expr.rhs)

        if isinstance(expr, MLILUnaryOp):
            return self._has_side_effects(expr.operand)

        return False

    def _is_impure_read(self, expr: MediumLevelILInstruction) -> bool:
        '''Check if expression reads from mutable storage (REG/GLOBAL/pointer target)'''
        if isinstance(expr, (MLILLoadReg, MLILLoadGlobal, MLILDeref)):
            return True

        if isinstance(expr, MLILBinaryOp):
            return self._is_impure_read(expr.lhs) or self._is_impure_read(expr.rhs)

        if isinstance(expr, MLILUnaryOp):
            return self._is_impure_read(expr.operand)

        return False

    def _is_immediate_use(self, func: MediumLevelILFunction,
                          defn: MLILSetVarSSA, use: MediumLevelILInstruction) -> bool:
        '''Check if use immediately follows definition in same block'''
        for block in func.basic_blocks:
            for i, inst in enumerate(block.instructions):
                if inst is defn:
                    if i + 1 < len(block.instructions):
                        return self._inst_contains(block.instructions[i + 1], use)
                    return False
        return False

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

        if isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
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

        elif isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
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
                return self._reconstruct_binary_op(expr, lhs, rhs)

        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILTestZero)):
            operand = self._inline_in_expr(expr.operand, inlinable)
            if operand is not expr.operand:
                return self._reconstruct_unary_op(expr, operand)

        elif isinstance(expr, MLILDeref):
            operand = self._inline_in_expr(expr.operand, inlinable)
            if operand is not expr.operand:
                return MLILDeref(operand)

        return expr

    def _reconstruct_binary_op(self, expr: MediumLevelILInstruction,
                               lhs: MediumLevelILInstruction,
                               rhs: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Reconstruct binary operation with new operands'''
        if isinstance(expr, MLILAdd):
            return MLILAdd(lhs, rhs)

        elif isinstance(expr, MLILSub):
            return MLILSub(lhs, rhs)

        elif isinstance(expr, MLILMul):
            return MLILMul(lhs, rhs)

        elif isinstance(expr, MLILDiv):
            return MLILDiv(lhs, rhs)

        elif isinstance(expr, MLILMod):
            return MLILMod(lhs, rhs)

        elif isinstance(expr, MLILAnd):
            return MLILAnd(lhs, rhs)

        elif isinstance(expr, MLILOr):
            return MLILOr(lhs, rhs)

        elif isinstance(expr, MLILXor):
            return MLILXor(lhs, rhs)

        elif isinstance(expr, MLILShl):
            return MLILShl(lhs, rhs)

        elif isinstance(expr, MLILShr):
            return MLILShr(lhs, rhs)

        elif isinstance(expr, MLILLogicalAnd):
            return MLILLogicalAnd(lhs, rhs)

        elif isinstance(expr, MLILLogicalOr):
            return MLILLogicalOr(lhs, rhs)

        elif isinstance(expr, MLILEq):
            return MLILEq(lhs, rhs)

        elif isinstance(expr, MLILNe):
            return MLILNe(lhs, rhs)

        elif isinstance(expr, MLILLt):
            return MLILLt(lhs, rhs)

        elif isinstance(expr, MLILLe):
            return MLILLe(lhs, rhs)

        elif isinstance(expr, MLILGt):
            return MLILGt(lhs, rhs)

        elif isinstance(expr, MLILGe):
            return MLILGe(lhs, rhs)

        else:
            raise NotImplementedError(f'Unhandled binary operation: {type(expr).__name__}')

    def _reconstruct_unary_op(self, expr: MediumLevelILInstruction,
                              operand: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Reconstruct unary operation with new operand'''
        if isinstance(expr, MLILNeg):
            return MLILNeg(operand)

        elif isinstance(expr, MLILLogicalNot):
            return MLILLogicalNot(operand)

        elif isinstance(expr, MLILBitwiseNot):
            return MLILBitwiseNot(operand)

        elif isinstance(expr, MLILTestZero):
            return MLILTestZero(operand)

        else:
            raise NotImplementedError(f'Unhandled unary operation: {type(expr).__name__}')
