'''Copy Propagation Pass

Replace SSA variable copies (x#1 = x#0 -> use x#0).
'''

from typing import Dict, List
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
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
    MLILRet,
    MLILCall,
    MLILSyscall,
    MLILCallScript,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILDeref,
    MLILStoreDeref,
)
from ..mlil_ssa import (
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILIf,
)


class CopyPropagationPass(Pass):
    '''Replace SSA variable copies with original variables'''

    def __init__(self):
        self.ssa_defs: Dict[MLILVariableSSA, MLILSetVarSSA] = {}
        self.use_counts: Dict[MLILVariableSSA, int] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Propagate copies through the function'''
        self._build_def_chains(func)
        changed = True

        while changed:
            self._count_uses(func)
            changed = self._propagate_once(func)

        return func

    def _build_def_chains(self, func: MediumLevelILFunction):
        '''Build SSA definition chains'''
        self.ssa_defs = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    self.ssa_defs[inst.var] = inst

                elif isinstance(inst, MLILPhi):
                    self.ssa_defs[inst.dest] = inst

    def _count_uses(self, func: MediumLevelILFunction):
        '''Count reads of every SSA variable'''
        self.use_counts = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                for var in self._collect_uses(inst):
                    self.use_counts[var] = self.use_counts.get(var, 0) + 1

    def _collect_uses(self, node: MediumLevelILInstruction) -> List[MLILVariableSSA]:
        '''SSA variables read by an instruction or expression'''
        if isinstance(node, MLILVarSSA):
            return [node.var]

        if isinstance(node, MLILPhi):
            return [source_var for source_var, _ in node.sources]

        if isinstance(node, MLILSetVarSSA):
            return self._collect_uses(node.value)

        if isinstance(node, (MLILStoreGlobal, MLILStoreReg)):
            return self._collect_uses(node.value)

        if isinstance(node, MLILStoreDeref):
            return self._collect_uses(node.dest) + self._collect_uses(node.value)

        if isinstance(node, MLILDeref):
            return self._collect_uses(node.operand)

        if isinstance(node, MLILIf):
            return self._collect_uses(node.condition)

        if isinstance(node, MLILRet):
            return self._collect_uses(node.value) if node.value is not None else []

        if isinstance(node, (MLILCall, MLILSyscall, MLILCallScript)):
            uses = []
            for arg in node.args:
                uses.extend(self._collect_uses(arg))
            return uses

        if isinstance(node, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod,
                             MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr,
                             MLILLogicalAnd, MLILLogicalOr,
                             MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe)):
            return self._collect_uses(node.lhs) + self._collect_uses(node.rhs)

        if isinstance(node, (MLILNeg, MLILLogicalNot, MLILBitwiseNot)):
            return self._collect_uses(node.operand)

        return []

    def _propagate_once(self, func: MediumLevelILFunction) -> bool:
        '''Single copy propagation pass'''
        # Build copy map
        copies: Dict[MLILVariableSSA, MLILVariableSSA] = {}
        for ssa_var, defn in self.ssa_defs.items():
            if isinstance(defn, MLILSetVarSSA):
                if isinstance(defn.value, MLILVarSSA):
                    # A local read more than once keeps its own name rather than the
                    # register's/global's, so reg0/global0 does not spread over values that have a
                    # real variable. With a single read there is nothing to spread.
                    if func.is_register_var(defn.value.var.base_var) or func.is_global_var(defn.value.var.base_var):
                        if self.use_counts.get(ssa_var, 0) > 1:
                            continue

                    copies[ssa_var] = defn.value.var

        if not copies:
            return False

        changed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = self._replace_in_inst(inst, copies)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _replace_in_inst(self, inst: MediumLevelILInstruction,
                         copies: Dict[MLILVariableSSA, MLILVariableSSA]) -> MediumLevelILInstruction:
        '''Replace copy variables in instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._replace_in_expr(inst.value, copies)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_condition = self._replace_in_expr(inst.condition, copies)
            if new_condition is not inst.condition:
                return MLILIf(new_condition, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._replace_in_expr(inst.value, copies)
                if new_value is not inst.value:
                    return MLILRet(new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
            new_args = [self._replace_in_expr(arg, copies) for arg in inst.args]
            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                return inst.rebuild(new_args)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._replace_in_expr(inst.value, copies)
            if new_value is not inst.value:
                if isinstance(inst, MLILStoreGlobal):
                    return MLILStoreGlobal(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

                return MLILStoreReg(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._replace_in_expr(inst.dest, copies)
            new_value = self._replace_in_expr(inst.value, copies)
            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _replace_in_expr(self, expr: MediumLevelILInstruction,
                         copies: Dict[MLILVariableSSA, MLILVariableSSA]) -> MediumLevelILInstruction:
        '''Replace copy variables in expression'''
        if isinstance(expr, MLILVarSSA):
            if expr.var in copies:
                return MLILVarSSA(copies[expr.var])

        elif isinstance(expr, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod,
                               MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr,
                               MLILLogicalAnd, MLILLogicalOr,
                               MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe)):
            lhs = self._replace_in_expr(expr.lhs, copies)
            rhs = self._replace_in_expr(expr.rhs, copies)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return self._reconstruct_binary_op(expr, lhs, rhs)

        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot)):
            operand = self._replace_in_expr(expr.operand, copies)
            if operand is not expr.operand:
                return self._reconstruct_unary_op(expr, operand)

        elif isinstance(expr, MLILDeref):
            # Unlike MLILAddressOf (whose operand is a location, never substitutable), a
            # pointer's VALUE is an ordinary operand - propagating a value-equal copy into it
            # is safe and desirable.
            operand = self._replace_in_expr(expr.operand, copies)
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

        else:
            raise NotImplementedError(f'Unhandled unary operation: {type(expr).__name__}')
