'''Negation Normal Form (NNF) Pass

Push all NOT operators down to comparison leaves:
- !(!x) → x (double negation elimination)
- !(x == y) → x != y
- !(x && y) → !x || !y (De Morgan)
- !(x || y) → !x && !y (De Morgan)
'''

from typing import Optional
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
    MLILLogicalNot,
    MLILLogicalAnd,
    MLILLogicalOr,
    MLILTestZero,
    MLILEq,
    MLILNe,
    MLILLt,
    MLILLe,
    MLILGt,
    MLILGe,
)
from ..mlil_ssa import MLILSetVarSSA, MLILIf


class NNFPass(Pass):
    '''Negation Normal Form transformation pass'''

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Apply NNF transformation to the function'''
        # Single pass - outer optimizer loop handles iteration
        self._normalize_negations(func)
        return func

    def _normalize_negations(self, func: MediumLevelILFunction) -> bool:
        '''Single iteration of NNF transformation'''
        changed = False

        for block in func.basic_blocks:
            for i, inst in enumerate(block.instructions):
                new_inst = self._normalize_inst(inst)
                if new_inst is not inst:
                    block.instructions[i] = new_inst
                    changed = True

        return changed

    def _normalize_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Apply NNF to an instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._push_negation(inst.value, negated = False)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_cond = self._push_negation(inst.condition, negated = False)
            if new_cond is not inst.condition:
                return MLILIf(new_cond, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        return inst

    def _push_negation(self, expr: MediumLevelILInstruction, negated: bool) -> MediumLevelILInstruction:
        '''Recursively push negation down to leaves'''
        if isinstance(expr, MLILLogicalNot):
            # !x with negated → !!x → x (cancel out)
            # !x without negated → pass negation down
            return self._push_negation(expr.operand, not negated)

        elif isinstance(expr, MLILLogicalAnd):
            if negated:
                # !(a && b) → !a || !b (De Morgan)
                lhs = self._push_negation(expr.lhs, True)
                rhs = self._push_negation(expr.rhs, True)
                return MLILLogicalOr(lhs, rhs)

            else:
                lhs = self._push_negation(expr.lhs, False)
                rhs = self._push_negation(expr.rhs, False)
                if lhs is not expr.lhs or rhs is not expr.rhs:
                    return expr.rebuild(lhs, rhs)
                return expr

        elif isinstance(expr, MLILLogicalOr):
            if negated:
                # !(a || b) → !a && !b (De Morgan)
                lhs = self._push_negation(expr.lhs, True)
                rhs = self._push_negation(expr.rhs, True)
                return MLILLogicalAnd(lhs, rhs)

            else:
                lhs = self._push_negation(expr.lhs, False)
                rhs = self._push_negation(expr.rhs, False)
                if lhs is not expr.lhs or rhs is not expr.rhs:
                    return expr.rebuild(lhs, rhs)
                return expr

        elif isinstance(expr, MLILTestZero):
            # TestZero(x) = (x == 0)
            # !TestZero(x) = (x != 0)
            if negated:
                return MLILNe(expr.operand, MLILConst(0, is_hex = False))
            return expr

        elif isinstance(expr, (MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe)):
            if negated:
                return self._invert_comparison(expr)
            return expr

        else:
            # For other expressions, if negated, wrap with NOT
            if negated:
                return MLILLogicalNot(expr)
            return expr

    def _invert_comparison(self, expr: MediumLevelILInstruction) -> Optional[MediumLevelILInstruction]:
        '''Invert comparison: >= → <, > → <=, == → !=, etc.'''
        if isinstance(expr, MLILGe):
            return MLILLt(expr.lhs, expr.rhs)

        elif isinstance(expr, MLILGt):
            return MLILLe(expr.lhs, expr.rhs)

        elif isinstance(expr, MLILLt):
            return MLILGe(expr.lhs, expr.rhs)

        elif isinstance(expr, MLILLe):
            return MLILGt(expr.lhs, expr.rhs)

        elif isinstance(expr, MLILEq):
            return MLILNe(expr.lhs, expr.rhs)

        elif isinstance(expr, MLILNe):
            return MLILEq(expr.lhs, expr.rhs)

        else:
            return None
