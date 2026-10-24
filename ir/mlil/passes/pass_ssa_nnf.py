"""Negation Normal Form (NNF) Pass

Push all NOT operators down to comparison leaves:
- !(!x) → x (double negation elimination)
- !(x == y) → x != y
- !(x && y) → !x || !y (De Morgan)
- !(x || y) → !x && !y (De Morgan)
"""

from ir.pipeline import Pass
from ..mlil import (
    COMPARISON_TYPES,
    DE_MORGAN,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
    MLILLogicalNot,
    MLILLogicalAnd,
    MLILLogicalOr,
    MLILTestZero,
    MLILNe,
    negate_comparison,
)
from ..mlil_ssa import MLILSetVarSSA, MLILIf


class NNFPass(Pass):
    """Negation Normal Form transformation pass"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Apply NNF transformation to the function"""
        # Single pass - outer optimizer loop handles iteration
        for block in func.basic_blocks:
            for i, inst in enumerate(block.instructions):
                block.instructions[i] = self._normalize_inst(inst)

        return func

    def _normalize_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        """Apply NNF to an instruction"""
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._push_negation(inst.value, negated=False)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value).copy_metadata_from(inst)
        elif isinstance(inst, MLILIf):
            new_cond = self._push_negation(inst.condition, negated=False)
            if new_cond is not inst.condition:
                return MLILIf(new_cond, inst.true_target, inst.false_target).copy_metadata_from(inst)

        return inst

    def _push_negation(self, expr: MediumLevelILInstruction, negated: bool) -> MediumLevelILInstruction:
        """Recursively push negation down to leaves"""
        if isinstance(expr, MLILLogicalNot):
            # !x with negated → !!x → x (cancel out)
            # !x without negated → pass negation down
            return self._push_negation(expr.operand, not negated)
        elif isinstance(expr, (MLILLogicalAnd, MLILLogicalOr)):
            lhs = self._push_negation(expr.lhs, negated)
            rhs = self._push_negation(expr.rhs, negated)
            if negated:
                # De Morgan: !(a && b) → !a || !b, !(a || b) → !a && !b
                return DE_MORGAN[type(expr)](lhs, rhs)

            if lhs is not expr.lhs or rhs is not expr.rhs:
                return expr.rebuild(lhs, rhs)

            return expr
        elif not negated:
            return expr
        elif isinstance(expr, MLILTestZero):
            # !TestZero(x) = (x != 0)
            return MLILNe(expr.operand, MLILConst(0, is_hex=False))
        elif isinstance(expr, COMPARISON_TYPES):
            return negate_comparison(expr)

        # Any other negated expression is wrapped with NOT
        return MLILLogicalNot(expr)
