"""Condition Simplification Pass

Simplify conditionals:
- (expr == 0) → !expr
- (expr != 0) → expr
  (int 0 only: a jump truncates a Float, so 0.5 tests false while 0.5 != 0.0 holds)
- !(x == y) → x != y; an ordering keeps its NOT (negate_comparison)
"""

from ir.core import is_int_zero
from ir.pipeline import Pass
from ir.mlil.mlil import (
    COMPARISON_TYPES,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
    MLILLogicalNot,
    MLILEq,
    MLILNe,
    negate_comparison,
)
from ..mlil_ssa import MLILIf


class ConditionSimplificationPass(Pass):
    """Simplify conditional expressions"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Apply condition simplification"""
        for block in func.basic_blocks:
            for i, inst in enumerate(block.instructions):
                if not isinstance(inst, MLILIf):
                    continue

                new_condition = self._simplify_condition(inst.condition)
                if new_condition is not None:
                    simplified = MLILIf(new_condition, inst.true_target, inst.false_target)
                    block.instructions[i] = simplified.copy_metadata_from(inst)

        return func

    def _simplify_condition(self, condition: MediumLevelILInstruction) -> MediumLevelILInstruction | None:
        """The simpler condition, or None if there is none"""
        if isinstance(condition, MLILLogicalNot):
            return negate_comparison(condition.operand)

        if not (isinstance(condition, (MLILEq, MLILNe))
                and isinstance(condition.rhs, MLILConst) and is_int_zero(condition.rhs.value)):
            return None

        if isinstance(condition, MLILEq):
            inverted = negate_comparison(condition.lhs)
            return inverted if inverted is not None else MLILLogicalNot(condition.lhs)

        return condition.lhs if isinstance(condition.lhs, COMPARISON_TYPES) else None
