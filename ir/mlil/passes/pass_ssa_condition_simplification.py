'''Condition Simplification Pass

Simplify conditionals:
- (expr == 0) → !expr
- (expr != 0) → expr
  (int 0 only: a float's truth in the VM is unverified)
- !comparison → inverted comparison
'''

from typing import Optional
from ir.core import is_int_zero
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
    MLILLogicalNot,
    MLILEq,
    MLILNe,
    MLILLt,
    MLILLe,
    MLILGt,
    MLILGe,
)
from ..mlil_ssa import MLILIf


class ConditionSimplificationPass(Pass):
    '''Simplify conditional expressions'''

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Apply condition simplification'''
        for block in func.basic_blocks:
            for i, inst in enumerate(block.instructions):
                if not isinstance(inst, MLILIf):
                    continue

                condition = inst.condition
                new_condition = None

                if isinstance(condition, MLILLogicalNot):
                    inverted = self._invert_comparison(condition.operand)
                    if inverted is not None:
                        new_condition = inverted

                elif isinstance(condition, MLILEq):
                    if isinstance(condition.rhs, MLILConst) and is_int_zero(condition.rhs.value):
                        inverted = self._invert_comparison(condition.lhs)
                        if inverted is not None:
                            new_condition = inverted

                        else:
                            new_condition = MLILLogicalNot(condition.lhs)

                elif isinstance(condition, MLILNe):
                    if isinstance(condition.rhs, MLILConst) and is_int_zero(condition.rhs.value):
                        if isinstance(condition.lhs, (MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe)):
                            new_condition = condition.lhs

                if new_condition is not None:
                    block.instructions[i] = MLILIf(new_condition, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        return func

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
