"""Expression Simplification Pass

Apply algebraic simplifications:
- x + 0 → x
- x * 1 → x
- x * 0 → 0
- x & 0 → 0
- x | 0 → x
- x & -1 → x
- x | -1 → -1
etc.

Identities fire only on plain int constants (is_plain_int)
"""

from ir.core import is_plain_int
from ir.pipeline import Pass
from ir.mlil.mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
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
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILRet,
    MLILDeref,
    MLILStoreDeref,
)
from ..mlil_ssa import MLILSetVarSSA, MLILIf

ALL_BITS_SET = -1   # every bit set at any int width (Python's -1), what SCCP folds ~0 to


class ExpressionSimplificationPass(Pass):
    """Apply algebraic simplifications"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Apply simplification to all instructions"""
        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = self._simplify_expr_in_inst(inst)
                new_instructions.append(new_inst)

            block.instructions = new_instructions

        return func

    def _simplify_expr_in_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        """Simplify expressions in a single instruction"""
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._simplify_expr(inst.value)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value).copy_metadata_from(inst)
        elif isinstance(inst, MLILIf):
            new_condition = self._simplify_expr(inst.condition)
            if new_condition is not inst.condition:
                return MLILIf(new_condition, inst.true_target, inst.false_target).copy_metadata_from(inst)
        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._simplify_expr(inst.value)
                if new_value is not inst.value:
                    return MLILRet(new_value).copy_metadata_from(inst)
        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._simplify_expr(inst.dest)
            new_value = self._simplify_expr(inst.value)
            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _simplify_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        """Recursively apply algebraic simplifications"""
        if isinstance(expr, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod,
                             MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr)):
            lhs = self._simplify_expr(expr.lhs)
            rhs = self._simplify_expr(expr.rhs)

            simplified = self._apply_algebraic_identity(type(expr), lhs, rhs)
            if simplified is not None:
                return simplified

            if lhs is not expr.lhs or rhs is not expr.rhs:
                return expr.rebuild(lhs, rhs)
        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILDeref)):
            operand = self._simplify_expr(expr.operand)
            if operand is not expr.operand:
                return expr.rebuild(operand)

        return expr

    def _apply_algebraic_identity(self, op_type, lhs, rhs) -> MediumLevelILInstruction | None:
        """Apply algebraic identity rules"""
        # Plain int constants only: x * 0.0 is a Float, not int 0, and can be -0.0 or NaN; a string or a frontend's own
        # int takes the VM's arithmetic (SCCP doesn't fold them either)
        if any(isinstance(operand, MLILConst) and not is_plain_int(operand.value) for operand in (lhs, rhs)):
            return None

        if op_type == MLILAdd:
            if isinstance(rhs, MLILConst) and rhs.value == 0:
                return lhs

            if isinstance(lhs, MLILConst) and lhs.value == 0:
                return rhs
        elif op_type == MLILSub:
            if isinstance(rhs, MLILConst) and rhs.value == 0:
                return lhs
        elif op_type == MLILMul:
            if isinstance(rhs, MLILConst):
                if rhs.value == 0:
                    return MLILConst(0, is_hex=False)
                elif rhs.value == 1:
                    return lhs

            if isinstance(lhs, MLILConst):
                if lhs.value == 0:
                    return MLILConst(0, is_hex=False)
                elif lhs.value == 1:
                    return rhs
        elif op_type == MLILDiv:
            if isinstance(rhs, MLILConst) and rhs.value == 1:
                return lhs
        elif op_type == MLILAnd:
            if isinstance(rhs, MLILConst):
                if rhs.value == 0:
                    return MLILConst(0, is_hex=False)
                elif rhs.value == ALL_BITS_SET:
                    return lhs

            if isinstance(lhs, MLILConst):
                if lhs.value == 0:
                    return MLILConst(0, is_hex=False)
                elif lhs.value == ALL_BITS_SET:
                    return rhs
        elif op_type == MLILOr:
            if isinstance(rhs, MLILConst):
                if rhs.value == 0:
                    return lhs
                elif rhs.value == ALL_BITS_SET:
                    return rhs

            if isinstance(lhs, MLILConst):
                if lhs.value == 0:
                    return rhs
                elif lhs.value == ALL_BITS_SET:
                    return lhs
        elif op_type == MLILXor:
            if isinstance(rhs, MLILConst) and rhs.value == 0:
                return lhs

            if isinstance(lhs, MLILConst) and lhs.value == 0:
                return rhs
        elif op_type in (MLILShl, MLILShr):
            if isinstance(rhs, MLILConst) and rhs.value == 0:
                return lhs

        return None
