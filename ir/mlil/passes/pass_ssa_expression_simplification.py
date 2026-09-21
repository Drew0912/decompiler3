'''Expression Simplification Pass

Apply algebraic simplifications:
- x + 0 → x
- x * 1 → x
- x * 0 → 0
- x & 0 → 0
- x | 0 → x
etc.
'''

from typing import Optional
from ir.pipeline import Pass
from ..mlil import (
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
    MLILLogicalAnd,
    MLILLogicalOr,
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILTestZero,
    MLILEq,
    MLILNe,
    MLILLt,
    MLILLe,
    MLILGt,
    MLILGe,
    MLILRet,
    MLILDeref,
    MLILStoreDeref,
)
from ..mlil_ssa import MLILSetVarSSA, MLILIf


class ExpressionSimplificationPass(Pass):
    '''Apply algebraic simplifications'''

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Apply simplification to all instructions'''
        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = self._simplify_expr_in_inst(inst)
                new_instructions.append(new_inst)

            block.instructions = new_instructions

        return func

    def _simplify_expr_in_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Simplify expressions in a single instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._simplify_expr(inst.value)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_condition = self._simplify_expr(inst.condition)
            if new_condition is not inst.condition:
                return MLILIf(new_condition, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._simplify_expr(inst.value)
                if new_value is not inst.value:
                    return MLILRet(new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._simplify_expr(inst.dest)
            new_value = self._simplify_expr(inst.value)
            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _simplify_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Recursively apply algebraic simplifications'''
        if isinstance(expr, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod,
                             MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr)):
            lhs = self._simplify_expr(expr.lhs)
            rhs = self._simplify_expr(expr.rhs)

            simplified = self._apply_algebraic_identity(type(expr), lhs, rhs)
            if simplified is not None:
                return simplified

            if lhs is not expr.lhs or rhs is not expr.rhs:
                return self._reconstruct_binary_op(expr, lhs, rhs)

        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILDeref)):
            operand = self._simplify_expr(expr.operand)
            if operand is not expr.operand:
                return self._reconstruct_unary_op(expr, operand)

        return expr

    def _apply_algebraic_identity(self, op_type, lhs, rhs) -> Optional[MediumLevelILInstruction]:
        '''Apply algebraic identity rules'''
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
                    return MLILConst(0, is_hex = False)

                elif rhs.value == 1:
                    return lhs

            if isinstance(lhs, MLILConst):
                if lhs.value == 0:
                    return MLILConst(0, is_hex = False)

                elif lhs.value == 1:
                    return rhs

        elif op_type == MLILDiv:
            if isinstance(rhs, MLILConst) and rhs.value == 1:
                return lhs

        elif op_type == MLILAnd:
            if isinstance(rhs, MLILConst):
                if rhs.value == 0:
                    return MLILConst(0, is_hex = False)

                elif rhs.value == 0xFFFFFFFF:
                    return lhs

            if isinstance(lhs, MLILConst):
                if lhs.value == 0:
                    return MLILConst(0, is_hex = False)

                elif lhs.value == 0xFFFFFFFF:
                    return rhs

        elif op_type == MLILOr:
            if isinstance(rhs, MLILConst):
                if rhs.value == 0:
                    return lhs

                elif rhs.value == 0xFFFFFFFF:
                    return MLILConst(0xFFFFFFFF, is_hex = True)

            if isinstance(lhs, MLILConst):
                if lhs.value == 0:
                    return rhs

                elif lhs.value == 0xFFFFFFFF:
                    return MLILConst(0xFFFFFFFF, is_hex = True)

        elif op_type == MLILXor:
            if isinstance(rhs, MLILConst) and rhs.value == 0:
                return lhs

            if isinstance(lhs, MLILConst) and lhs.value == 0:
                return rhs

        elif op_type in (MLILShl, MLILShr):
            if isinstance(rhs, MLILConst) and rhs.value == 0:
                return lhs

        return None

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

        elif isinstance(expr, MLILDeref):
            return MLILDeref(operand)

        else:
            raise NotImplementedError(f'Unhandled unary operation: {type(expr).__name__}')
