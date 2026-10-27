"""Bitwise hex pass - a bitwise operation on a value prints its constant operand in hex (`arg3 & 0x00000800`,
`x & ~0x00000010`), and a union of single-bit flags there too (`x & (0x00000001 | 0x00000008)`); any other expression
made only of constants prints as written (`1 | 32768`, `x & (119 | 128)`). Only MLILConst.is_hex changes, and the HLIL
converter copies it, so .mlil.asm, .hlil.ts and .ts agree"""

from ir.pipeline import Pass
from ..mlil import (
    map_operands,
    walk,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
    MLILBinaryOp,
    MLILAnd,
    MLILOr,
    MLILXor,
    MLILShl,
    MLILShr,
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILTestZero,
)

BITWISE_OPS = (MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr)

# What a constant expression is made of: a dereference reads memory and an address names storage, so neither is one
CONSTANT_EXPRESSION_NODES = (MLILConst, MLILBinaryOp, MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILTestZero)


def is_constant_expression(expr: MediumLevelILInstruction) -> bool:
    return all(isinstance(node, CONSTANT_EXPRESSION_NODES) for node in walk(expr))


def is_single_bit(value) -> bool:
    return isinstance(value, int) and value > 0 and value & (value - 1) == 0


def is_flag_union(expr: MediumLevelILInstruction) -> bool:
    """A | of single-bit int constants (1 | 8): a bitwise enum's values"""
    if isinstance(expr, MLILOr):
        return is_flag_union(expr.lhs) and is_flag_union(expr.rhs)

    return isinstance(expr, MLILConst) and is_single_bit(expr.value)


def hex_operand(operand: MediumLevelILInstruction) -> MediumLevelILInstruction:
    """operand with its int constants marked hex: a constant, a union of single-bit flags, or either under ~"""
    if isinstance(operand, MLILConst) and isinstance(operand.value, int) and not operand.is_hex:
        return MLILConst(operand.value, is_hex=True).copy_metadata_from(operand)

    if isinstance(operand, MLILBitwiseNot) or (isinstance(operand, MLILOr) and is_flag_union(operand)):
        return map_operands(operand, hex_operand)

    return operand


class BitwiseHexPass(Pass):
    """Mark the constant operand of a bitwise operation whose other operand is not constant"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        for block in func.basic_blocks:
            block.instructions = [map_operands(inst, self._mark) for inst in block.instructions]

        return func

    def _mark(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        expr = map_operands(expr, self._mark)
        if not isinstance(expr, BITWISE_OPS):
            return expr

        lhs = expr.lhs if is_constant_expression(expr.rhs) else hex_operand(expr.lhs)
        rhs = expr.rhs if is_constant_expression(expr.lhs) else hex_operand(expr.rhs)
        if lhs is expr.lhs and rhs is expr.rhs:
            return expr

        return expr.rebuild(lhs, rhs)
