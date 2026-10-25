"""LLIL Formatter - the .llil.asm listing and the .llil.dot graph"""

from ir.core import CFGDotFormatter
from .llil import *


class LLILFormatter(CFGDotFormatter):
    """Formatting layer for beautiful output"""

    DOT_IF     = LowLevelILIf
    DOT_GOTO   = LowLevelILJmp
    DOT_RETURN = LowLevelILRet

    # Map operation to expression template
    __expr_templates = {
        LowLevelILOperation.LLIL_ADD            : '{lhs} + {rhs}',
        LowLevelILOperation.LLIL_SUB            : '{lhs} - {rhs}',
        LowLevelILOperation.LLIL_MUL            : '{lhs} * {rhs}',
        LowLevelILOperation.LLIL_DIV            : '{lhs} / {rhs}',
        LowLevelILOperation.LLIL_MOD            : '{lhs} % {rhs}',
        LowLevelILOperation.LLIL_EQ             : '({lhs} == {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_NE             : '({lhs} != {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_LT             : '({lhs} < {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_LE             : '({lhs} <= {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_GT             : '({lhs} > {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_GE             : '({lhs} >= {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_AND            : '{lhs} & {rhs}',
        LowLevelILOperation.LLIL_OR             : '{lhs} | {rhs}',
        LowLevelILOperation.LLIL_LOGICAL_AND    : '({lhs} && {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_LOGICAL_OR     : '({lhs} || {rhs}) ? 1 : 0',

        LowLevelILOperation.LLIL_NEG            : '-{operand}',
        LowLevelILOperation.LLIL_BITWISE_NOT    : '~{operand}',
        LowLevelILOperation.LLIL_TEST_ZERO      : '({operand} == 0) ? 1 : 0',
    }

    @classmethod
    def _format_binary_op_expanded(cls, binary_op: LowLevelILBinaryOp) -> list[str]:
        """Format binary operation with expanded pseudo-code"""
        template = cls.__expr_templates[binary_op.operation]
        expr = template.format(lhs='lhs', rhs='rhs')
        return [
            f'rhs = STACK[--sp]  ; {binary_op.rhs}',
            f'lhs = STACK[--sp]  ; {binary_op.lhs}',
            f'STACK[sp++] = {expr}',
        ]

    @classmethod
    def _format_unary_op_expanded(cls, unary_op: LowLevelILUnaryOp) -> list[str]:
        """Format unary operation with expanded pseudo-code"""
        template = cls.__expr_templates[unary_op.operation]
        expr = template.format(operand='operand')
        return [
            f'operand = STACK[--sp]  ; {unary_op.operand}',
            f'STACK[sp++] = {expr}',
        ]

    @classmethod
    def _format_simplified(cls, inst: LowLevelILInstruction) -> list[str]:
        """One line: the instruction's own text; a stack store / load also shows its slot"""
        if isinstance(inst, (LowLevelILStackStore, LowLevelILStackLoad)):
            return [f'{inst} ; [{inst.slot_index}]']

        return [str(inst)]

    @classmethod
    def format_instruction_expanded(cls, inst: LowLevelILInstruction) -> list[str] | None:
        """A binary or unary operation, pushed or bare, as its pops, its computation and its push; None for any other
        instruction"""
        operation = inst.value if isinstance(inst, LowLevelILStackStore) and inst.offset == 0 else inst
        if isinstance(operation, LowLevelILBinaryOp):
            return cls._format_binary_op_expanded(operation)

        if isinstance(operation, LowLevelILUnaryOp):
            return cls._format_unary_op_expanded(operation)

        return None

    @classmethod
    def format_instruction_sequence(cls, instructions: list[LowLevelILInstruction], indent: str = '  ') -> list[str]:
        """Format sequence of instructions - returns list of lines"""
        result = []

        for inst in instructions:
            # Skip instructions marked as hidden for formatter
            if inst.options.hidden_for_formatter:
                continue

            if result and isinstance(inst, LowLevelILDebug):
                result.append('')

            lines = cls.format_instruction_expanded(inst) or cls._format_simplified(inst)
            result.extend(indent + line for line in lines)

        return result

    @classmethod
    def format_llil_function(cls, func: LowLevelILFunction) -> list[str]:
        """Format entire LLIL function with beautiful output - returns list of lines"""
        result = [
            f'; ---------- {func.name} ----------',
        ]

        for block in func.basic_blocks:
            result.append(cls._block_header(func, block, address_spec='04X'))
            result.extend(cls.format_instruction_sequence(block.instructions))
            result.append('')

        return result

    @classmethod
    def _block_header(cls, func: LowLevelILFunction, block: LowLevelILBasicBlock, address_spec: str) -> str:
        """block_N(0xADDR), label, [sp = N]; the entry block also shows fp: [sp = N, fp = M]"""
        if block.index == 0 and func.frame_base_sp is not None:
            stack = f'[sp = {block.sp_in}, fp = {func.frame_base_sp}]'
        else:
            stack = f'[sp = {block.sp_in}]'

        return f'block_{block.index}(0x{block.start:{address_spec}}), {block.label}, {stack}'

    @classmethod
    def _dot_header(cls, func: LowLevelILFunction, block: LowLevelILBasicBlock) -> str:
        return cls._block_header(func, block, address_spec='X')

    @classmethod
    def _dot_lines(cls, block: LowLevelILBasicBlock) -> list[str]:
        """The listing's lines, unindented"""
        return cls.format_instruction_sequence(block.instructions, '')
