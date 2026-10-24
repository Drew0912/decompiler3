"""LLIL Formatter - the .llil.asm listing and the .llil.dot graph"""

from typing import List, Optional

from .llil import *


class LLILFormatter:
    """Formatting layer for beautiful output"""

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
    def _format_binary_op_expanded(cls, binary_op: LowLevelILBinaryOp) -> List[str]:
        """Format binary operation with expanded pseudo-code"""
        template = cls.__expr_templates[binary_op.operation]
        expr = template.format(lhs='lhs', rhs='rhs')
        return [
            f'rhs = STACK[--sp]  ; {binary_op.rhs}',
            f'lhs = STACK[--sp]  ; {binary_op.lhs}',
            f'STACK[sp++] = {expr}',
        ]

    @classmethod
    def _format_unary_op_expanded(cls, unary_op: 'LowLevelILUnaryOp') -> List[str]:
        """Format unary operation with expanded pseudo-code"""
        template = cls.__expr_templates[unary_op.operation]
        expr = template.format(operand='operand')
        return [
            f'operand = STACK[--sp]  ; {unary_op.operand}',
            f'STACK[sp++] = {expr}',
        ]

    @classmethod
    def _format_simplified(cls, inst: LowLevelILInstruction) -> List[str]:
        """One line: the instruction's own text; a stack store / load also shows its slot"""
        if isinstance(inst, (LowLevelILStackStore, LowLevelILStackLoad)):
            return [f'{inst} ; [{inst.slot_index}]']

        return [str(inst)]

    @classmethod
    def format_instruction_expanded(cls, inst: LowLevelILInstruction) -> Optional[List[str]]:
        """A binary or unary operation, pushed or bare, as its pops, its computation and its push; None for any other
        instruction"""
        operation = inst.value if isinstance(inst, LowLevelILStackStore) and inst.offset == 0 else inst
        if isinstance(operation, LowLevelILBinaryOp):
            return cls._format_binary_op_expanded(operation)

        if isinstance(operation, LowLevelILUnaryOp):
            return cls._format_unary_op_expanded(operation)

        return None

    @classmethod
    def format_instruction_sequence(cls, instructions: List[LowLevelILInstruction], indent: str = '  ') -> list[str]:
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
            # Block header: {block_N}(addr), label, [sp = N, fp = M]

            block_info = [
                f'block_{block.index}(0x{block.start:04X})',
                block.label,
            ]

            # Show sp and fp (fp only on first block)
            if block.index == 0 and func.frame_base_sp is not None:
                block_info.append(f'[sp = {block.sp_in}, fp = {func.frame_base_sp}]')
            else:
                block_info.append(f'[sp = {block.sp_in}]')

            result.append(', '.join(block_info))
            result.extend(cls.format_instruction_sequence(block.instructions))
            result.append('')

        return result

    @classmethod
    def to_dot(cls, func: LowLevelILFunction) -> str:
        """Generate Graphviz DOT format for CFG visualization"""
        lines = []
        lines.append(f'digraph "{func.name}" {{')
        lines.append('    rankdir=TB;')
        lines.append('    node [shape=box, fontname="Courier New", fontsize=10];')
        lines.append('    edge [fontname="Courier New", fontsize=9];')
        lines.append('')

        # Add nodes (basic blocks)
        for block in func.basic_blocks:
            label_parts = []

            # Block header: block_N(0xADDR), label, [sp = N, fp = M]
            # Use same format as format_llil_function
            header_parts = [
                f'block_{block.index}(0x{block.start:X})',
                block.label,
            ]

            # Show sp and fp (fp only on first block)
            if block.index == 0 and func.frame_base_sp is not None:
                header_parts.append(f'[sp = {block.sp_in}, fp = {func.frame_base_sp}]')
            else:
                header_parts.append(f'[sp = {block.sp_in}]')

            header = ', '.join(header_parts) + '\\l'
            label_parts.append(header)
            label_parts.append('-' * 40 + '\\l')

            # Format instructions using expand format (same as format_llil_function)
            formatted_lines = cls.format_instruction_sequence(block.instructions, '')
            for line in formatted_lines:
                # Escape for DOT format
                escaped = line.replace('\\', '\\\\').replace('"', '\\"')
                label_parts.append(escaped + '\\l')

            label = ''.join(label_parts)

            # Node styling
            if block.index == 0:
                # Entry block
                lines.append(f'    {block.block_name} [label="{label}", style=filled, fillcolor=lightgreen];')
            elif block.has_terminal and isinstance(block.instructions[-1], LowLevelILRet):
                # Exit block
                lines.append(f'    {block.block_name} [label="{label}", style=filled, fillcolor=lightblue];')
            else:
                lines.append(f'    {block.block_name} [label="{label}"];')

        lines.append('')

        # Add edges
        for block in func.basic_blocks:
            if not block.outgoing_edges:
                continue

            last_inst = block.instructions[-1] if block.instructions else None

            for target in block.outgoing_edges:
                # Determine edge label and style
                edge_label = ''
                edge_style = ''

                if isinstance(last_inst, LowLevelILIf):
                    # Conditional branch
                    if target == last_inst.true_target:
                        edge_label = 'true'
                        edge_style = ', color=green'
                    elif last_inst.false_target and target == last_inst.false_target:
                        edge_label = 'false'
                        edge_style = ', color=red'
                    else:
                        edge_label = 'fall-through'
                        edge_style = ', style=dashed'
                elif isinstance(last_inst, LowLevelILJmp):
                    edge_label = 'goto'
                    edge_style = ', color=blue'
                else:
                    # Fall-through
                    edge_label = 'fall-through'
                    edge_style = ', style=dashed'

                if edge_label:
                    lines.append(f'    {block.block_name} -> {target.block_name} [label="{edge_label}"{edge_style}];')
                else:
                    lines.append(f'    {block.block_name} -> {target.block_name}{edge_style};')

        lines.append('}')
        return '\n'.join(lines)
