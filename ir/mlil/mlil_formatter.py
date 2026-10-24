"""MLIL Formatter - Format MLIL for display"""

from typing import List

from .mlil import *


class MLILFormatter:
    """Format MLIL functions for display"""

    @classmethod
    def format_function(cls, func: MediumLevelILFunction) -> List[str]:
        result = [
            f'; ===== MLIL Function {func.name} @ 0x{func.start_addr:X} =====',
            f'; Parameters: {len([p for p in func.parameters if p])}, Locals: {len(func.locals)}',
        ]

        # List parameters
        if func.parameters:
            result.append(';')
            result.append('; Parameters:')
            for param in func.parameters:
                if param:
                    result.append(f';   {param.name}')

        # List local variables
        if func.locals:
            result.append(';')
            result.append('; Locals:')
            for var_name in sorted(func.locals.keys()):
                var = func.locals[var_name]
                if var.slot_index != UNASSIGNED_SLOT_INDEX:
                    result.append(f';   {var.name} (slot {var.slot_index})')
                else:
                    result.append(f';   {var.name}')

        # List inferred types (if available)
        if func.var_types:
            result.append(';')
            result.append('; Inferred Types:')
            for var_name in sorted(func.var_types.keys()):
                typ = func.var_types[var_name]
                result.append(f';   {var_name}: {typ}')

        result.append('')

        # Format each block
        for block in func.basic_blocks:
            result.extend(cls.format_block(block))
            result.append('')

        return result

    @classmethod
    def format_block(cls, block: MediumLevelILBasicBlock) -> List[str]:
        result = [f'{block.label}:']

        for inst in block.instructions:
            formatted = cls.format_instruction(inst)
            result.append(f'  {formatted}')

        return result

    @classmethod
    def format_instruction(cls, inst: MediumLevelILInstruction) -> str:
        """Format a single instruction: its own str(), except a script call and a debug record"""
        if isinstance(inst, MLILCallScript):
            return f'{inst}  ; MLILCallScript'
        elif isinstance(inst, MLILDebug):
            return f'; {inst}'

        return str(inst)

    @classmethod
    def to_dot(cls, func: MediumLevelILFunction) -> str:
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

            # Block header
            header = f'{block.label} @ 0x{block.start:X}\\l'
            label_parts.append(header)
            label_parts.append('-' * 40 + '\\l')

            # Format instructions
            for inst in block.instructions:
                formatted = cls.format_instruction(inst)
                escaped = formatted.replace('\\', '\\\\').replace('"', '\\"')
                label_parts.append(escaped + '\\l')

            label = ''.join(label_parts)

            # Node styling
            if block.index == 0:
                # Entry block
                lines.append(f'    {block.block_name} [label="{label}", style=filled, fillcolor=lightgreen];')
            elif block.has_terminal and isinstance(block.instructions[-1], MLILRet):
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

                if isinstance(last_inst, MLILIf):
                    # Conditional branch
                    if target == last_inst.true_target:
                        edge_label = 'true'
                        edge_style = ', color=green'
                    elif target == last_inst.false_target:
                        edge_label = 'false'
                        edge_style = ', color=red'
                elif isinstance(last_inst, MLILGoto):
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
