"""MLIL Formatter - Format MLIL for display"""

from ir.core import CFGDotFormatter
from .mlil import *


class MLILFormatter(CFGDotFormatter):
    """Format MLIL functions for display"""

    DOT_IF     = MLILIf
    DOT_GOTO   = MLILGoto
    DOT_RETURN = MLILRet

    @classmethod
    def format_function(cls, func: MediumLevelILFunction) -> list[str]:
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
    def format_block(cls, block: MediumLevelILBasicBlock) -> list[str]:
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
    def _dot_header(cls, func: MediumLevelILFunction, block: MediumLevelILBasicBlock) -> str:
        return f'{block.label} @ 0x{block.start:X}'

    @classmethod
    def _dot_lines(cls, block: MediumLevelILBasicBlock) -> list[str]:
        return [cls.format_instruction(inst) for inst in block.instructions]
