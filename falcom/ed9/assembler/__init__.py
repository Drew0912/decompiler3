"""The ED9 instruction set: the opcode table and each instruction's stack effect"""

from .ed9_optable import ED9_INSTRUCTION_TABLE, ED9InstructionTable, ED9Opcode
from .stack_effects import InstructionKind

__all__ = (
    'ED9Opcode',
    'ED9InstructionTable',
    'ED9_INSTRUCTION_TABLE',
    'InstructionKind',
)
