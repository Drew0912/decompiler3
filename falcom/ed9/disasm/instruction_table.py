"""Instruction table interface and descriptor"""

from common import *
from abc import ABC, abstractmethod
from dataclasses import dataclass
from .basic_block import BranchKind
from typing import TYPE_CHECKING, Any
from .instruction import Instruction

if TYPE_CHECKING:
    from .instruction import Operand
    from .formatter import FormatterContext


class OperandType(IntEnum2):
    """Operand types"""
    Empty       = 0
    SInt8       = 1
    SInt16      = 2
    SInt32      = 3
    UInt8       = 4
    UInt16      = 5
    UInt32      = 6
    Float32     = 7
    String      = 8
    Offset      = 9
    UserDefined = 100

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class OperandFormat:
    """Operand format descriptor"""
    size_table: dict[OperandType, int] = {
        OperandType.SInt8   : 1,
        OperandType.SInt16  : 2,
        OperandType.SInt32  : 4,
        OperandType.UInt8   : 1,
        OperandType.UInt16  : 2,
        OperandType.UInt32  : 4,
        OperandType.Float32 : 4,
        OperandType.String  : None,
        OperandType.Offset  : 4,
    }

    def __init__(self, opr_type: OperandType, is_hex: bool = False):
        self.type   = opr_type
        self.is_hex = is_hex

    def __str__(self):
        return repr(self.type)

    def __repr__(self):
        return self.__str__()

    @property
    def size(self):
        return self.size_table.get(self.type)


class OperandDescriptor:
    """Operand descriptor with read/write/format methods"""
    format_table: dict[str, 'OperandDescriptor'] = {}

    @classmethod
    def from_format_string(cls, fmtstr: str, format_table: dict | None = None) -> tuple['OperandDescriptor', ...]:
        format_table = format_table if format_table else cls.format_table
        return tuple(format_table[f] for f in fmtstr)

    def __init__(self, format: OperandFormat):
        self.format = format

    @property
    def type(self) -> OperandType:
        return self.format.type

    def read_value(self, fs: 'fileio.FileStream') -> Any:
        """Read operand value from file stream"""
        return {
            OperandType.SInt8   : lambda: fs.ReadChar(),
            OperandType.SInt16  : lambda: fs.ReadShort(),
            OperandType.SInt32  : lambda: fs.ReadLong(),
            OperandType.UInt8   : lambda: fs.ReadByte(),
            OperandType.UInt16  : lambda: fs.ReadUShort(),
            OperandType.UInt32  : lambda: fs.ReadULong(),
            OperandType.Float32 : lambda: fs.ReadFloat(),
            OperandType.Offset  : lambda: fs.ReadULong(),
        }[self.format.type]()

    def format_operand(self, operand: 'Operand', context: 'FormatterContext') -> str:
        """Format operand for display"""
        return {
            OperandType.SInt8   : self.format_integer,
            OperandType.SInt16  : self.format_integer,
            OperandType.SInt32  : self.format_integer,
            OperandType.UInt8   : self.format_integer,
            OperandType.UInt16  : self.format_integer,
            OperandType.UInt32  : self.format_integer,
            OperandType.Float32 : self.format_float,
            OperandType.Offset  : self.format_offset,
        }[self.format.type](operand)

    def format_integer(self, operand: 'Operand') -> str:
        if self.format.is_hex:
            if self.format.type in (OperandType.SInt8, OperandType.SInt16, OperandType.SInt32):
                # Signed integer
                if operand.value < 0:
                    return f'-0x{-operand.value:0{self.format.size * 2}X}'
                else:
                    return f'0x{operand.value:0{self.format.size * 2}X}'
            else:
                # Unsigned integer
                return f'0x{operand.value:0{self.format.size * 2}X}'
        return str(operand.value)

    def format_float(self, operand: 'Operand') -> str:
        return str(operand.value)

    def format_offset(self, operand: 'Operand') -> str:
        return f'\'loc_{operand.value:X}\''


# Initialize format table
def _oprdesc(opr_type: OperandType, is_hex: bool = False):
    return OperandDescriptor(OperandFormat(opr_type, is_hex = is_hex))

OperandDescriptor.format_table.update({
    'c' : _oprdesc(OperandType.SInt8, is_hex = False),
    'C' : _oprdesc(OperandType.UInt8, is_hex = False),
    'b' : _oprdesc(OperandType.SInt8, is_hex = True),
    'B' : _oprdesc(OperandType.UInt8, is_hex = True),

    'h' : _oprdesc(OperandType.SInt16, is_hex = False),
    'H' : _oprdesc(OperandType.UInt16, is_hex = False),
    'w' : _oprdesc(OperandType.SInt16, is_hex = True),
    'W' : _oprdesc(OperandType.UInt16, is_hex = True),

    'i' : _oprdesc(OperandType.SInt32, is_hex = False),
    'I' : _oprdesc(OperandType.UInt32, is_hex = False),
    'l' : _oprdesc(OperandType.SInt32, is_hex = True),
    'L' : _oprdesc(OperandType.UInt32, is_hex = True),

    'f' : _oprdesc(OperandType.Float32),

    'S' : _oprdesc(OperandType.String),

    'O' : _oprdesc(OperandType.Offset),
})


@dataclass
class BranchTarget:
    """Branch target information"""
    kind   : 'BranchKind'
    offset : int

    @classmethod
    def unconditional(cls, offset: int) -> 'BranchTarget':
        """Create unconditional branch target"""
        return cls(BranchKind.UNCONDITIONAL, offset)

    @classmethod
    def true_branch(cls, offset: int) -> 'BranchTarget':
        """Create true branch target"""
        return cls(BranchKind.TRUE, offset)

    @classmethod
    def false_branch(cls, offset: int) -> 'BranchTarget':
        """Create false branch target"""
        return cls(BranchKind.FALSE, offset)


class InstructionFlags(IntFlag2):
    """Instruction flags (can be combined with bitwise OR)"""
    NONE        = 0
    END_BLOCK   = 1 << 0  # Terminates a basic block
    START_BLOCK = 1 << 1  # Starts a new basic block at target


@dataclass
class InstructionDescriptor:
    """Descriptor for an instruction in the instruction table"""
    opcode: int
    mnemonic: str
    flags: InstructionFlags = InstructionFlags.NONE

    def is_end_block(self) -> bool:
        """Check if instruction terminates a basic block"""
        return bool(self.flags & InstructionFlags.END_BLOCK)

    def is_start_block(self) -> bool:
        """Check if instruction starts a new basic block"""
        return bool(self.flags & InstructionFlags.START_BLOCK)

    def get_branch_targets(self, inst: Instruction, current_pos: int) -> list[BranchTarget]:
        """Get branch targets from this instruction"""
        return []

    def format_operands(self, operands: list['Operand'], context: 'FormatterContext') -> list[str]:
        """Format operands for display"""
        return [op.descriptor.format_operand(op, context) for op in operands]

    def format_instruction(self, inst: Instruction, context: 'FormatterContext') -> str:
        """Format instruction for display"""
        ops = self.format_operands(inst.operands, context)
        return f'{self.mnemonic}({", ".join(ops)})'


class InstructionTable(ABC):
    """Abstract interface for instruction tables"""

    @abstractmethod
    def read_opcode(self, fs: 'fileio.FileStream') -> int:
        """Read opcode from file stream"""
        pass

    @abstractmethod
    def get_descriptor(self, opcode: int) -> InstructionDescriptor:
        """Get instruction descriptor for opcode"""
        pass

    @abstractmethod
    def read_operands(
        self,
        fs: 'fileio.FileStream',
        inst: Instruction,
        offset: int
    ) -> list['Operand']:
        """Read operands for instruction"""
        pass

    def decode_instruction(
        self,
        fs: 'fileio.FileStream',
        offset: int
    ) -> Instruction:
        """Decode a complete instruction"""
        # Read opcode
        opcode = self.read_opcode(fs)

        # Get descriptor
        descriptor = self.get_descriptor(opcode)

        # Create instruction
        inst = Instruction(
            offset      = offset,
            opcode      = opcode,
            descriptor  = descriptor,
            operands    = [],
            size        = 0
        )

        # Read operands (may modify inst.opcode and inst.descriptor)
        operands = self.read_operands(fs, inst, offset)

        # Update instruction
        inst.operands = operands
        inst.size = fs.Position - offset

        return inst
