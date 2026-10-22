"""Instruction table interface and descriptor"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from dc3 import fileio, format_signed_hex, IntEnum2, IntFlag2
from .basic_block import BranchKind
from .instruction import Instruction, Operand


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


SIGNED_INTEGER_TYPES    = {OperandType.SInt8, OperandType.SInt16, OperandType.SInt32}
UNSIGNED_INTEGER_TYPES  = {OperandType.UInt8, OperandType.UInt16, OperandType.UInt32}
HEX_DIGITS_PER_BYTE     = 2


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
        self.type        = opr_type
        self.is_hex      = is_hex
        self.value_range = self.integer_range(opr_type)

    def __repr__(self):
        return repr(self.type)

    @property
    def size(self):
        return self.size_table.get(self.type)

    @classmethod
    def integer_range(cls, opr_type: OperandType) -> range | None:
        """The integers a type reads back, from its width and signedness; None for a non-integer type"""
        if opr_type not in SIGNED_INTEGER_TYPES | UNSIGNED_INTEGER_TYPES:
            return None

        bits = cls.size_table[opr_type] * fileio.BITS_PER_BYTE
        if opr_type in SIGNED_INTEGER_TYPES:
            return range(-(1 << (bits - 1)), 1 << (bits - 1))

        return range(1 << bits)


class OperandDescriptor:
    """Operand descriptor with read/write/format methods"""

    format_table: dict[str, 'OperandDescriptor'] = {}

    @classmethod
    def from_format_string(cls, fmtstr: str, format_table: dict | None = None) -> tuple['OperandDescriptor', ...]:
        format_table = format_table or cls.format_table
        return tuple(format_table[f] for f in fmtstr)

    def __init__(self, format: OperandFormat):
        self.format = format

    @property
    def type(self) -> OperandType:
        return self.format.type

    READER_BY_TYPE = {
        OperandType.SInt8   : fileio.FileStream.ReadChar,
        OperandType.SInt16  : fileio.FileStream.ReadShort,
        OperandType.SInt32  : fileio.FileStream.ReadLong,
        OperandType.UInt8   : fileio.FileStream.ReadByte,
        OperandType.UInt16  : fileio.FileStream.ReadUShort,
        OperandType.UInt32  : fileio.FileStream.ReadULong,
        OperandType.Float32 : fileio.FileStream.ReadFloat,
        OperandType.Offset  : fileio.FileStream.ReadULong,
    }

    def read_value(self, fs: 'fileio.FileStream') -> Any:
        """Read operand value from file stream"""
        return self.READER_BY_TYPE[self.format.type](fs)

    WRITER_BY_TYPE = {
        OperandType.SInt8   : fileio.FileStream.WriteChar,
        OperandType.SInt16  : fileio.FileStream.WriteShort,
        OperandType.SInt32  : fileio.FileStream.WriteLong,
        OperandType.UInt8   : fileio.FileStream.WriteByte,
        OperandType.UInt16  : fileio.FileStream.WriteUShort,
        OperandType.UInt32  : fileio.FileStream.WriteULong,
        OperandType.Float32 : fileio.FileStream.WriteFloat,
        OperandType.Offset  : fileio.FileStream.WriteULong,
    }

    def write_value(self, fs: 'fileio.FileStream', value: Any):
        """Write operand value to file stream"""
        self.WRITER_BY_TYPE[self.format.type](fs, value)

    def format_integer(self, operand: Operand) -> str:
        if self.format.is_hex:
            # Only a signed type can hold a negative value, so one rule fits both
            return format_signed_hex(operand.value, self.format.size * HEX_DIGITS_PER_BYTE)

        return str(operand.value)

    def format_float(self, operand: Operand) -> str:
        return str(operand.value)

    def format_offset(self, operand: Operand) -> str:
        return f"'loc_{operand.value:X}'"

    FORMATTER_BY_TYPE = {
        OperandType.SInt8   : format_integer,
        OperandType.SInt16  : format_integer,
        OperandType.SInt32  : format_integer,
        OperandType.UInt8   : format_integer,
        OperandType.UInt16  : format_integer,
        OperandType.UInt32  : format_integer,
        OperandType.Float32 : format_float,
        OperandType.Offset  : format_offset,
    }

    def format_operand(self, operand: Operand, context: Any) -> str:
        """Format operand for display; context is the engine's formatter context, read only by an engine's override"""
        return self.FORMATTER_BY_TYPE[self.format.type](self, operand)


# Initialize format table
def _oprdesc(opr_type: OperandType, is_hex: bool = False):
    return OperandDescriptor(OperandFormat(opr_type, is_hex=is_hex))


OperandDescriptor.format_table.update({
    'c' : _oprdesc(OperandType.SInt8, is_hex=False),
    'C' : _oprdesc(OperandType.UInt8, is_hex=False),
    'b' : _oprdesc(OperandType.SInt8, is_hex=True),
    'B' : _oprdesc(OperandType.UInt8, is_hex=True),

    'h' : _oprdesc(OperandType.SInt16, is_hex=False),
    'H' : _oprdesc(OperandType.UInt16, is_hex=False),
    'w' : _oprdesc(OperandType.SInt16, is_hex=True),
    'W' : _oprdesc(OperandType.UInt16, is_hex=True),

    'i' : _oprdesc(OperandType.SInt32, is_hex=False),
    'I' : _oprdesc(OperandType.UInt32, is_hex=False),
    'l' : _oprdesc(OperandType.SInt32, is_hex=True),
    'L' : _oprdesc(OperandType.UInt32, is_hex=True),

    'f' : _oprdesc(OperandType.Float32),

    'S' : _oprdesc(OperandType.String),

    'O' : _oprdesc(OperandType.Offset),
})


@dataclass
class BranchTarget:
    """Branch target information"""

    kind   : BranchKind
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
    ends_block: bool = field(init=False, repr=False)
    starts_block: bool = field(init=False, repr=False)

    def __post_init__(self):
        self.ends_block = bool(self.flags & InstructionFlags.END_BLOCK)
        self.starts_block = bool(self.flags & InstructionFlags.START_BLOCK)

    def get_branch_targets(self, inst: Instruction, current_pos: int) -> list[BranchTarget]:
        """Get branch targets from this instruction"""
        return []

    def format_operands(self, operands: list[Operand], context: Any) -> list[str]:
        """Format operands for display"""
        return [op.descriptor.format_operand(op, context) for op in operands]

    def format_instruction(self, inst: Instruction, context: Any) -> str:
        """Format instruction for display"""
        ops = self.format_operands(inst.operands, context)
        return f'{self.mnemonic}({", ".join(ops)})'


class InstructionTable(ABC):
    """Abstract interface for instruction tables"""

    @abstractmethod
    def read_opcode(self, fs: 'fileio.FileStream') -> int:
        """Read opcode from file stream"""

    @abstractmethod
    def get_descriptor(self, opcode: int) -> InstructionDescriptor:
        """Get instruction descriptor for opcode"""

    @abstractmethod
    def read_operands(
        self,
        fs: 'fileio.FileStream',
        inst: Instruction,
        offset: int
    ) -> list[Operand]:
        """Read operands for instruction"""

    def decode_instruction(
        self,
        fs: 'fileio.FileStream',
        offset: int
    ) -> Instruction:
        """Decode a complete instruction"""
        opcode = self.read_opcode(fs)
        descriptor = self.get_descriptor(opcode)
        inst = Instruction(offset=offset, opcode=opcode, descriptor=descriptor)

        # Read operands (may modify inst.opcode and inst.descriptor)
        operands = self.read_operands(fs, inst, offset)
        inst.operands = operands
        inst.size = fs.Position - offset

        return inst
