"""ED9 (Kuro no Kiseki) Instruction Table"""

from common import *
from ml import fileio
from typing import TYPE_CHECKING

from .instruction_table import *
from .instruction import *
from .basic_block import *
from ..parser.types_scp import *

if TYPE_CHECKING:
    from .formatter import FormatterContext

# ED9-specific operand types
class ED9OperandType(IntEnum2):
    """ED9-specific operand types extending base OperandType"""
    Func      = OperandType.UserDefined + 1  # Function ID
    Value     = OperandType.UserDefined + 2  # ScpValue
    GlobalVar = OperandType.UserDefined + 3  # Global var table index (LOAD_GLOBAL/SET_GLOBAL)

# ED9 operand descriptor with extended functionality
class ED9OperandDescriptor(OperandDescriptor):
    """ED9-specific operand descriptor"""

    def read_value(self, fs: fileio.FileStream) -> Any:
        """Read ED9-specific operand values"""
        match self.format.type:
            case ED9OperandType.Func:
                return fs.ReadUShort()

            case ED9OperandType.Value:
                return ScpValue(fs=fs)

            case ED9OperandType.GlobalVar:
                return fs.ReadLong()

            case _:
                return super().read_value(fs)

    def format_operand(self, operand: Operand, context: 'FormatterContext') -> str:
        """Format ED9-specific operands"""
        match self.format.type:
            case ED9OperandType.Func:
                # Try to get function name from context
                if context.get_func_name_from_func_id:
                    func_name = context.get_func_name_from_func_id(operand.value)
                    if func_name:
                        return func_name
                return f'func_{operand.value}'

            case ED9OperandType.Value:
                return str(operand.value)

            case ED9OperandType.GlobalVar:
                # Try to get the global var's real name from context
                if context.get_global_name_from_index:
                    global_name = context.get_global_name_from_index(operand.value)
                    if global_name:
                        return quote_string(global_name)
                return str(operand.value)

            case OperandType.String:
                return quote_string(operand.value)

            case _:
                return super().format_operand(operand, context)

# ED9 operand descriptor factory
def _ed9_oprdesc(opr_type: OperandType | ED9OperandType, is_hex: bool = False):
    return ED9OperandDescriptor(OperandFormat(opr_type, is_hex=is_hex))

# Extend format table with ED9-specific types
ED9_FORMAT_TABLE = OperandDescriptor.format_table.copy()
ED9_FORMAT_TABLE.update({
    'F' : _ed9_oprdesc(ED9OperandType.Func),
    'V' : _ed9_oprdesc(ED9OperandType.Value),
    'S' : _ed9_oprdesc(OperandType.String),
    'G' : _ed9_oprdesc(ED9OperandType.GlobalVar),
})

if TYPE_CHECKING:
    from .disassembler import DisassemblerContext




@dataclass
class InstructionEntry:
    """Single instruction table entry"""
    opcode: int
    mnemonic: str
    operand_fmt: str = ''
    flags: InstructionFlags = InstructionFlags.NONE


# ED9 Instruction Table
ED9_OPCODE_TABLE = [
    # Stack operations
    InstructionEntry(0x00, 'PUSH',                    'CV'),       # Special: decoded to PUSH_INT/PUSH_FLOAT/PUSH_STR
    InstructionEntry(0x01, 'POP',                     'C'),
    InstructionEntry(0x02, 'LOAD_STACK',              'i'),
    InstructionEntry(0x03, 'LOAD_STACK_DEREF',        'i'),
    InstructionEntry(0x04, 'PUSH_STACK_OFFSET',       'i'),
    InstructionEntry(0x05, 'POP_TO',                  'i'),
    InstructionEntry(0x06, 'POP_TO_DEREF',            'i'),

    # Global variables
    InstructionEntry(0x07, 'LOAD_GLOBAL',             'G'),
    InstructionEntry(0x08, 'SET_GLOBAL',              'G'),

    # Registers
    InstructionEntry(0x09, 'GET_REG',                 'C'),
    InstructionEntry(0x0A, 'SET_REG',                 'C'),

    # Control flow
    InstructionEntry(0x0B, 'JMP',                     'O',   InstructionFlags.END_BLOCK),
    InstructionEntry(0x0C, 'CALL',                    'F',   InstructionFlags.END_BLOCK),
    InstructionEntry(0x0D, 'RETURN',                  '',    InstructionFlags.END_BLOCK),
    InstructionEntry(0x0E, 'POP_JMP_NOT_ZERO',        'O',   InstructionFlags.END_BLOCK),
    InstructionEntry(0x0F, 'POP_JMP_ZERO',            'O',   InstructionFlags.END_BLOCK),

    # Arithmetic
    InstructionEntry(0x10, 'ADD'),
    InstructionEntry(0x11, 'SUB'),
    InstructionEntry(0x12, 'MUL'),
    InstructionEntry(0x13, 'DIV'),
    InstructionEntry(0x14, 'MOD'),

    # Comparison
    InstructionEntry(0x15, 'EQ'),
    InstructionEntry(0x16, 'NE'),
    InstructionEntry(0x17, 'GT'),
    InstructionEntry(0x18, 'GE'),
    InstructionEntry(0x19, 'LT'),
    InstructionEntry(0x1A, 'LE'),

    # Bitwise & Logical
    InstructionEntry(0x1B, 'BITWISE_AND'),
    InstructionEntry(0x1C, 'BITWISE_OR'),
    InstructionEntry(0x1D, 'LOGICAL_AND'),
    InstructionEntry(0x1E, 'LOGICAL_OR'),

    # Unary
    InstructionEntry(0x1F, 'NEG'),
    InstructionEntry(0x20, 'EZ'),
    InstructionEntry(0x21, 'NOT'),

    # Script calls
    InstructionEntry(0x22, 'CALL_SCRIPT',             'VVC', InstructionFlags.END_BLOCK),
    InstructionEntry(0x23, 'CALL_SCRIPT_NO_RETURN',   'VVC', InstructionFlags.END_BLOCK),

    # System
    InstructionEntry(0x24, 'SYSCALL',                 'CBB'),
    InstructionEntry(0x25, 'PUSH_CALLER_FRAME',       'O',   InstructionFlags.START_BLOCK),
    InstructionEntry(0x26, 'DEBUG_SET_LINENO',        'H'),
    InstructionEntry(0x27, 'DEBUG_LOG',               'C'),

    # Pseudo-instructions (optimized from other instructions)
    InstructionEntry(0x1000, 'PUSH_CURRENT_FUNC_ID',  ''),
    InstructionEntry(0x1001, 'PUSH_RET_ADDR',         'O'),
    InstructionEntry(0x1002, 'PUSH_RAW',              'I'),
    InstructionEntry(0x1003, 'PUSH_INT',              'I'),
    InstructionEntry(0x1004, 'PUSH_FLOAT',            'f'),
    InstructionEntry(0x1005, 'PUSH_STR',              'S'),
]

# Helper to lookup opcode from table
def _opcode(mnemonic: str) -> int:
    for entry in ED9_OPCODE_TABLE:
        if entry.mnemonic == mnemonic:
            return entry.opcode
    raise ValueError(f'Unknown mnemonic: {mnemonic}')

class ED9Opcode(IntEnum2):
    """ED9 VM Opcodes"""
    # Stack operations
    PUSH                    = _opcode('PUSH')
    POP                     = _opcode('POP')
    LOAD_STACK              = _opcode('LOAD_STACK')
    LOAD_STACK_DEREF        = _opcode('LOAD_STACK_DEREF')
    PUSH_STACK_OFFSET       = _opcode('PUSH_STACK_OFFSET')
    POP_TO                  = _opcode('POP_TO')
    POP_TO_DEREF            = _opcode('POP_TO_DEREF')

    # Global variables
    LOAD_GLOBAL             = _opcode('LOAD_GLOBAL')
    SET_GLOBAL              = _opcode('SET_GLOBAL')

    # Registers
    GET_REG                 = _opcode('GET_REG')
    SET_REG                 = _opcode('SET_REG')

    # Control flow
    JMP                     = _opcode('JMP')
    CALL                    = _opcode('CALL')
    RETURN                  = _opcode('RETURN')
    POP_JMP_NOT_ZERO        = _opcode('POP_JMP_NOT_ZERO')
    POP_JMP_ZERO            = _opcode('POP_JMP_ZERO')

    # Arithmetic
    ADD                     = _opcode('ADD')
    SUB                     = _opcode('SUB')
    MUL                     = _opcode('MUL')
    DIV                     = _opcode('DIV')
    MOD                     = _opcode('MOD')

    # Comparison
    EQ                      = _opcode('EQ')
    NE                      = _opcode('NE')
    GT                      = _opcode('GT')
    GE                      = _opcode('GE')
    LT                      = _opcode('LT')
    LE                      = _opcode('LE')

    # Bitwise & Logical
    BITWISE_AND             = _opcode('BITWISE_AND')
    BITWISE_OR              = _opcode('BITWISE_OR')
    LOGICAL_AND             = _opcode('LOGICAL_AND')
    LOGICAL_OR              = _opcode('LOGICAL_OR')

    # Unary
    NEG                     = _opcode('NEG')
    EZ                      = _opcode('EZ')
    NOT                     = _opcode('NOT')

    # Script calls
    CALL_SCRIPT             = _opcode('CALL_SCRIPT')
    CALL_SCRIPT_NO_RETURN   = _opcode('CALL_SCRIPT_NO_RETURN')

    # System
    SYSCALL                 = _opcode('SYSCALL')
    PUSH_CALLER_FRAME       = _opcode('PUSH_CALLER_FRAME')
    DEBUG_SET_LINENO        = _opcode('DEBUG_SET_LINENO')
    DEBUG_LOG               = _opcode('DEBUG_LOG')

    # Never seen in a sample script and its operand format is unknown - not in the table, so decoding it raises
    UNKNOWN_28              = 0x28

    # Pseudo-instructions
    PUSH_CURRENT_FUNC_ID    = _opcode('PUSH_CURRENT_FUNC_ID')
    PUSH_RET_ADDR           = _opcode('PUSH_RET_ADDR')
    PUSH_RAW                = _opcode('PUSH_RAW')
    PUSH_INT                = _opcode('PUSH_INT')
    PUSH_FLOAT              = _opcode('PUSH_FLOAT')
    PUSH_STR                = _opcode('PUSH_STR')


class ED9InstructionDescriptor(InstructionDescriptor):
    """ED9-specific instruction descriptor with operand format"""
    _allow_creation = True

    def __init__(
        self,
        opcode: int,
        mnemonic: str,
        operand_fmt: str = '',
        flags: InstructionFlags = InstructionFlags.NONE
    ):
        if not ED9InstructionDescriptor._allow_creation:
            raise RuntimeError('Cannot create ED9InstructionDescriptor after ED9InstructionTable initialization')
        super().__init__(opcode, mnemonic, flags)
        self.operand_fmt = operand_fmt

    def format_operands(self, operands: list[Operand], context: 'FormatterContext') -> list[str]:
        """Format operands for display (ED9-specific)"""
        return [op.descriptor.format_operand(op, context) for op in operands]

    def get_branch_targets(self, inst, current_pos: int) -> list[BranchTarget]:
        """Extract branch targets from instruction"""
        targets = []

        if self.opcode == ED9Opcode.JMP:
            # Unconditional jump
            target = self._get_offset_operand(inst)
            if target is not None:
                targets.append(BranchTarget.unconditional(target))

        elif self.opcode in (ED9Opcode.POP_JMP_ZERO, ED9Opcode.POP_JMP_NOT_ZERO):
            # Conditional jump
            target = self._get_offset_operand(inst)
            if target is not None:
                targets.append(BranchTarget.true_branch(target))
                targets.append(BranchTarget.false_branch(current_pos))

        elif self.opcode == ED9Opcode.PUSH_CALLER_FRAME:
            # Return address
            target = self._get_offset_operand(inst)
            if target is not None:
                targets.append(BranchTarget.unconditional(target))

        return targets

    def _get_offset_operand(self, inst) -> int | None:
        """Extract offset operand from instruction"""
        for op in inst.operands:
            if op.descriptor.format.type == OperandType.Offset:
                return op.value
        return None



class ED9InstructionTable(InstructionTable):
    """ED9 VM Instruction Table"""

    def __init__(self):
        self.descriptors: dict[int, ED9InstructionDescriptor] = {}
        self._init_table()
        # Disable further descriptor creation
        ED9InstructionDescriptor._allow_creation = False

    def _init_table(self):
        """Initialize instruction table from ED9_OPCODE_TABLE"""
        for entry in ED9_OPCODE_TABLE:
            desc = ED9InstructionDescriptor(
                opcode       = entry.opcode,
                mnemonic     = entry.mnemonic,
                operand_fmt  = entry.operand_fmt,
                flags        = entry.flags
            )
            self.descriptors[entry.opcode] = desc

    def read_opcode(self, fs: fileio.FileStream) -> int:
        """Read opcode byte"""
        return fs.ReadByte()

    def get_descriptor(self, opcode: int) -> ED9InstructionDescriptor:
        """Get instruction descriptor"""
        if opcode == ED9Opcode.UNKNOWN_28:
            raise NotImplementedError(f'opcode 0x{opcode:02X} decoded - never seen in a sample script, operand format unknown')

        if opcode not in self.descriptors:
            raise ValueError(f'Unknown opcode: 0x{opcode:02X}')
        return self.descriptors[opcode]

    def read_operands(
        self,
        fs          : fileio.FileStream,
        inst        : Instruction,
        offset      : int
    ) -> list[Operand]:
        """Read operands according to format string"""
        descriptor = inst.descriptor
        if not isinstance(descriptor, ED9InstructionDescriptor):
            raise TypeError('Expected ED9InstructionDescriptor')

        # Get operand descriptors from format string
        operand_descriptors = OperandDescriptor.from_format_string(descriptor.operand_fmt, ED9_FORMAT_TABLE)

        operands = []
        for op_desc in operand_descriptors:
            value = op_desc.read_value(fs)
            operands.append(Operand(descriptor=op_desc, value=value))

        # Special handling for PUSH instruction
        if descriptor.opcode == ED9Opcode.PUSH:
            self._decode_push(inst, operands)
            return inst.operands

        return operands

    def _decode_push(self, inst: Instruction, operands: list[Operand]):
        """Decode PUSH instruction to specific variant based on value type"""

        operand_size = operands[0]
        operand_value = operands[1]

        if operand_size.descriptor.format.type not in (OperandType.SInt8, OperandType.UInt8):
            raise ValueError(f'Expected SInt8 operand for size, got {operand_size.descriptor.format.type}')

        if operand_value.descriptor.format.type != ED9OperandType.Value:
            raise ValueError(f'Expected Value operand, got {operand_value.descriptor.format.type}')

        value = operand_value.value
        if not isinstance(value, ScpValue):
            raise ValueError(f'Expected ScpValue, got {type(value)}')

        # Helper to update instruction with new opcode and operand
        def update_push_inst(opcode: int, operand_value: Any):
            inst.opcode = opcode
            inst.descriptor = self.get_descriptor(opcode)
            # Get operand descriptor from instruction descriptor
            op_desc = OperandDescriptor.from_format_string(inst.descriptor.operand_fmt, ED9_FORMAT_TABLE)[0]
            inst.operands = [Operand(descriptor=op_desc, value=operand_value)]

        # Replace descriptor and operands based on value type
        match value.type:
            case ScpValue.Type.Raw:
                update_push_inst(ED9Opcode.PUSH_RAW, value.value)

            case ScpValue.Type.Integer:
                update_push_inst(ED9Opcode.PUSH_INT, value.value)

            case ScpValue.Type.Float:
                update_push_inst(ED9Opcode.PUSH_FLOAT, value.value)

            case ScpValue.Type.String:
                update_push_inst(ED9Opcode.PUSH_STR, value.value)


def ed9_create_fallthrough_jump(offset: int, target: int, inst_table: 'InstructionTable') -> Instruction:
    """Create a synthetic JMP instruction for split blocks"""

    # Get JMP descriptor from instruction table
    jmp_descriptor = inst_table.get_descriptor(ED9Opcode.JMP)

    # Create offset operand from instruction descriptor
    op_desc = OperandDescriptor.from_format_string(jmp_descriptor.operand_fmt, ED9_FORMAT_TABLE)[0]
    operand = Operand(descriptor = op_desc, value = target)

    # Create synthetic instruction
    # Use offset - 1 to avoid collision with tail block's first instruction
    synthetic_inst = Instruction(
        offset     = offset - 1,
        opcode     = jmp_descriptor.opcode,
        descriptor = jmp_descriptor,
        operands   = [operand],
        size       = SYNTHETIC_INSTRUCTION_SIZE
    )

    return synthetic_inst


# Global instruction table instance
ED9_INSTRUCTION_TABLE = ED9InstructionTable()
