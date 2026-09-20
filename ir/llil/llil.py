'''LLIL - Stack-based low-level IR'''

from abc import ABC, abstractmethod
from typing import Any, List, Optional, Union, TYPE_CHECKING
from common import *
from ir.core import *

if TYPE_CHECKING:
    # Forward declaration for type hints
    pass

# Constants
WORD_SIZE = 4  # 4 bytes per word


class LowLevelILOperation(IntEnum2):
    '''Atomic LLIL operations'''

    # Stack operations (atomic)
    LLIL_STACK_STORE        = 0     # STACK[sp + offset] = value
    LLIL_STACK_LOAD         = 1     # load STACK[sp + offset]
    LLIL_SP_ADD             = 2     # sp = sp + delta

    # Frame operations (relative to frame base, for function parameters/locals)
    LLIL_FRAME_LOAD         = 5     # load STACK[frame + offset]
    LLIL_FRAME_STORE        = 6     # STACK[frame + offset] = value

    # Register operations
    LLIL_REG_STORE          = 10    # R[index] = value
    LLIL_REG_LOAD           = 11    # load R[index]

    # Arithmetic operations (stack-based)
    LLIL_ADD                = 20    # binary operation on stack
    LLIL_SUB                = 21    # subtraction
    LLIL_MUL                = 22    # multiplication
    LLIL_DIV                = 23    # division
    LLIL_EQ                 = 24    # equality compare
    LLIL_NE                 = 25    # inequality compare
    LLIL_LT                 = 26    # less-than compare
    LLIL_LE                 = 27    # less-or-equal compare
    LLIL_GT                 = 28    # greater-than compare
    LLIL_GE                 = 29    # greater-or-equal compare
    LLIL_AND                = 30    # bitwise AND
    LLIL_OR                 = 31    # bitwise OR
    LLIL_LOGICAL_AND        = 32    # logical AND (&&)
    LLIL_LOGICAL_OR         = 33    # logical OR (||)
    LLIL_MOD                = 34    # modulus

    # Unary operations
    LLIL_NEG                = 35    # arithmetic negation (-x)
    LLIL_BITWISE_NOT        = 36    # bitwise NOT (~x)
    LLIL_TEST_ZERO          = 37    # test if zero (x == 0)

    # Control flow
    LLIL_JMP                = 40    # unconditional jump
    LLIL_BRANCH             = 41    # conditional branch
    LLIL_CALL               = 42    # function call
    LLIL_RET                = 43    # return

    # Constants and special
    LLIL_CONST              = 50    # constant value
    LLIL_LABEL              = 51    # label
    LLIL_NOP                = 52    # no operation

    # VM specific
    LLIL_SYSCALL            = 60    # system call
    LLIL_DEBUG              = 61    # debug info
    LLIL_STACK_ADDR         = 62    # address of stack location (sp + offset)

    # Falcom VM specific (user-defined extensions)
    LLIL_PUSH_CALLER_FRAME     = 1000  # Falcom VM: push caller frame (4 values)
    LLIL_CALL_SCRIPT           = 1001  # Falcom VM: call script function
    LLIL_CALL_SCRIPT_NO_RETURN = 1002  # Falcom VM: tail-call script function (never returns to caller)

    # User-defined extensions (reserved range: 1003+)
    LLIL_USER_DEFINED       = 1003  # Start of user-defined operations


class LowLevelILInstruction(ILInstruction):
    '''Base class for all LLIL instructions'''

    def __init__(self, operation: LowLevelILOperation):
        super().__init__()
        self.address = 0
        self.inst_index = -1  # Assigned via LowLevelILFunction._register_instruction
        self.operation = operation
        self.options = ILOptions()  # Formatting and processing options

    @property
    def operation_name(self) -> str:
        '''Get operation name without LLIL_ prefix (e.g., 'LLIL_ADD' -> 'ADD')'''
        return self.operation.name.replace('LLIL_', '')

    @abstractmethod
    def __str__(self) -> str:
        pass

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {str(self)}>'


# === Instruction Categories (following BinaryNinja design) ===

class LowLevelILExpr(LowLevelILInstruction):
    '''Base class for value expressions'''
    pass


class LowLevelILStatement(LowLevelILInstruction):
    '''Base class for statements'''
    pass


# === Atomic Stack Operations ===

class LowLevelILStackStore(LowLevelILStatement):
    '''STACK[sp + offset] = value'''

    def __init__(self, value: Union['LowLevelILInstruction', int, str], offset: int = 0, slot_index: int = None):
        super().__init__(LowLevelILOperation.LLIL_STACK_STORE)
        self.value = value
        self.offset = offset  # Byte offset
        self.slot_index = slot_index  # Absolute stack slot index

    def __str__(self) -> str:
        # Convert byte offset to word offset for display
        word_offset = self.offset // WORD_SIZE
        if word_offset == 0:
            return f'STACK[sp] = {self.value}'
        elif word_offset > 0:
            return f'STACK[sp + {word_offset}] = {self.value}'
        else:
            return f'STACK[sp - {-word_offset}] = {self.value}'


class LowLevelILStackLoad(LowLevelILExpr):
    '''Load STACK[sp + offset]'''

    def __init__(self, offset: int, slot_index: int):
        super().__init__(LowLevelILOperation.LLIL_STACK_LOAD)
        self.offset = offset  # Byte offset
        self.slot_index = slot_index  # Absolute stack slot index

    def __eq__(self, other):
        return object.__eq__(self, other)

    def __hash__(self):
        return object.__hash__(self)

    def __str__(self) -> str:
        # Convert byte offset to word offset for display
        word_offset = self.offset // WORD_SIZE
        if word_offset == 0:
            return f'STACK[sp<{self.slot_index}>]'
        elif word_offset > 0:
            return f'STACK[sp + {word_offset}<{self.slot_index}>]'
        else:
            return f'STACK[sp - {-word_offset}<{self.slot_index}>]'


class LowLevelILFrameLoad(LowLevelILExpr):
    '''Load STACK[frame + offset]'''

    def __init__(self, offset: int = 0):
        super().__init__(LowLevelILOperation.LLIL_FRAME_LOAD)
        self.offset = offset  # Byte offset relative to frame

    def __str__(self) -> str:
        # Convert byte offset to word offset for display
        # Always show explicit offset: fp + 0, fp + 1, etc.
        word_offset = self.offset // WORD_SIZE
        if word_offset >= 0:
            return f'STACK[fp + {word_offset}]'
        else:
            return f'STACK[fp - {-word_offset}]'


class LowLevelILFrameStore(LowLevelILStatement):
    '''STACK[frame + offset] = value'''

    def __init__(self, value: Union['LowLevelILInstruction', int, str], offset: int = 0):
        super().__init__(LowLevelILOperation.LLIL_FRAME_STORE)
        self.value = value
        self.offset = offset  # Byte offset relative to frame

    def __str__(self) -> str:
        # Convert byte offset to word offset for display
        # Always show explicit offset: fp + 0, fp + 1, etc.
        word_offset = self.offset // WORD_SIZE
        if word_offset >= 0:
            return f'STACK[fp + {word_offset}] = {self.value}'
        else:
            return f'STACK[fp - {-word_offset}] = {self.value}'


class LowLevelILSpAdd(LowLevelILStatement):
    '''sp = sp + delta (statement)'''

    def __init__(self, delta: int):
        super().__init__(LowLevelILOperation.LLIL_SP_ADD)
        self.delta = delta

    def __str__(self) -> str:
        if self.delta == 1:
            return 'sp++'
        elif self.delta == -1:
            return 'sp--'
        elif self.delta > 0:
            return f'sp += {self.delta}'
        else:
            return f'sp -= {-self.delta}'




class LowLevelILStackAddr(LowLevelILExpr):
    '''Address of stack slot (sp-independent)'''

    def __init__(self, slot_index: int):
        super().__init__(LowLevelILOperation.LLIL_STACK_ADDR)
        self.slot_index = slot_index  # Absolute stack slot index

    def __str__(self) -> str:
        return f'&STACK[{self.slot_index}]'


# Alias for compatibility
LowLevelILVspAdd = LowLevelILSpAdd


# === Register Operations ===

class LowLevelILRegStore(LowLevelILStatement):
    '''REG[index] = value (statement)'''

    def __init__(self, reg_index: int, value: Union['LowLevelILInstruction', int]):
        super().__init__(LowLevelILOperation.LLIL_REG_STORE)
        self.reg_index = reg_index
        self.value = value

    def __str__(self) -> str:
        return f'REG[{self.reg_index}] = {self.value}'


class LowLevelILRegLoad(LowLevelILExpr):
    '''load REG[index] (expression)'''

    def __init__(self, reg_index: int):
        super().__init__(LowLevelILOperation.LLIL_REG_LOAD)
        self.reg_index = reg_index

    def __str__(self) -> str:
        return f'REG[{self.reg_index}]'


# === Arithmetic Operations ===

class LowLevelILBinaryOp(LowLevelILExpr, BinaryOperation):
    '''Base for binary operations (expression)'''

    def __init__(
        self,
        operation: LowLevelILOperation,
        lhs: 'LowLevelILExpr' = None,
        rhs: 'LowLevelILExpr' = None
    ):
        super().__init__(operation)
        self.lhs = lhs  # Left operand expression
        self.rhs = rhs  # Right operand expression

    def __str__(self) -> str:
        if self.lhs and self.rhs:
            return f'{self.operation_name}({self.lhs}, {self.rhs})'
        return self.operation_name


class LowLevelILAdd(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_ADD, lhs, rhs)


class LowLevelILMul(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_MUL, lhs, rhs)


class LowLevelILSub(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_SUB, lhs, rhs)


class LowLevelILDiv(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_DIV, lhs, rhs)


class LowLevelILMod(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_MOD, lhs, rhs)


class LowLevelILEq(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_EQ, lhs, rhs)


class LowLevelILNe(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_NE, lhs, rhs)


class LowLevelILLt(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_LT, lhs, rhs)


class LowLevelILLe(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_LE, lhs, rhs)


class LowLevelILGt(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_GT, lhs, rhs)


class LowLevelILGe(LowLevelILBinaryOp):
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_GE, lhs, rhs)


class LowLevelILAnd(LowLevelILBinaryOp):
    '''Bitwise AND'''
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_AND, lhs, rhs)


class LowLevelILOr(LowLevelILBinaryOp):
    '''Bitwise OR'''
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_OR, lhs, rhs)


class LowLevelILLogicalAnd(LowLevelILBinaryOp):
    '''Logical AND (&&)'''
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_LOGICAL_AND, lhs, rhs)


class LowLevelILLogicalOr(LowLevelILBinaryOp):
    '''Logical OR (||)'''
    def __init__(self, lhs: 'LowLevelILExpr' = None, rhs: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_LOGICAL_OR, lhs, rhs)


# === Unary Operations ===

class LowLevelILUnaryOp(LowLevelILExpr, UnaryOperation):
    '''Base class for unary operations (expression)'''

    def __init__(self, operation: LowLevelILOperation, operand: 'LowLevelILExpr' = None):
        super().__init__(operation)
        self.operand = operand

    def __str__(self) -> str:
        if self.operand:
            return f'{self.operation_name}({self.operand})'
        return self.operation_name


class LowLevelILNeg(LowLevelILUnaryOp):
    '''Arithmetic negation (-x)'''
    def __init__(self, operand: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_NEG, operand)


class LowLevelILBitwiseNot(LowLevelILUnaryOp):
    '''Bitwise NOT (~x)'''
    def __init__(self, operand: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_BITWISE_NOT, operand)


class LowLevelILTestZero(LowLevelILUnaryOp):
    '''Test if zero (x == 0)'''
    def __init__(self, operand: 'LowLevelILExpr' = None):
        super().__init__(LowLevelILOperation.LLIL_TEST_ZERO, operand)


# === Control Flow ===

class LowLevelILGoto(LowLevelILStatement, Terminal):
    '''Unconditional jump - target must be a BasicBlock (terminal)'''

    def __init__(self, target: 'LowLevelILBasicBlock'):
        super().__init__(LowLevelILOperation.LLIL_JMP)
        self.target = target

    def __str__(self) -> str:
        return f'goto {self.target.block_name}'


class LowLevelILJmp(LowLevelILGoto):
    '''Alias for LowLevelILGoto for convenience'''
    pass


class LowLevelILIf(LowLevelILStatement, Terminal):
    '''Conditional branch - targets must be BasicBlocks (terminal)'''

    def __init__(self, condition: 'LowLevelILBinaryOp', true_target: 'LowLevelILBasicBlock',
                 false_target: Optional['LowLevelILBasicBlock'] = None):
        super().__init__(LowLevelILOperation.LLIL_BRANCH)
        self.condition = condition  # An instruction that produces a boolean value
        self.true_target = true_target
        self.false_target = false_target

    def __str__(self) -> str:
        true_name = self.true_target.block_name
        if self.false_target:
            false_name = self.false_target.block_name
            return f'if {self.condition} goto {true_name} else {false_name}'
        else:
            return f'if {self.condition} goto {true_name}'


class LowLevelILCall(LowLevelILStatement, Terminal):
    '''Function call (terminal)'''

    def __init__(
        self,
        target: str,
        return_target: Optional['LowLevelILBasicBlock'],
        args: List['LowLevelILExpr'] = None,
        *,
        returns: bool = True,
    ):
        super().__init__(LowLevelILOperation.LLIL_CALL)
        self.target = target
        self.return_target = return_target  # Where to return after call (None if returns is False)
        self.args = args if args is not None else []  # Arguments (used by MLIL translator)
        self.returns = returns  # False for a tail call that never gives control back to this function

    def __str__(self) -> str:
        if self.args:
            return f'call {self.target}({', '.join(str(arg) for arg in self.args)})'
        else:
            return f'call {self.target}'


class LowLevelILRet(LowLevelILStatement, Terminal):
    '''Return from function (terminal)'''

    def __init__(self):
        super().__init__(LowLevelILOperation.LLIL_RET)

    def __str__(self) -> str:
        return 'return'


# === Constants and Special ===

class LowLevelILConst(LowLevelILExpr, Constant):
    '''Constant value (int, float, or string) (expression)'''

    def __init__(self, value: Union[int, float, str], is_hex: bool = False, is_raw: bool = False):
        super().__init__(LowLevelILOperation.LLIL_CONST)
        self.value = value
        self.is_hex = is_hex  # True to display as hex, False for decimal (default)
        self.is_raw = is_raw  # True for raw values (type-less), False for typed constants

    def __str__(self) -> str:
        if isinstance(self.value, str):
            return f"'{self.value}'"

        elif isinstance(self.value, float):
            # Format float with up to 6 decimal places, strip trailing zeros
            formatted = f'{self.value:.6f}'
            # Remove trailing zeros and decimal point if not needed
            formatted = formatted.rstrip('0').rstrip('.')
            return formatted

        elif isinstance(self.value, int):
            # Raw values are always displayed in hex
            if self.is_raw:
                if self.value < 0:
                    return f'-0x{-self.value:X}'
                else:
                    return f'0x{self.value:X}'
            elif self.is_hex:
                # Hex display
                if self.value < 0:
                    # Negative hex: -0xAB
                    return f'-0x{-self.value:X}'
                else:
                    return f'0x{self.value:X}'
            else:
                # Decimal display
                return str(self.value)

        else:
            return str(self.value)


class LowLevelILLabelInstr(LowLevelILStatement):
    '''Label instruction (for marking positions in code) (statement)'''

    def __init__(self, name: str):
        super().__init__(LowLevelILOperation.LLIL_LABEL)
        self.name = name

    def __str__(self) -> str:
        return f'{self.name}:'


class LowLevelILDebug(LowLevelILStatement):
    '''Debug information (statement)'''

    def __init__(self, debug_type: str, value: Any):
        super().__init__(LowLevelILOperation.LLIL_DEBUG)
        self.debug_type = debug_type
        self.value = value

    def __str__(self) -> str:
        return f'dbg_{self.debug_type.lower()} {self.value}'


# === VM Specific ===

class LowLevelILSyscall(LowLevelILStatement):
    '''System call (statement)'''

    def __init__(self, subsystem: int, cmd: int, argc: int, args: List['LowLevelILExpr'] = None):
        super().__init__(LowLevelILOperation.LLIL_SYSCALL)
        self.subsystem = subsystem
        self.cmd = cmd
        self.argc = argc
        self.args = args if args is not None else []  # Argument expressions (from vstack)

    def __str__(self) -> str:
        if self.args:
            args_str = ', '.join(str(arg) for arg in self.args)
            return f'SYSCALL({self.subsystem}, 0x{self.cmd:02x}, {args_str})'
        else:
            return f'SYSCALL({self.subsystem}, 0x{self.cmd:02x}, {self.argc})'


# === Helper Functions ===

def default_label_for_addr(addr: int) -> str:
    '''Generate default label name from address'''
    return f'loc_{addr:X}'


# === Container Classes ===

class LowLevelILBasicBlock:
    '''Basic block containing LLIL instructions (following BN design)'''

    def __init__(self, start: int, index: int = 0, label: Optional[str] = None):
        self.start = start
        self.end = start
        self.index = index  # Block index in function
        self.label = label if label is not None else default_label_for_addr(start)
        self.instructions: List[LowLevelILInstruction] = []
        self.sp_in = 0   # sp state at block entry
        self.sp_out = 0  # sp state at block exit
        self.function: Optional['LowLevelILFunction'] = None  # Set when block added to a function

        # Control flow edges (following BN design)
        self.outgoing_edges: List['LowLevelILBasicBlock'] = []
        self.incoming_edges: List['LowLevelILBasicBlock'] = []

    def add_instruction(self, inst: LowLevelILInstruction):
        '''Add instruction to this block'''
        if self.has_terminal:
            raise RuntimeError(
                f'Cannot add instruction to {self.block_name}: '
                f'block already has terminal instruction {self.instructions[-1]}'
            )

        if inst.inst_index != -1:
            raise RuntimeError(
                f'Instruction {inst} already registered (inst_index = {inst.inst_index}). '
                f'Instructions should not be reused across blocks.'
            )

        self.instructions.append(inst)

        if self.function is not None:
            self.function._register_instruction(self, inst)

    def add_outgoing_edge(self, target: 'LowLevelILBasicBlock'):
        '''Add outgoing edge to another block'''
        if target not in self.outgoing_edges:
            self.outgoing_edges.append(target)
        if self not in target.incoming_edges:
            target.incoming_edges.append(self)

    @property
    def has_terminal(self) -> bool:
        '''Check if block ends with a terminal instruction'''
        if not self.instructions:
            return False
        return isinstance(self.instructions[-1], Terminal)

    @property
    def block_name(self) -> str:
        '''Get canonical block name for jump targets and references'''
        return f'block_{self.index}'

    @property
    def label_name(self) -> Optional[str]:
        '''Get label name if this block starts with a label instruction'''
        if self.instructions and isinstance(self.instructions[0], LowLevelILLabelInstr):
            return self.instructions[0].name
        return None

    def __str__(self) -> str:
        result = f'{self.block_name} {self.label} @ {hex(self.start)}: [sp={self.sp_in}]\n'
        # for i, inst in enumerate(self.instructions):
        #     result += f'  {inst}\n'
        if self.outgoing_edges:
            targets = [b.block_name for b in self.outgoing_edges]
            result += f'  -> {', '.join(targets)}\n'
        return result


class LowLevelILFunction:
    '''Function containing LLIL basic blocks (following BN design)'''

    def __init__(self, name: str, start_addr: int = 0, params: List['IRParameter'] = None, *, is_common_func: bool = False):
        self.name = name
        self.start_addr = start_addr
        self.params: List['IRParameter'] = params or []
        self.basic_blocks: List[LowLevelILBasicBlock] = []
        self._block_map: dict[int, LowLevelILBasicBlock] = {}  # addr -> block
        self._label_map: dict[str, LowLevelILBasicBlock] = {}  # label -> block
        self.frame_base_sp: Optional[int] = None  # Frame pointer (sp at function entry)
        self._next_inst_index: int = 0
        self._inst_block_map: dict[int, LowLevelILBasicBlock] = {}
        self._instructions: List[LowLevelILInstruction] = []
        self.is_common_func = is_common_func

    @property
    def num_params(self) -> int:
        '''Number of parameters (for backward compatibility)'''
        return len(self.params)

    def add_basic_block(self, block: LowLevelILBasicBlock):
        '''Add basic block to function'''
        block.index = len(self.basic_blocks)
        block.function = self
        self.basic_blocks.append(block)
        self._block_map[block.start] = block
        self._label_map[block.label] = block

    def _register_instruction(self, block: LowLevelILBasicBlock, inst: LowLevelILInstruction):
        '''Assign a global instruction index and track block association'''
        inst.inst_index = self._next_inst_index
        self._next_inst_index += 1
        self._instructions.append(inst)
        self._inst_block_map[inst.inst_index] = block

    def get_instruction_by_index(self, inst_index: int) -> Optional[LowLevelILInstruction]:
        '''Get instruction by global inst_index'''
        if inst_index < 0 or inst_index >= len(self._instructions):
            return None
        return self._instructions[inst_index]

    def get_instruction_block_by_index(self, inst_index: int) -> Optional[LowLevelILBasicBlock]:
        '''Get the basic block containing the instruction with inst_index'''
        return self._inst_block_map.get(inst_index)

    def iter_instructions(self):
        '''Iterate over instructions in insertion order'''
        return iter(self._instructions)

    def get_block_by_addr(self, addr: int) -> Optional[LowLevelILBasicBlock]:
        '''Get basic block by start address'''
        return self._block_map.get(addr)

    def get_block_by_label(self, label: str) -> Optional[LowLevelILBasicBlock]:
        '''Get block by label name (O(1) lookup using label map)'''
        return self._label_map.get(label)

    def build_cfg(self):
        '''Build control flow graph from terminal instructions'''
        for block in self.basic_blocks:
            if not block.instructions:
                continue

            last_inst = block.instructions[-1]

            # Terminal instructions already have their edges set via block references
            if isinstance(last_inst, LowLevelILGoto):
                # Edge already created: block -> target
                block.add_outgoing_edge(last_inst.target)

            elif isinstance(last_inst, LowLevelILIf):
                # Both targets must be explicitly specified
                if any([
                    last_inst.true_target is None,
                    last_inst.false_target is None,
                ]):
                    raise RuntimeError(
                        f'Block {block.index} has If instruction with no true_target or false_target. '
                        f'Both true_target and false_target must be explicitly specified.'
                    )

                block.add_outgoing_edge(last_inst.true_target)
                block.add_outgoing_edge(last_inst.false_target)

            elif isinstance(last_inst, LowLevelILCall):
                if not last_inst.returns:
                    # Tail call - caller never regains control, no outgoing edge
                    pass

                # Call returns to explicit return target
                elif last_inst.return_target is not None:
                    return_block = last_inst.return_target
                    # Resolve label if needed
                    if isinstance(return_block, str):
                        return_block = self.get_block_by_label(return_block)
                        if return_block is None:
                            raise RuntimeError(f'Undefined return label: {last_inst.return_target}')

                    block.add_outgoing_edge(return_block)

                else:
                    raise NotImplementedError('Fall through is not supported')
                    # next_idx = block.index + 1
                    # if next_idx < len(self.basic_blocks):
                    #     block.add_outgoing_edge(self.basic_blocks[next_idx])

            elif not isinstance(last_inst, Terminal):
                # Should not happen - all blocks must end with terminal
                raise RuntimeError(
                    f'Block {block} {block.label} ends with non-terminal instruction: {last_inst}'
                )

    def __str__(self) -> str:
        result = f'; ---------- {self.name} ----------\n'
        for block in self.basic_blocks:
            result += str(block)
        return result
