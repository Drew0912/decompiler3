"""LLIL - Stack-based low-level IR"""

from typing import Any, Iterator
from dc3 import format_signed_hex, IntEnum2, quote_string
from ir.core import *

# Constants
WORD_SIZE = 4  # bytes per stack word


class LowLevelILOperation(IntEnum2):
    """Atomic LLIL operations"""

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

    # VM specific
    LLIL_SYSCALL            = 60    # system call
    LLIL_DEBUG              = 61    # debug info
    LLIL_STACK_ADDR         = 62    # address of stack location (sp + offset)

    # Generic pointer dereference (address computed at runtime, not a known stack/frame slot)
    LLIL_LOAD               = 63    # load *ptr
    LLIL_STORE              = 64    # *ptr = value
    LLIL_FRAME_ADDR         = 65    # address of frame-relative location (fp + offset)

    # User-defined extensions (reserved range: 1003+)
    LLIL_USER_DEFINED       = 1003  # Start of user-defined operations


class LowLevelILInstruction(ILInstruction):
    """Base class for all LLIL instructions"""

    def __init__(self, operation: LowLevelILOperation):
        super().__init__()
        self.address = 0
        self.inst_index = UNASSIGNED_INST_INDEX  # Assigned via LowLevelILFunction._register_instruction
        self.operation = operation

    @property
    def operation_name(self) -> str:
        """Get operation name without LLIL_ prefix (e.g., 'LLIL_ADD' -> 'ADD')"""
        return self.operation.name.replace('LLIL_', '')

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        """Direct expression operands in evaluation order - none for a leaf. Every node holding an expression
        overrides this; walk() is built on it"""
        return ()

    def __str__(self) -> str:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {str(self)}>'


# === Instruction Categories (following BinaryNinja design) ===

class LowLevelILExpr(LowLevelILInstruction):
    """Base class for value expressions"""


class LowLevelILStatement(LowLevelILInstruction):
    """Base class for statements"""


# === Offset Text ===

def sp_offset_text(offset: int) -> str:
    """A byte offset from sp in words, as the listing shows it: 'sp', 'sp + 1', 'sp - 1'"""
    words = offset // WORD_SIZE
    if words == 0:
        return 'sp'

    return f'sp + {words}' if words > 0 else f'sp - {-words}'


def frame_offset_text(offset: int) -> str:
    """A byte offset from the frame base in words, as the listing shows it: 'fp + 0', 'fp + 1', 'fp - 1'"""
    words = offset // WORD_SIZE
    return f'fp + {words}' if words >= 0 else f'fp - {-words}'


# === Atomic Stack Operations ===

class LowLevelILStackStore(LowLevelILStatement):
    """STACK[sp + offset] = value"""

    def __init__(self, value: LowLevelILInstruction | int | str, offset: int = 0, slot_index: int = None):
        super().__init__(LowLevelILOperation.LLIL_STACK_STORE)
        self.value = value
        self.offset = offset  # Byte offset
        self.slot_index = slot_index  # Absolute stack slot index

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'STACK[{sp_offset_text(self.offset)}] = {self.value}'


class LowLevelILStackLoad(LowLevelILExpr):
    """Load STACK[sp + offset]"""

    def __init__(self, offset: int, slot_index: int):
        super().__init__(LowLevelILOperation.LLIL_STACK_LOAD)
        self.offset = offset  # Byte offset
        self.slot_index = slot_index  # Absolute stack slot index

    def __str__(self) -> str:
        return f'STACK[{sp_offset_text(self.offset)}<{self.slot_index}>]'


class LowLevelILFrameLoad(LowLevelILExpr):
    """Load STACK[frame + offset]"""

    def __init__(self, offset: int = 0):
        super().__init__(LowLevelILOperation.LLIL_FRAME_LOAD)
        self.offset = offset  # Byte offset relative to frame

    def __str__(self) -> str:
        return f'STACK[{frame_offset_text(self.offset)}]'


class LowLevelILFrameStore(LowLevelILStatement):
    """STACK[frame + offset] = value"""

    def __init__(self, value: LowLevelILInstruction | int | str, offset: int = 0):
        super().__init__(LowLevelILOperation.LLIL_FRAME_STORE)
        self.value = value
        self.offset = offset  # Byte offset relative to frame

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'STACK[{frame_offset_text(self.offset)}] = {self.value}'


class LowLevelILLoad(LowLevelILExpr):
    """Load *src - generic pointer dereference (address computed at runtime, e.g. a parameter
    that itself holds a pointer, unlike StackLoad/FrameLoad whose slot is known statically)"""

    def __init__(self, src: LowLevelILExpr):
        super().__init__(LowLevelILOperation.LLIL_LOAD)
        self.src = src

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.src,)

    def __str__(self) -> str:
        return f'*{self.src}'


class LowLevelILStore(LowLevelILStatement):
    """*dest = value - generic pointer dereference store"""

    def __init__(self, dest: LowLevelILExpr, value: LowLevelILExpr):
        super().__init__(LowLevelILOperation.LLIL_STORE)
        self.dest = dest
        self.value = value

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.dest, self.value)

    def __str__(self) -> str:
        return f'*{self.dest} = {self.value}'


class LowLevelILSpAdd(LowLevelILStatement):
    """sp = sp + delta (statement)"""

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
    """Address of stack slot (sp-independent)"""

    def __init__(self, slot_index: int):
        super().__init__(LowLevelILOperation.LLIL_STACK_ADDR)
        self.slot_index = slot_index  # Absolute stack slot index

    def __str__(self) -> str:
        return f'&STACK[{self.slot_index}]'


class LowLevelILFrameAddr(LowLevelILExpr):
    """Address of STACK[frame + offset] - the frame-relative sibling of StackAddr, for taking
    the address of a parameter rather than a local (mirrors FrameLoad/FrameStore)"""

    def __init__(self, offset: int = 0):
        super().__init__(LowLevelILOperation.LLIL_FRAME_ADDR)
        self.offset = offset  # Byte offset relative to frame

    def __str__(self) -> str:
        return f'&STACK[{frame_offset_text(self.offset)}]'


# === Register Operations ===

class LowLevelILRegStore(LowLevelILStatement):
    """REG[index] = value (statement)"""

    def __init__(self, reg_index: int, value: LowLevelILInstruction | int):
        super().__init__(LowLevelILOperation.LLIL_REG_STORE)
        self.reg_index = reg_index
        self.value = value

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'REG[{self.reg_index}] = {self.value}'


class LowLevelILRegLoad(LowLevelILExpr):
    """load REG[index] (expression)"""

    def __init__(self, reg_index: int):
        super().__init__(LowLevelILOperation.LLIL_REG_LOAD)
        self.reg_index = reg_index

    def __str__(self) -> str:
        return f'REG[{self.reg_index}]'


# === Arithmetic Operations ===

class LowLevelILBinaryOp(LowLevelILExpr):
    """Base for binary operations (expression): each subclass sets only its OPERATION"""

    OPERATION: LowLevelILOperation

    def __init__(self, lhs: LowLevelILExpr, rhs: LowLevelILExpr):
        super().__init__(self.OPERATION)
        self.lhs = lhs  # Left operand expression
        self.rhs = rhs  # Right operand expression

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.lhs, self.rhs)

    def __str__(self) -> str:
        return f'{self.operation_name}({self.lhs}, {self.rhs})'


class LowLevelILAdd(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_ADD


class LowLevelILMul(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_MUL


class LowLevelILSub(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_SUB


class LowLevelILDiv(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_DIV


class LowLevelILMod(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_MOD


class LowLevelILEq(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_EQ


class LowLevelILNe(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_NE


class LowLevelILLt(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_LT


class LowLevelILLe(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_LE


class LowLevelILGt(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_GT


class LowLevelILGe(LowLevelILBinaryOp):
    OPERATION = LowLevelILOperation.LLIL_GE


class LowLevelILAnd(LowLevelILBinaryOp):
    """Bitwise AND"""

    OPERATION = LowLevelILOperation.LLIL_AND


class LowLevelILOr(LowLevelILBinaryOp):
    """Bitwise OR"""

    OPERATION = LowLevelILOperation.LLIL_OR


class LowLevelILLogicalAnd(LowLevelILBinaryOp):
    """Logical AND (&&)"""

    OPERATION = LowLevelILOperation.LLIL_LOGICAL_AND


class LowLevelILLogicalOr(LowLevelILBinaryOp):
    """Logical OR (||)"""

    OPERATION = LowLevelILOperation.LLIL_LOGICAL_OR


# === Unary Operations ===

class LowLevelILUnaryOp(LowLevelILExpr):
    """Base class for unary operations (expression): each subclass sets only its OPERATION"""

    OPERATION: LowLevelILOperation

    def __init__(self, operand: LowLevelILExpr):
        super().__init__(self.OPERATION)
        self.operand = operand

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.operand,)

    def __str__(self) -> str:
        return f'{self.operation_name}({self.operand})'


class LowLevelILNeg(LowLevelILUnaryOp):
    """Arithmetic negation (-x)"""

    OPERATION = LowLevelILOperation.LLIL_NEG


class LowLevelILBitwiseNot(LowLevelILUnaryOp):
    """Bitwise NOT (~x)"""

    OPERATION = LowLevelILOperation.LLIL_BITWISE_NOT


class LowLevelILTestZero(LowLevelILUnaryOp):
    """Test if zero (x == 0)"""

    OPERATION = LowLevelILOperation.LLIL_TEST_ZERO


# === Control Flow ===

class LowLevelILJmp(LowLevelILStatement, Terminal):
    """Unconditional jump - target must be a BasicBlock (terminal)"""

    def __init__(self, target: LowLevelILBasicBlock):
        super().__init__(LowLevelILOperation.LLIL_JMP)
        self.target = target

    def __str__(self) -> str:
        return f'goto {self.target.block_name}'


class LowLevelILIf(LowLevelILStatement, Terminal):
    """Conditional branch - targets must be BasicBlocks (terminal)"""

    def __init__(self, condition: LowLevelILBinaryOp, true_target: LowLevelILBasicBlock,
                 false_target: LowLevelILBasicBlock):
        super().__init__(LowLevelILOperation.LLIL_BRANCH)
        self.condition = condition  # An instruction that produces a boolean value
        self.true_target = true_target
        self.false_target = false_target

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.condition,)

    def __str__(self) -> str:
        return f'if {self.condition} goto {self.true_target.block_name} else {self.false_target.block_name}'


class LowLevelILCall(LowLevelILStatement, Terminal):
    """Function call (terminal)"""

    def __init__(
        self,
        target: str,
        return_target: LowLevelILBasicBlock | None,
        args: list[LowLevelILExpr] = None,
        *,
        returns: bool = True,
    ):
        super().__init__(LowLevelILOperation.LLIL_CALL)
        self.target = target
        self.return_target = return_target  # Where to return after call (None if returns is False)
        self.args = args if args is not None else []  # Argument expressions
        self.returns = returns  # False for a tail call that never gives control back to this function

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return tuple(self.args)

    def __str__(self) -> str:
        if self.args:
            return f'call {self.target}({', '.join(str(arg) for arg in self.args)})'
        else:
            return f'call {self.target}'


class LowLevelILRet(LowLevelILStatement, Terminal):
    """Return from function (terminal)"""

    def __init__(self):
        super().__init__(LowLevelILOperation.LLIL_RET)

    def __str__(self) -> str:
        return 'return'


# === Constants and Special ===

class LowLevelILConst(LowLevelILExpr, Constant):
    """Constant value (int, float, or string) (expression)"""

    def __init__(self, value: int | float | str, is_raw: bool = False):
        super().__init__(LowLevelILOperation.LLIL_CONST)
        self.value = value
        self.is_raw = is_raw  # True for raw values (type-less), False for typed constants

    def __str__(self) -> str:
        if isinstance(self.value, str):
            return quote_string(self.value, "'")

        # Raw values always print in hex
        if isinstance(self.value, int) and self.is_raw:
            return format_signed_hex(self.value)

        return str(self.value)


class LowLevelILDebug(LowLevelILStatement):
    """Debug information (statement)"""

    def __init__(self, debug_type: str, value: Any):
        super().__init__(LowLevelILOperation.LLIL_DEBUG)
        self.debug_type = debug_type
        self.value = value

    def __str__(self) -> str:
        return f'dbg_{self.debug_type.lower()} {self.value}'


# === VM Specific ===

class LowLevelILSyscall(LowLevelILStatement):
    """System call (statement)"""

    def __init__(self, subsystem: int, cmd: int, argc: int, args: list[LowLevelILExpr] = None):
        super().__init__(LowLevelILOperation.LLIL_SYSCALL)
        self.subsystem = subsystem
        self.cmd = cmd
        self.argc = argc
        self.args = args if args is not None else []  # Argument expressions (from vstack)

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return tuple(self.args)

    def __str__(self) -> str:
        if self.args:
            args_str = ', '.join(str(arg) for arg in self.args)
            return f'SYSCALL({self.subsystem}, 0x{self.cmd:02x}, {args_str})'
        else:
            return f'SYSCALL({self.subsystem}, 0x{self.cmd:02x}, {self.argc})'


# === Traversal ===

def walk(node: LowLevelILInstruction, skip: tuple[type, ...] = ()) -> Iterator[LowLevelILInstruction]:
    """node and every expression below it, pre-order in evaluation order; a node that is an instance of a type in skip
    (subclasses included) is yielded but not descended into"""
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        if skip and isinstance(current, skip):
            continue
        operands = current.operands()
        if len(operands) == 1:
            pending.append(operands[0])
        elif operands:
            pending.extend(reversed(operands))


# === Helper Functions ===

def default_label_for_addr(addr: int) -> str:
    """Generate default label name from address"""
    return f'loc_{addr:X}'


# === Container Classes ===

class LowLevelILBasicBlock(ILBasicBlock):
    """Basic block containing LLIL instructions (following BN design)"""

    def __init__(self, start: int, label: str | None = None):
        # The index is set by LowLevelILFunction.add_basic_block
        super().__init__(0, start, label if label is not None else default_label_for_addr(start))
        self.sp_in = 0   # sp state at block entry
        self.function: LowLevelILFunction | None = None  # Set when block added to a function

    def add_instruction(self, inst: LowLevelILInstruction):
        """Add instruction to this block, registered with its function once it has one"""
        super().add_instruction(inst)

        if self.function is not None:
            self.function._register_instruction(inst)

    @property
    def block_name(self) -> str:
        """Get canonical block name for jump targets and references"""
        return f'block_{self.index}'

    def __str__(self) -> str:
        result = f'{self.block_name} {self.label} @ {hex(self.start)}: [sp={self.sp_in}]\n'
        if self.outgoing_edges:
            targets = [b.block_name for b in self.outgoing_edges]
            result += f'  -> {', '.join(targets)}\n'
        return result


class LowLevelILFunction:
    """Function containing LLIL basic blocks (following BN design)"""

    def __init__(self, name: str, start_addr: int = 0, params: list[IRParameter] = None):
        self.name = name
        self.start_addr = start_addr
        self.params: list[IRParameter] = params or []
        self.basic_blocks: list[LowLevelILBasicBlock] = []
        self._block_map: dict[int, LowLevelILBasicBlock] = {}  # addr -> block
        self._label_map: dict[str, LowLevelILBasicBlock] = {}  # label -> block
        self.frame_base_sp: int | None = None  # Frame pointer (sp at function entry)
        self._next_inst_index: int = 0

    @property
    def num_params(self) -> int:
        """Number of parameters"""
        return len(self.params)

    def add_basic_block(self, block: LowLevelILBasicBlock):
        """Add basic block to function"""
        if block.label in self._label_map:
            raise RuntimeError(f'A block is already labelled {block.label}')

        block.index = len(self.basic_blocks)
        block.function = self
        self.basic_blocks.append(block)
        self._block_map[block.start] = block
        self._label_map[block.label] = block

    def _register_instruction(self, inst: LowLevelILInstruction):
        """Assign the next global instruction index"""
        inst.inst_index = self._next_inst_index
        self._next_inst_index += 1

    def reindex_in_block_order(self):
        """Renumber the instructions in basic-block list order, regardless of the order they were originally
        registered in"""
        self._next_inst_index = 0
        for block in self.basic_blocks:
            for inst in block.instructions:
                self._register_instruction(inst)

    def get_block_by_addr(self, addr: int) -> LowLevelILBasicBlock | None:
        """Get basic block by start address"""
        return self._block_map.get(addr)

    def get_block_by_label(self, label: str) -> LowLevelILBasicBlock | None:
        """Get block by label name (O(1) lookup using label map)"""
        return self._label_map.get(label)

    def build_cfg(self):
        """Rebuild the control flow graph from terminal instructions, replacing the edges of any earlier build. The
        successors are found before an edge changes, so an unsupported terminal keeps the previous graph"""
        edges = [(block, target) for block in self.basic_blocks for target in self._successors(block)]
        for block in self.basic_blocks:
            block.outgoing_edges.clear()
            block.incoming_edges.clear()

        for block, target in edges:
            block.add_outgoing_edge(target)

    def _successors(self, block: LowLevelILBasicBlock) -> list[LowLevelILBasicBlock]:
        """Return the block's CFG successors; raise for an unsupported terminal"""
        if not block.instructions:
            return []

        last_inst = block.instructions[-1]
        if isinstance(last_inst, LowLevelILJmp):
            return [last_inst.target]
        elif isinstance(last_inst, LowLevelILIf):
            return [last_inst.true_target, last_inst.false_target]
        elif isinstance(last_inst, LowLevelILCall):
            return [last_inst.return_target] if last_inst.returns else []   # a tail call has no return edge
        elif isinstance(last_inst, LowLevelILRet):
            return []
        else:
            raise RuntimeError(f'{block.block_name} {block.label} does not end with a supported terminal: {last_inst}')

    def __str__(self) -> str:
        result = f'; ---------- {self.name} ----------\n'
        for block in self.basic_blocks:
            result += str(block)
        return result
