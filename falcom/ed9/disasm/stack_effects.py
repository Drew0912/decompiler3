"""What each kind of ED9 instruction does to the VM stack, one effect per kind"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Sequence
from ir.llil import WORD_SIZE

__all__ = (
    'InstructionKind',
    'OperandCount',
    'CalleeParamCount',
    'StackEffect',
    'STACK_EFFECTS',
    'ONE_VALUE',
    'BINARY_OPERAND_COUNT',
    'LOCAL_SETUP_SLOTS',
    'CALLER_FRAME_SLOTS',
    'POP_SIZE_OPERAND',
    'DEBUG_LOG_ARGC_OPERAND',
    'ARGC_OPERAND',
    'SLOT_OFFSET_OPERAND',
    'CALLEE_OPERAND',
)

ONE_VALUE               = 1
BINARY_OPERAND_COUNT    = 2
LOCAL_SETUP_SLOTS       = 2     # CALL: func_id, ret_addr
CALLER_FRAME_SLOTS      = 5     # PUSH_CALLER_FRAME: func_id, ret_addr, script pointer (2 slots), script_name
POP_SIZE_OPERAND        = 0     # POP's byte count
DEBUG_LOG_ARGC_OPERAND  = 0
ARGC_OPERAND            = 2     # the argument count of every argument call but CALL, whose count is its callee's parameters
SLOT_OFFSET_OPERAND     = 0     # the byte offset of a slot-addressing opcode
CALLEE_OPERAND          = 0     # CALL's callee, whose parameters are its argument count


class InstructionKind(Enum):
    """What an instruction does to the stack; every opcode table row has one"""
    PUSH_CONST          = auto()    # PUSH and its constant pseudo-ops
    SLOT_ADDRESS        = auto()    # PUSH_STACK_OFFSET
    LOAD_SLOT           = auto()
    LOAD_DEREF          = auto()
    LOAD_GLOBAL         = auto()
    LOAD_REG            = auto()    # GET_REG: a call's result
    STORE_SLOT          = auto()    # POP_TO, the one store into a live slot
    STORE_DEREF         = auto()
    STORE_GLOBAL        = auto()
    STORE_REG           = auto()
    BINARY              = auto()
    UNARY               = auto()
    POP                 = auto()
    JUMP                = auto()
    CONDITIONAL_JUMP    = auto()
    PUSH_FUNC_ID        = auto()    # a local call's setup: PUSH_CURRENT_FUNC_ID, then PUSH_RET_ADDR
    PUSH_RET_ADDR       = auto()
    PUSH_CALLER_FRAME   = auto()    # a script call's setup
    CALL                = auto()
    CALL_SCRIPT         = auto()
    TAIL_CALL           = auto()    # CALL_SCRIPT_NO_RETURN
    SYSCALL             = auto()
    RETURN              = auto()
    DEBUG_LINE          = auto()    # DEBUG_SET_LINENO
    DEBUG_LOG           = auto()


@dataclass(frozen = True)
class OperandCount:
    """A count read from an operand; unit = WORD_SIZE when the operand counts bytes (POP)"""
    index   : int
    unit    : int = 1


@dataclass(frozen = True)
class CalleeParamCount:
    """A local CALL's argument count: its callee's declared parameters, looked up by each walker"""


@dataclass(frozen = True)
class StackEffect:
    """In order: pops (operands, or a call's arguments), the call setup below them, pushes"""
    pops            : int | OperandCount | CalleeParamCount = 0
    setup_pops      : int = 0
    reads           : int | OperandCount = 0     # values read in place, not popped (SYSCALL's arguments)
    pushes          : int = 0
    addresses_slot  : bool = False               # the offset operand counts from sp after the pops
    exits           : bool = False               # the stack must be empty afterwards

    def pop_count(self, operand_values: Sequence[int], callee_param_count: int | None = None) -> int:
        """Values popped above any call setup; a local CALL needs its callee's parameter count"""
        if isinstance(self.pops, CalleeParamCount):
            if callee_param_count is None:
                raise ValueError("a local CALL pops its callee's parameter count, which wasn't given")

            return callee_param_count

        return self.resolve_count(self.pops, operand_values)

    def read_count(self, operand_values: Sequence[int]) -> int:
        """Values read in place, not popped"""
        return self.resolve_count(self.reads, operand_values)

    @classmethod
    def resolve_count(cls, count: int | OperandCount, operand_values: Sequence[int]) -> int:
        if isinstance(count, OperandCount):
            return operand_values[count.index] // count.unit    # floored: POP's partial slot isn't popped

        return count


STACK_EFFECTS = {
    InstructionKind.PUSH_CONST          : StackEffect(pushes = ONE_VALUE),
    InstructionKind.SLOT_ADDRESS        : StackEffect(addresses_slot = True, pushes = ONE_VALUE),
    InstructionKind.LOAD_SLOT           : StackEffect(addresses_slot = True, pushes = ONE_VALUE),
    InstructionKind.LOAD_DEREF          : StackEffect(addresses_slot = True, pushes = ONE_VALUE),
    InstructionKind.LOAD_GLOBAL         : StackEffect(pushes = ONE_VALUE),
    InstructionKind.LOAD_REG            : StackEffect(pushes = ONE_VALUE),
    InstructionKind.STORE_SLOT          : StackEffect(pops = ONE_VALUE, addresses_slot = True),
    InstructionKind.STORE_DEREF         : StackEffect(pops = ONE_VALUE, addresses_slot = True),
    InstructionKind.STORE_GLOBAL        : StackEffect(pops = ONE_VALUE),
    InstructionKind.STORE_REG           : StackEffect(pops = ONE_VALUE),
    InstructionKind.BINARY              : StackEffect(pops = BINARY_OPERAND_COUNT, pushes = ONE_VALUE),
    InstructionKind.UNARY               : StackEffect(pops = ONE_VALUE, pushes = ONE_VALUE),
    InstructionKind.POP                 : StackEffect(pops = OperandCount(POP_SIZE_OPERAND, unit = WORD_SIZE)),
    InstructionKind.JUMP                : StackEffect(),
    InstructionKind.CONDITIONAL_JUMP    : StackEffect(pops = ONE_VALUE),
    InstructionKind.PUSH_FUNC_ID        : StackEffect(pushes = ONE_VALUE),
    InstructionKind.PUSH_RET_ADDR       : StackEffect(pushes = ONE_VALUE),
    InstructionKind.PUSH_CALLER_FRAME   : StackEffect(pushes = CALLER_FRAME_SLOTS),
    InstructionKind.CALL                : StackEffect(pops = CalleeParamCount(), setup_pops = LOCAL_SETUP_SLOTS),
    InstructionKind.CALL_SCRIPT         : StackEffect(pops = OperandCount(ARGC_OPERAND), setup_pops = CALLER_FRAME_SLOTS),
    InstructionKind.TAIL_CALL           : StackEffect(pops = OperandCount(ARGC_OPERAND), exits = True),
    InstructionKind.SYSCALL             : StackEffect(reads = OperandCount(ARGC_OPERAND)),     # a later POP removes them
    InstructionKind.RETURN              : StackEffect(exits = True),
    InstructionKind.DEBUG_LINE          : StackEffect(),
    InstructionKind.DEBUG_LOG           : StackEffect(pops = OperandCount(DEBUG_LOG_ARGC_OPERAND)),
}
