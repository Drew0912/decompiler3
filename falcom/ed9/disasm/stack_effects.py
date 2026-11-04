"""What each kind of ED9 instruction does to the VM stack, one effect per kind"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Sequence
from ir.llil import WORD_SIZE

__all__ = (
    'InstructionKind',
    'OperandCount',
    'CalleeParamCount',
    'PoppedBytes',
    'PopCarry',
    'StackEffect',
    'STACK_EFFECTS',
    'LOCAL_SETUP_SLOTS',
    'CALLER_FRAME_SLOTS',
    'POP_SIZE_OPERAND',
    'POPN_COUNT_OPERAND',
    'ARGC_OPERAND',
    'SLOT_OFFSET_OPERAND',
    'CALLEE_OPERAND',
    'REGISTER_OPERAND',
    'RESULT_REGISTER',
    'REGISTER_COUNT',
)

LOCAL_SETUP_SLOTS       = 2     # CALL: func_id, ret_addr
CALLER_FRAME_SLOTS      = 5     # PUSH_CALLER_FRAME: func_id, ret_addr, script pointer (2 slots), frame marker
POP_SIZE_OPERAND        = 0     # POP's byte count
POPN_COUNT_OPERAND      = 0     # POPN's slot count
ARGC_OPERAND            = 2     # the argument count of every argument call but CALL, whose count is its callee's parameters
SLOT_OFFSET_OPERAND     = 0     # the byte offset of a slot-addressing opcode
CALLEE_OPERAND          = 0     # CALL's callee, whose parameters are its argument count
REGISTER_OPERAND        = 0     # GET_REG / SET_REG's register
RESULT_REGISTER         = 0     # where a returning call leaves its result
REGISTER_COUNT          = 16    # the VM's registers (GET_REG / SET_REG)


class InstructionKind(Enum):
    """What an instruction does to the stack; every opcode table row has one"""

    PUSH_CONST          = auto()    # PUSH and its constant pseudo-ops
    SLOT_ADDRESS        = auto()    # PUSH_STACK_OFFSET
    LOAD_SLOT           = auto()
    LOAD_DEREF          = auto()
    LOAD_GLOBAL         = auto()
    LOAD_REG            = auto()    # GET_REG: a register's value, a call's result after a call
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
    POPN                = auto()
    DEBUG_INT           = auto()


@dataclass(frozen=True)
class OperandCount:
    """A count read from an operand"""

    index   : int


@dataclass(frozen=True)
class CalleeParamCount:
    """A local CALL's argument count: what its callee, the operand at index, declares - each walker looks it up"""

    index   : int


@dataclass(frozen=True)
class PoppedBytes:
    """POP's count, the bytes in the operand at index: each walker counts them through its PopCarry, as a POP may
    end inside a slot that the POP right after it completes"""

    index   : int


@dataclass
class PopCarry:
    """The bytes a walker's last POP popped past a whole slot: the compiler splits a pop of more than 255 bytes into
    POP 255 and a POP completing the slots, and the VM rounds nothing, so they carry into the next POP"""

    carried : int = 0       # bytes popped past the last whole slot

    def pop(self, byte_count: int) -> int:
        """The whole slots a POP of byte_count bytes pops, the carried bytes counted first"""
        popped = self.carried + byte_count
        self.carried = popped % WORD_SIZE
        return popped // WORD_SIZE


@dataclass(frozen=True)
class StackEffect:
    """In order: pops (operands, or a call's arguments), the call setup below them, pushes"""

    pops            : int | OperandCount | CalleeParamCount | PoppedBytes = 0
    setup_pops      : int = 0
    reads           : int | OperandCount = 0     # values read in place, not popped (SYSCALL's arguments)
    pushes          : int = 0
    addresses_slot  : bool = False               # the offset operand counts from sp after the pops
    exits           : bool = False               # the walkers require an empty stack after it; the VM does not

    def pop_count(self, operand_values: Sequence, get_param_count: Callable[[Any], int] | None = None,
                  pop_carry: PopCarry | None = None) -> int:
        """Values popped above any call setup; a local CALL's are its callee's parameters, from the walker's lookup; a
        POP's are the whole slots its bytes complete, the walker's carried bytes first"""
        if isinstance(self.pops, CalleeParamCount):
            return get_param_count(operand_values[self.pops.index])

        if isinstance(self.pops, PoppedBytes):
            return pop_carry.pop(operand_values[self.pops.index])

        return self.resolve_count(self.pops, operand_values)

    def read_count(self, operand_values: Sequence[int]) -> int:
        """Values read in place, not popped"""
        return self.resolve_count(self.reads, operand_values)

    @classmethod
    def resolve_count(cls, count: int | OperandCount, operand_values: Sequence[int]) -> int:
        if isinstance(count, OperandCount):
            return operand_values[count.index]

        return count


STACK_EFFECTS = {
    InstructionKind.PUSH_CONST          : StackEffect(pushes=1),
    InstructionKind.SLOT_ADDRESS        : StackEffect(addresses_slot=True, pushes=1),
    InstructionKind.LOAD_SLOT           : StackEffect(addresses_slot=True, pushes=1),
    InstructionKind.LOAD_DEREF          : StackEffect(addresses_slot=True, pushes=1),
    InstructionKind.LOAD_GLOBAL         : StackEffect(pushes=1),
    InstructionKind.LOAD_REG            : StackEffect(pushes=1),
    InstructionKind.STORE_SLOT          : StackEffect(pops=1, addresses_slot=True),
    InstructionKind.STORE_DEREF         : StackEffect(pops=1, addresses_slot=True),
    InstructionKind.STORE_GLOBAL        : StackEffect(pops=1),
    InstructionKind.STORE_REG           : StackEffect(pops=1),
    InstructionKind.BINARY              : StackEffect(pops=2, pushes=1),
    InstructionKind.UNARY               : StackEffect(pops=1, pushes=1),
    InstructionKind.POP                 : StackEffect(pops=PoppedBytes(POP_SIZE_OPERAND)),
    InstructionKind.JUMP                : StackEffect(),
    InstructionKind.CONDITIONAL_JUMP    : StackEffect(pops=1),
    InstructionKind.PUSH_FUNC_ID        : StackEffect(pushes=1),
    InstructionKind.PUSH_RET_ADDR       : StackEffect(pushes=1),
    InstructionKind.PUSH_CALLER_FRAME   : StackEffect(pushes=CALLER_FRAME_SLOTS),
    InstructionKind.CALL                : StackEffect(pops=CalleeParamCount(CALLEE_OPERAND),
                                                      setup_pops=LOCAL_SETUP_SLOTS),
    InstructionKind.CALL_SCRIPT         : StackEffect(pops=OperandCount(ARGC_OPERAND), setup_pops=CALLER_FRAME_SLOTS),
    InstructionKind.TAIL_CALL           : StackEffect(pops=OperandCount(ARGC_OPERAND), exits=True),
    InstructionKind.SYSCALL             : StackEffect(reads=OperandCount(ARGC_OPERAND)),       # a later POP removes them
    InstructionKind.RETURN              : StackEffect(exits=True),
    InstructionKind.DEBUG_LINE          : StackEffect(),
    InstructionKind.POPN                : StackEffect(pops=OperandCount(POPN_COUNT_OPERAND)),
    InstructionKind.DEBUG_INT           : StackEffect(),
}
