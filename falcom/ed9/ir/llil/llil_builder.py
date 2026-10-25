"""Falcom VM Builder - High-level builder with Falcom VM patterns"""

from dataclasses import dataclass, replace
from enum import Enum, auto
from typing import NamedTuple
from ir.llil import *
from falcom.ed9.disasm.stack_effects import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS
from .constants import *
from .llil_ext import *


class CallSetupKind(Enum):
    """Which call a pending setup is for"""

    LOCAL = auto()    # PUSH_CURRENT_FUNC_ID + PUSH_RET_ADDR ... CALL
    SCRIPT = auto()   # PUSH_CALLER_FRAME ... CALL_SCRIPT


class SetupShape(NamedTuple):
    """A pending setup as code after an edge observes it"""

    kind: str
    sp_before_call: int
    return_block: str | None


@dataclass(frozen=True)
class PendingCallSetup:
    """A call setup pushed but not yet consumed by its call"""

    kind: CallSetupKind
    sp_before_call: int
    return_block: LowLevelILBasicBlock | None   # None while a LOCAL setup awaits PUSH_RET_ADDR

    def shape(self) -> SetupShape:
        return_name = None if self.return_block is None else self.return_block.block_name
        return SetupShape(self.kind.name, self.sp_before_call, return_name)


class FalcomStackShape(NamedTuple):
    sp: int
    slots: tuple[int, ...]
    setups: tuple[SetupShape, ...]


@dataclass
class FalcomStackSnapshot(StackSnapshot):
    """Pending call setups are stack state too: a branch's arms each see the setups pushed before it"""

    pending_setups: tuple[PendingCallSetup, ...]

    def shape(self) -> FalcomStackShape:
        return FalcomStackShape(*super().shape(), tuple(setup.shape() for setup in self.pending_setups))


class FalcomVMBuilder(LowLevelILBuilder):
    """High-level builder with Falcom VM patterns"""

    PARAMETER_COPY_HINT = 'work on a LOAD_STACK copy instead'

    def __init__(self):
        """Create builder without function (call create_function first)"""
        super().__init__()
        self._pending_setups: list[PendingCallSetup] = []   # Innermost last

    def finalize(self) -> LowLevelILFunction:
        """Finalize builder and return function"""
        self.function.build_cfg()
        self.function.reindex_in_block_order()
        return self.function

    # === Virtual Stack Management ===

    def push(self, value: LowLevelILExpr | int | float | str, *, hidden_for_formatter: bool = False):
        if isinstance(value, LowLevelILConstScript):
            # The script pointer takes two slots
            super().push(value, hidden_for_formatter=hidden_for_formatter)

        return super().push(value, hidden_for_formatter=hidden_for_formatter)

    def save_stack_state(self) -> FalcomStackSnapshot:
        """Snapshot sp, the virtual stack and the pending call setups together"""
        snapshot = super().save_stack_state()
        return FalcomStackSnapshot(snapshot.sp, snapshot.values, tuple(self._pending_setups))

    def restore_stack_state(self, snapshot: FalcomStackSnapshot):
        """Restore sp, the virtual stack and the pending call setups"""
        super().restore_stack_state(snapshot)
        self._pending_setups = list(snapshot.pending_setups)

    # === Call Setup Tracking ===

    def _consume_setup(self, setup: PendingCallSetup, call_slots: int):
        """After the call is emitted: the callee pops the setup and args, and the return edge continues
        from that state - without the consumed setup"""
        self._cleanup_stack(call_slots)
        self._pending_setups.pop()
        self._record_edge_state(setup.return_block)

    # === Falcom Specific Constants ===

    def push_func_id(self):
        """Push current function ID - opens a local call setup, completed by push_ret_addr"""
        sp_before_call = self.sp_get()
        self.push(LowLevelILConstFuncId())
        self._pending_setups.append(PendingCallSetup(CallSetupKind.LOCAL, sp_before_call, return_block=None))

    def push_ret_addr(self, target: LowLevelILBasicBlock):
        """Push return address - completes the open local call setup"""
        setup = self._pending_setups[-1]
        self.push(LowLevelILConstRetAddrBlock(target))
        self._pending_setups[-1] = replace(setup, return_block=target)

    def push_caller_frame(self, return_target: LowLevelILBasicBlock):
        """PUSH_CALLER_FRAME operation - opens a script call setup, consumed by call_script"""
        sp_before_call = self.sp_get()
        self.push(LowLevelILConstFuncId())
        self.push(LowLevelILConstRetAddrBlock(return_target))
        self.push(LowLevelILConstScript())
        self.push(LowLevelILConstScriptName())
        self._pending_setups.append(PendingCallSetup(CallSetupKind.SCRIPT, sp_before_call, return_target))

    def call_local(self, target: str, arg_count: int):
        """CALL operation - arg_count is the callee's declared parameter count; the callee pops them and the setup"""
        setup = self._pending_setups[-1]
        args = self.vstack_peek_many(arg_count)   # last pushed first

        self.call(target, return_target=setup.return_block, args=args)
        self._consume_setup(setup, LOCAL_SETUP_SLOTS + arg_count)

    def call_script(self, module: str, func: str, arg_count: int):
        """CALL_SCRIPT operation - call a script function"""
        setup = self._pending_setups[-1]
        args = self.vstack_peek_many(arg_count)   # last pushed first

        self.add_instruction(LowLevelILCallScript(module, func, args, setup.return_block))
        self._consume_setup(setup, CALLER_FRAME_SLOTS + arg_count)

    def call_script_no_return(self, module: str, func: str, arg_count: int):
        """CALL_SCRIPT_NO_RETURN operation - tail call to a script function, no return to caller

        No call setup precedes this opcode in the bytecode, and it never consumes one. The args
        stay logically on the vstack (the callee's frame takes over rather than this function
        reading them back), so _cleanup_stack brings the tracked sp back to 0 without emitting IL -
        matching the bytecode, which emits no cleanup POP before a tail call.
        """
        parameters = self._describe_untracked_parameters(arg_count)
        if parameters is not None:
            raise RuntimeError(
                f"forwards {parameters} to a tail call, which the decompiler can't follow - pass LOAD_STACK copies "
                f'through registers (SET_REG, pop the parameters, GET_REG)'
            )

        args = self.vstack_peek_many(arg_count)   # last pushed first
        self.add_instruction(LowLevelILCallScriptNoReturn(module, func, args))

        self._cleanup_stack(arg_count)

    # === VM Operations ===

    def push_int(self, value: int):
        """PUSH_INT operation"""
        self.push(self.const_int(value))

    def push_str(self, value: str):
        """PUSH_STR operation"""
        self.push(self.const_str(value))

    def push_raw(self, value: int):
        """PUSH_RAW operation - push raw 4-byte value without type info"""
        self.push(self.const_raw(value))

    def set_reg(self, reg_index: int):
        """SET_REG operation"""
        stack_val = self.pop(hidden_for_formatter=True)
        self.reg_store(reg_index, stack_val)

    def get_reg(self, reg_index: int):
        """GET_REG operation"""
        reg_val = self.reg_load(reg_index)
        self.push(reg_val)

    def pop_to(self, offset: int):
        """POP_TO operation - pop and store to STACK[sp + offset]"""
        val = self.pop(hidden_for_formatter=True)
        # offset is relative to sp after the pop
        self._store_slot(val, self._slot_index(offset), offset)

    def _resolve_deref_param_ptr(self, slot_index: int, opcode_name: str):
        """The pointer a dereference goes through - only a caller-supplied one, in a parameter the function still
        holds: a pointer in any other slot may point into this function's own frame"""
        if not self._holds_parameter(slot_index):
            raise NotImplementedError(
                f'{opcode_name} requires a slot still holding a caller parameter, got slot {slot_index}'
            )

        return self.frame_load(self._frame_offset(slot_index))

    def load_stack_deref(self, offset: int):
        """LOAD_STACK_DEREF operation - dereference the pointer at STACK[sp + offset], push *ptr"""
        ptr = self._resolve_deref_param_ptr(self._slot_index(offset), 'LOAD_STACK_DEREF')
        self.push(LowLevelILLoad(ptr))

    def pop_to_deref(self, offset: int):
        """POP_TO_DEREF operation - pop and store through the pointer at STACK[sp + offset]
        (*ptr = value)"""
        val = self.pop(hidden_for_formatter=True)
        # offset is relative to sp after the pop (mirrors pop_to)
        ptr = self._resolve_deref_param_ptr(self._slot_index(offset), 'POP_TO_DEREF')
        self.add_instruction(LowLevelILStore(ptr, val))

    def pop_jmp_zero(self, true_target, false_target):
        """POP_JMP_ZERO operation - branch if popped value is zero"""
        cond = self.pop(hidden_for_formatter=True)
        self.branch_if(LowLevelILEq(cond, self.const_int(0)), true_target, false_target)

    def pop_jmp_not_zero(self, true_target, false_target):
        """POP_JMP_NOT_ZERO operation - branch if popped value is not zero"""
        # NOT_ZERO is the inverse of ZERO, so swap the targets
        self.pop_jmp_zero(false_target, true_target)

    def pop_bytes(self, num_bytes: int, *, hidden_for_formatter: bool = False):
        """POP operation - discard N bytes from stack"""
        self.pop_n(num_bytes // WORD_SIZE, hidden_for_formatter=hidden_for_formatter)

    def pop_n(self, count: int, *, hidden_for_formatter: bool = False):
        """POP_N operation - discard N slots from stack"""
        self.emit_sp_add(-count, hidden_for_formatter=hidden_for_formatter)
        self._discard_vstack_to(self.sp_get())

    def load_global(self, index: int):
        """LOAD_GLOBAL operation - push global variable onto stack"""
        global_val = LowLevelILGlobalLoad(index)
        self.push(global_val)

    def set_global(self, index: int):
        """SET_GLOBAL operation - pop from stack and store to global"""
        val = self.pop(hidden_for_formatter=True)
        self.add_instruction(LowLevelILGlobalStore(index, val))

    def syscall(self, subsystem: int, cmd: int, argc: int):
        """SYSCALL operation - Falcom VM system call"""
        args = self.vstack_peek_many(argc)   # read in place, last pushed first
        self.add_instruction(LowLevelILSyscall(subsystem, cmd, argc, args))

    def debug_log(self, argc: int):
        """DEBUG_LOG operation - log the top argc stack values (message first), then pop them"""
        args = self.vstack_peek_many(argc)
        self.add_instruction(LowLevelILDebugLog(args))

        if argc > 0:
            self.pop_n(argc)
