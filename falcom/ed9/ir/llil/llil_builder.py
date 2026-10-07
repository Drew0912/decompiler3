'''Falcom VM Builder - High-level builder with Falcom VM patterns'''

from dataclasses import dataclass, replace
from enum import Enum, auto
from typing import List, NamedTuple, Optional, Tuple, Union
from ir.core import SourceFloat
from ir.llil import *
from falcom.ed9.disasm.stack_effects import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS
from falcom.ed9.parser.types_scp import ScpValue
from .constants import *
from .llil_ext import *


EMPTY_STACK_SP = 0   # ED9 calling convention: any real exit must leave the VM stack empty


class CallSetupKind(Enum):
    '''Which call a pending setup is for'''
    LOCAL = auto()    # PUSH_CURRENT_FUNC_ID + PUSH_RET_ADDR ... CALL
    SCRIPT = auto()   # PUSH_CALLER_FRAME ... CALL_SCRIPT


@dataclass(frozen = True)
class PendingCallSetup:
    '''A call setup pushed but not yet consumed by its call. slot_loads are the exact vstack
    entries the setup pushed, lowest slot first; the call checks they are all still in place.'''
    kind: CallSetupKind
    sp_before_call: int
    slot_loads: Tuple[LowLevelILStackLoad, ...]
    return_block: Optional[LowLevelILBasicBlock]   # None while a LOCAL setup awaits PUSH_RET_ADDR
    caller_frame: Optional[LowLevelILPushCallerFrame] = None


class SetupShape(NamedTuple):
    '''A pending setup as code after an edge observes it; intact[i] is whether slot load i is still the
    vstack entry at its slot - the call checks each one'''
    kind: str
    sp_before_call: int
    return_block: Optional[str]
    intact: Tuple[bool, ...]


class FalcomStackShape(NamedTuple):
    sp: int
    slots: Tuple[int, ...]
    setups: Tuple[SetupShape, ...]


@dataclass
class FalcomStackSnapshot(StackSnapshot):
    '''Pending call setups are stack state too: a branch's arms each see the setups pushed before it'''
    pending_setups: Tuple[PendingCallSetup, ...]

    def shape(self) -> FalcomStackShape:
        values_by_slot = {value.slot_index: value for value in self.values}
        setups = tuple(
            SetupShape(
                setup.kind.name,
                setup.sp_before_call,
                None if setup.return_block is None else setup.return_block.block_name,
                tuple(values_by_slot.get(load.slot_index) is load for load in setup.slot_loads),
            )
            for setup in self.pending_setups
        )
        return FalcomStackShape(*super().shape(), setups)


class FalcomVMBuilder(LowLevelILBuilder):
    '''High-level builder with Falcom VM patterns'''

    def __init__(self):
        '''Create builder without function (call create_function first)'''
        super().__init__()
        self._pending_setups: List[PendingCallSetup] = []   # Innermost last
        self._finalized = False

    def finalize(self) -> 'LowLevelILFunction':
        '''Finalize builder and return function'''
        if self.function is None:
            raise RuntimeError('No function created. Call create_function() first.')

        if self._finalized:
            raise RuntimeError('Builder already finalized')

        self._finish_block()

        # RPO can end on a non-exit block; exit operations validate their own stack state.
        self.function.build_cfg()
        self._require_recorded_edges()

        self.function.reindex_in_block_order()
        self._finalized = True
        return self.function

    # === Virtual Stack Management ===

    def push(self, value: Union[LowLevelILExpr, int, float, str], *, hidden_for_formatter: bool = False):
        '''Push value onto stack: StackStore + SpAdd (see docs/LLIL_DESIGN.md)'''

        if isinstance(value, LowLevelILConstScript):
            # 8 bytes script pointer
            super().push(value, hidden_for_formatter = hidden_for_formatter)

        return super().push(value, hidden_for_formatter = hidden_for_formatter)

    def save_stack_state(self) -> FalcomStackSnapshot:
        '''Snapshot sp, the virtual stack and the pending call setups together'''
        snapshot = super().save_stack_state()
        return FalcomStackSnapshot(snapshot.sp, snapshot.values, tuple(self._pending_setups))

    def restore_stack_state(self, snapshot: FalcomStackSnapshot):
        '''Restore sp, the virtual stack and the pending call setups'''
        if not isinstance(snapshot, FalcomStackSnapshot):
            raise TypeError(f'Expected FalcomStackSnapshot, got {type(snapshot).__name__}')

        super().restore_stack_state(snapshot)
        self._pending_setups = list(snapshot.pending_setups)

    # === Call Setup Tracking ===

    def _check_setup_slots(self, setup: PendingCallSetup):
        '''Every slot the setup pushed must still hold that push - after a POP, re-push or in-place
        store (POP_TO) over it, the call would read something else.'''
        for stack_load in setup.slot_loads:
            if stack_load.slot_index >= self.sp_get() or self.vstack_entry_at_slot(stack_load.slot_index) is not stack_load:
                raise RuntimeError(
                    f'{setup.kind.name} call setup slot {stack_load.slot_index} was popped or overwritten '
                    f'before its call'
                )

    def _require_setup(self, kind: CallSetupKind) -> PendingCallSetup:
        '''The innermost pending setup, checked to be a complete `kind` setup with its slots intact.
        Not popped here - the call pops it once the call is emitted.'''
        if not self._pending_setups:
            raise RuntimeError(f'{kind.name} call without a pending call setup')

        setup = self._pending_setups[-1]
        if setup.kind != kind:
            raise RuntimeError(f'{kind.name} call, but the innermost pending call setup is {setup.kind.name}')

        if setup.return_block is None:
            raise RuntimeError(f'{kind.name} call, but the innermost pending call setup has no return address yet')

        self._check_setup_slots(setup)
        return setup

    def _consume_setup(self, setup: PendingCallSetup, call_slots: int, call_inst: LowLevelILInstruction):
        '''After the call is emitted: the callee pops the setup and args, and the return edge continues
        from that state - without the consumed setup.'''
        self._cleanup_stack(call_slots)
        self._pending_setups.pop()
        self._record_edge_state(call_inst, setup.return_block)

    def _require_no_pending_setups(self, exit_name: str):
        '''A real exit ends the function, so no call setup may still be waiting for its call'''
        if self._pending_setups:
            raise RuntimeError(f'{exit_name} with {len(self._pending_setups)} call setup(s) still pending')

    # === Falcom Specific Constants ===

    def push_func_id(self):
        '''Push current function ID - opens a local call setup, completed by push_ret_addr'''
        sp_before_call = self.sp_get()
        self.push(FalcomConstants.current_func_id())
        self._pending_setups.append(PendingCallSetup(
            CallSetupKind.LOCAL, sp_before_call, (self.vstack_peek(),), return_block = None
        ))

    def push_ret_addr(self, target: LowLevelILBasicBlock):
        '''Push return address - completes the open local call setup'''
        self._require_registered_block(target)
        setup = self._pending_setups[-1] if self._pending_setups else None
        if setup is None or setup.kind != CallSetupKind.LOCAL or setup.return_block is not None:
            raise RuntimeError(
                'push_ret_addr needs the innermost pending call setup to be a local one still '
                'waiting for its return address'
            )

        # The return address must land directly above the setup's function ID
        self._check_setup_slots(setup)
        if self.sp_get() != setup.sp_before_call + len(setup.slot_loads):
            raise RuntimeError(
                f'push_ret_addr at sp={self.sp_get()}, but its function ID ends the stack at '
                f'sp={setup.sp_before_call + len(setup.slot_loads)}'
            )

        self.push(FalcomConstants.ret_addr_block(target))
        self._pending_setups[-1] = replace(
            setup, slot_loads = setup.slot_loads + (self.vstack_peek(),), return_block = target
        )

    def push_caller_frame(self, return_target: LowLevelILBasicBlock):
        '''PUSH_CALLER_FRAME operation - opens a script call setup, consumed by call_script'''
        self._require_registered_block(return_target)
        sp_before_call = self.sp_get()

        func_id = FalcomConstants.current_func_id()
        ret_addr = FalcomConstants.ret_addr_block(return_target)
        script = FalcomConstants.current_script()
        script_name = FalcomConstants.current_script_name('')  # Empty string for now

        # The atomic PUSH_CALLER_FRAME instruction, occupying CALLER_FRAME_SLOTS stack slots
        push_frame_inst = LowLevelILPushCallerFrame(func_id, ret_addr, script, script_name)
        push_frame_inst.slot_index = sp_before_call

        self.push(func_id)
        self.push(ret_addr)
        self.push(script)
        self.push(script_name)

        frame_loads = tuple(reversed(self.vstack_peek_many(CALLER_FRAME_SLOTS)))
        self._pending_setups.append(PendingCallSetup(
            CallSetupKind.SCRIPT, sp_before_call, frame_loads, return_target, push_frame_inst
        ))

    def call(self, target):
        '''Falcom VM call - automatically cleans up stack (callee cleanup convention)'''
        setup = self._require_setup(CallSetupKind.LOCAL)
        call_slots = self.sp_get() - setup.sp_before_call   # func_id + ret_addr + args

        arg_count = call_slots - LOCAL_SETUP_SLOTS
        args = self.vstack_peek_many(arg_count) if arg_count > 0 else []

        call_inst = super().call(target, return_target = setup.return_block, args = args)
        self._consume_setup(setup, call_slots, call_inst)

    def call_script(self, module: str, func: str, arg_count: int):
        '''CALL_SCRIPT operation - call a script function'''
        setup = self._require_setup(CallSetupKind.SCRIPT)

        call_slots = CALLER_FRAME_SLOTS + arg_count
        if self.sp_get() != setup.sp_before_call + call_slots:
            raise RuntimeError(
                f'Stack mismatch in call_script: sp={self.sp_get()}, but the caller frame and '
                f'{arg_count} args end at sp={setup.sp_before_call + call_slots}'
            )

        args = self.vstack_peek_many(arg_count) if arg_count > 0 else []   # last pushed first

        call_inst = LowLevelILCallScript(module, func, setup.caller_frame, args, setup.return_block)
        self.add_instruction(call_inst)
        self._consume_setup(setup, call_slots, call_inst)

    def call_script_no_return(self, module: str, func: str, arg_count: int):
        '''CALL_SCRIPT_NO_RETURN operation - tail call to a script function, no return to caller

        No call setup precedes this opcode in the bytecode, and it never consumes one. The args
        stay logically on the vstack (the callee's frame takes over rather than this function
        reading them back), so _cleanup_stack brings the tracked sp back to 0 without emitting IL -
        matching the bytecode, which emits no cleanup POP before a tail call.
        '''
        args = self.vstack_peek_many(arg_count) if arg_count > 0 else []   # last pushed first

        call_inst = LowLevelILCallScriptNoReturn(module, func, args)
        self.add_instruction(call_inst)

        self._cleanup_stack(arg_count)

        # A tail call replaces the rest of the function, so only its own arguments should be
        # live here. This block has no successor, so nothing else would ever validate a leak here.
        if self.sp_get() != EMPTY_STACK_SP:
            raise RuntimeError(
                f'Stack imbalance in call_script_no_return: after cleaning up {arg_count} args, '
                f'current_sp={self.sp_get()} but a tail call must leave sp={EMPTY_STACK_SP}'
            )

        self._require_no_pending_setups('Tail call')

    def ret(self):
        '''RETURN operation - the VM calling convention requires an empty stack at any real exit'''
        if self.sp_get() != EMPTY_STACK_SP:
            raise RuntimeError(
                f'Stack imbalance at return: current sp={self.sp_get()}, expected {EMPTY_STACK_SP}'
            )

        self._require_no_pending_setups('Return')
        super().ret()

    # === VM Operations ===

    def push_int(self, value: int, is_hex: bool = False):
        '''PUSH_INT operation'''
        self.push(self.const_int(value, is_hex = is_hex))

    def push_str(self, value: str):
        '''PUSH_STR operation'''
        self.push(self.const_str(value))

    def push_raw(self, value: int):
        '''PUSH_RAW operation - push raw 4-byte value without type info'''
        self.push(self.const_raw(value))

    def set_reg(self, reg_index: int):
        '''SET_REG operation'''
        # Pop from stack using StackPop expression
        stack_val = self.pop(hidden_for_formatter = True)
        self.reg_store(reg_index, stack_val)

    def get_reg(self, reg_index: int):
        '''GET_REG operation'''
        reg_val = self.reg_load(reg_index)
        self.push(reg_val)

    def pop_to(self, offset: int):
        '''POP_TO operation - pop and store to STACK[sp + offset]'''
        val = self.pop(hidden_for_formatter = True)
        # offset is relative to sp after the pop
        self._store_slot(val, self._slot_index(offset), offset)

    def _resolve_deref_param_ptr(self, slot_index: int, opcode_name: str):
        '''The pointer a dereference goes through - only a caller-supplied one, in a parameter the function still
        holds: a pointer in any other slot may point into this function's own frame.'''
        if not self._holds_parameter(slot_index):
            raise NotImplementedError(
                f'{opcode_name} requires a slot still holding a caller parameter, got slot {slot_index}'
            )

        return self.frame_load(self._frame_offset(slot_index))

    def load_stack_deref(self, offset: int):
        '''LOAD_STACK_DEREF operation - dereference the pointer at STACK[sp + offset], push *ptr'''
        ptr = self._resolve_deref_param_ptr(self._slot_index(offset), 'LOAD_STACK_DEREF')
        self.push(LowLevelILLoad(ptr))

    def pop_to_deref(self, offset: int):
        '''POP_TO_DEREF operation - pop and store through the pointer at STACK[sp + offset]
        (*ptr = value)'''
        val = self.pop(hidden_for_formatter = True)
        # offset is relative to sp after the pop (mirrors pop_to)
        ptr = self._resolve_deref_param_ptr(self._slot_index(offset), 'POP_TO_DEREF')
        self.add_instruction(LowLevelILStore(ptr, val))

    def pop_jmp_zero(self, true_target, false_target):
        '''POP_JMP_ZERO operation - branch if popped value is zero'''
        cond = self.pop(hidden_for_formatter = True)
        self.branch_if(LowLevelILEq(cond, self.const_int(0)), true_target, false_target)

    def pop_jmp_not_zero(self, true_target, false_target):
        '''POP_JMP_NOT_ZERO operation - branch if popped value is not zero'''
        # NOT_ZERO is the inverse of ZERO, so swap the targets
        self.pop_jmp_zero(false_target, true_target)

    def pop_bytes(self, num_bytes: int, *, hidden_for_formatter: bool = False):
        '''POP operation - discard N bytes from stack'''
        if num_bytes < 0:
            raise ValueError(f'num_bytes ({num_bytes}) must not be negative')

        if num_bytes % WORD_SIZE != 0:
            raise ValueError(f'num_bytes ({num_bytes}) must be a multiple of WORD_SIZE ({WORD_SIZE})')

        num_words = num_bytes // WORD_SIZE
        if num_words > self.sp_get():
            raise ValueError(
                f'num_bytes ({num_bytes}) would pop past the start of the stack (sp={self.sp_get()})'
            )

        self.emit_sp_add(-num_words, hidden_for_formatter = hidden_for_formatter)
        self._discard_vstack_to(self.sp_get())

    def pop_n(self, count: int, *, hidden_for_formatter: bool = False):
        '''POP_N operation - discard N slots from stack'''

        if count <= 0:
            raise ValueError(f'count ({count}) must be positive')

        if count > self.sp_get():
            raise ValueError(
                f'count ({count}) would pop past the start of the stack (sp={self.sp_get()})'
            )

        self.emit_sp_add(-count, hidden_for_formatter = hidden_for_formatter)
        self._discard_vstack_to(self.sp_get())

    def load_global(self, index: int):
        '''LOAD_GLOBAL operation - push global variable onto stack'''
        global_val = LowLevelILGlobalLoad(index)
        self.push(global_val)

    def set_global(self, index: int):
        '''SET_GLOBAL operation - pop from stack and store to global'''
        val = self.pop(hidden_for_formatter = True)
        self.add_instruction(LowLevelILGlobalStore(index, val))

    def syscall(self, subsystem: int, cmd: int, argc: int):
        '''SYSCALL operation - Falcom VM system call'''
        # Extract arguments from vstack (they were pushed before syscall)
        args = []
        if argc > 0:
            # Peek at top argc items (in LIFO order)
            args = self.vstack_peek_many(argc)

        self.add_instruction(LowLevelILSyscall(subsystem, cmd, argc, args))

    def debug_log(self, argc: int):
        '''DEBUG_LOG operation - log the top argc stack values (message first), then pop them'''
        args = self.vstack_peek_many(argc) if argc > 0 else []
        self.add_instruction(LowLevelILDebugLog(args))

        if argc > 0:
            self.pop_n(argc)


class FalcomLLILFormatter(LLILFormatter):
    @classmethod
    def _format_global_store_expanded(cls, global_store: 'LowLevelILGlobalStore') -> List[str]:
        '''Format global store with expanded pseudo-code'''
        return [
            f'GLOBAL[{global_store.index}] = STACK[--sp] ; {global_store.value}',
        ]

    @classmethod
    def format_instruction_expanded(cls, inst: LowLevelILInstruction) -> List[str]:
        if isinstance(inst, LowLevelILGlobalStore):
            return cls._format_global_store_expanded(inst)

        return super().format_instruction_expanded(inst)

    @classmethod
    def _format_simplified(cls, inst: LowLevelILInstruction) -> List[str]:
        lines = super()._format_simplified(inst)

        # A float from the bytecode also shows its exact bits; a plain float has none to show
        if isinstance(inst, LowLevelILStackStore) and isinstance(inst.value, LowLevelILConst):
            if isinstance(inst.value.value, SourceFloat):
                lines[-1] = f'{lines[-1]} {ScpValue.float_bits_text(inst.value.value)}'

        return lines
