'''Falcom VM Builder - High-level builder with Falcom VM patterns'''

from math import exp
from typing import Union
from ir.llil import *
from .constants import *
from .llil_ext import *


class FalcomVMBuilder(LowLevelILBuilder):
    '''High-level builder with Falcom VM patterns'''

    def __init__(self):
        '''Create builder without function (call create_function first)'''
        super().__init__()
        self.sp_before_call_stack = []  # Stack of sp values before calls for nested calls
        self.return_target_stack = []  # Stack of return target blocks for nested calls
        self.caller_frame_inst = None  # Track PUSH_CALLER_FRAME instruction for call_script
        self._finalized = False

    def add_instruction(self, inst):
        '''Override to handle Falcom-specific instructions'''

        super().add_instruction(inst)

    def finalize(self) -> 'LowLevelILFunction':
        '''Finalize builder and return function'''

        if self.sp_get() != 0:
            raise RuntimeError(f'Stack is not empty at the end of the function. Current sp: {self.sp_get()}')

        self.function.build_cfg()

        if self.function is None:
            raise RuntimeError('No function created. Call create_function() first.')

        if self._finalized:
            raise RuntimeError('Builder already finalized')

        # Check for pending call setup
        if self.sp_before_call_stack:
            pending_sp = ', '.join([str(sp) for sp in self.sp_before_call_stack])
            raise RuntimeError(
                f'Function ended with pending call setups at sp={pending_sp}. '
                f'Incomplete call sequence detected (push_func_id without call).'
            )

        if self.return_target_stack:
            pending = ', '.join([block.label for block in self.return_target_stack])
            raise RuntimeError(
                f'Function ended with pending return targets: {pending}. '
                f'Incomplete call sequence detected (push_ret_addr without call).'
            )

        self._finalized = True
        return self.function

    # === Virtual Stack Management ===

    def push(self, value: Union[LowLevelILExpr, int, float, str], *, hidden_for_formatter: bool = False):
        '''Push value onto stack (SPEC-compliant: StackStore + SpAdd)'''

        if isinstance(value, LowLevelILConstScript):
            # 8 bytes script pointer
            super().push(value, hidden_for_formatter = hidden_for_formatter)

        return super().push(value, hidden_for_formatter = hidden_for_formatter)

    def pop(self, *, hidden_for_formatter: bool = False) -> LowLevelILExpr:
        '''Pop value from stack and emit SpAdd'''
        expr = super().pop(hidden_for_formatter = hidden_for_formatter)

        if isinstance(expr, LowLevelILConstScript):
            # 8 bytes script pointer - pop the second slot
            expr_clone = super().pop()
            if expr_clone is not expr:
                raise RuntimeError(f'Script pointer mismatch: {expr_clone} != {expr}')

        return expr

    # === Falcom Specific Constants ===

    def push_func_id(self):
        '''Push current function ID - marks the start of call setup'''
        # Save sp before we start pushing for the call (supports nesting)
        self.sp_before_call_stack.append(self.sp_get())
        self.stack_push(FalcomConstants.current_func_id())

    def push_ret_addr(self, target: LowLevelILBasicBlock):
        '''Push return address and remember it for call instruction'''
        # Verify push_func_id was called first

        if not isinstance(target, LowLevelILBasicBlock):
            raise RuntimeError(f'target must be a LowLevelILBasicBlock, got {type(target)}')

        if not self.sp_before_call_stack:
            raise RuntimeError(
                'push_ret_addr called without push_func_id. '
                'Call push_func_id() first to set up the call.'
            )
        # Push return target onto stack (supports nested calls)
        self.return_target_stack.append(target)
        self.stack_push(FalcomConstants.ret_addr_block(target))

    def push_caller_frame(self, return_target: LowLevelILBasicBlock):
        '''PUSH_CALLER_FRAME operation - save caller frame for module call'''
        # Save sp before we start pushing for the call (supports nesting)
        self.sp_before_call_stack.append(self.sp_get())

        # Prepare the 4 values
        func_id = FalcomConstants.current_func_id()
        ret_addr = FalcomConstants.ret_addr_block(return_target)
        script = FalcomConstants.current_script()
        script_name = FalcomConstants.current_script_name('')  # Empty string for now

        # Push return target onto stack (supports nested calls)
        self.return_target_stack.append(return_target)

        # Create and add the atomic PUSH_CALLER_FRAME instruction
        # This occupies 4 stack slots
        push_frame_inst = LowLevelILPushCallerFrame(func_id, ret_addr, script, script_name)
        push_frame_inst.slot_index = self.sp_get()
        # self.add_instruction(push_frame_instr)

        self.push(func_id)
        self.push(ret_addr)
        self.push(script)
        self.push(script_name)

        # Save reference for call_script to use
        self.caller_frame_inst = push_frame_inst

    def call(self, target):
        '''Falcom VM call - automatically cleans up stack (callee cleanup convention)'''
        # Verify call setup was done
        if not self.return_target_stack:
            raise RuntimeError(
                'No return target set. Did you forget to call push_ret_addr()?'
            )
        if not self.sp_before_call_stack:
            raise RuntimeError(
                'No call setup found. Did you forget to call push_func_id()?'
            )

        # Pop return block and sp from stacks
        return_block = self.return_target_stack.pop()
        sp_before_call = self.sp_before_call_stack.pop()

        # Calculate argc: total values pushed = sp_get() - sp_before_call
        # This includes: func_id (1) + ret_addr (1) + args (N)
        argc = self.sp_get() - sp_before_call

        if argc < 0:
            raise RuntimeError(f'argc is negative: {argc}')

        # Verify we have at least func_id and ret_addr
        if argc < 2:
            raise RuntimeError(
                f'Expected at least 2 values (func_id, ret_addr), got {argc}'
            )

        # Verify sp alignment: restored sp must match target block's entry sp
        # Only check if block has been visited (has instructions or sp_in was explicitly set)
        restored_sp = sp_before_call
        if return_block.instructions:
            # Block has been built, verify sp matches
            if return_block.sp_in != restored_sp:
                raise RuntimeError(
                    f'Stack pointer mismatch when connecting to {return_block.block_name}: '
                    f'call restores sp to {restored_sp}, but target block has sp_in={return_block.sp_in}. '
                    f'This indicates inconsistent stack management.'
                )

        # Peek arguments from vstack before cleanup
        if argc is not None and argc > 2:
            # argc includes func_id + ret_addr + actual args
            # Peek actual args (argc - 2)
            args = self.vstack_peek_many(argc - 2)
        else:
            args = []

        # Create call with arguments
        super().call(target, return_target = return_block, args = args)

        # Clean up stack (func_id + ret_addr + args)
        if argc > 0:
            self._cleanup_stack(argc)

    def call_script(self, module: str, func: str, arg_count: int):
        '''CALL_SCRIPT operation - call a script function'''
        # Verify call setup was done
        if not self.return_target_stack:
            raise RuntimeError(
                'No return target set. Did you forget to call push_caller_frame()?'
            )
        if not self.sp_before_call_stack:
            raise RuntimeError(
                'No call setup found. Did you forget to call push_caller_frame()?'
            )
        if self.caller_frame_inst is None:
            raise RuntimeError(
                'No caller frame instruction found. Did you forget to call push_caller_frame()?'
            )

        # Pop return block and sp from stacks
        return_block = self.return_target_stack.pop()
        sp_before_call = self.sp_before_call_stack.pop()

        # Pop arguments from vstack (in reverse order: last arg first)
        offset = -1
        args = [self.vstack_peek(offset - i) for i in range(arg_count)]

        # Verify caller frame via StackLoad -> expr mapping
        func_id_load     = self.vstack_peek(offset - arg_count - 4)
        ret_addr_load    = self.vstack_peek(offset - arg_count - 3)
        script_load      = self.vstack_peek(offset - arg_count - 1)
        script_name_load = self.vstack_peek(offset - arg_count - 0)

        if not all([
            self.get_source_expr(func_id_load) is self.caller_frame_inst.func_id,
            self.get_source_expr(ret_addr_load) is self.caller_frame_inst.ret_addr,
            self.get_source_expr(script_load) is self.caller_frame_inst.script_ptr,
            self.get_source_expr(script_name_load) is self.caller_frame_inst.script_name,
        ]):
            raise RuntimeError('Caller frame mismatch')

        # Create and add CALL_SCRIPT instruction
        # This represents the call that cleans up args + 4 caller frame values
        call_inst = LowLevelILCallScript(module, func, self.caller_frame_inst, args, return_block)
        self.add_instruction(call_inst)

        # Emit SpAdd to represent stack cleanup (arg_count + 4 caller frame values)

        cleanup_count = arg_count + (1 + 1 + 2 + 1)
        self._cleanup_stack(cleanup_count)

        # Verify stack is balanced
        if self.sp_get() != sp_before_call:
            raise RuntimeError(
                f'Stack imbalance in call_script: after cleaning up {arg_count} args + 4 caller frame, '
                f'current_sp={self.sp_get()} but expected sp_before_call={sp_before_call}'
            )

        # Clean up state
        self.caller_frame_inst = None

    def call_script_no_return(self, module: str, func: str, arg_count: int):
        '''CALL_SCRIPT_NO_RETURN operation - tail call to a script function, no return to caller

        No push_caller_frame/push_ret_addr pair precedes this opcode in the bytecode, so
        return_target_stack/sp_before_call_stack are not touched. The args stay logically on the
        vstack (the callee's frame takes over rather than this function reading them back), so
        _cleanup_stack brings the tracked sp back to 0 without emitting IL - matching the bytecode,
        which emits no cleanup POP before a tail call.
        '''
        offset = -1
        args = [self.vstack_peek(offset - i) for i in range(arg_count)]

        call_inst = LowLevelILCallScriptNoReturn(module, func, args)
        self.add_instruction(call_inst)

        self._cleanup_stack(arg_count)

        # A tail call replaces the rest of the function - nothing but its own arguments can be
        # live at this point. Checked immediately, not left to finalize()'s end-of-function check:
        # this block has no successor, so a leak here never propagates anywhere for finalize() to
        # see, and a later block reached via a different branch would restore its own saved sp
        # snapshot and silently paper over it (Codex Rule 0 finding, see notes/codex_rules.md).
        if self.sp_get() != 0:
            raise RuntimeError(
                f'Stack imbalance in call_script_no_return: after cleaning up {arg_count} args, '
                f'current_sp={self.sp_get()} but a tail call must leave sp=0'
            )

    # === VM Operations ===

    def push_int(self, value: int, is_hex: bool = False):
        '''PUSH_INT operation'''
        self.stack_push(self.const_int(value, is_hex = is_hex))

    def push_str(self, value: str):
        '''PUSH_STR operation'''
        self.stack_push(self.const_str(value))

    def push_raw(self, value: int):
        '''PUSH_RAW operation - push raw 4-byte value without type info'''
        self.stack_push(self.const_raw(value))

    def set_reg(self, reg_index: int):
        '''SET_REG operation'''
        # Pop from stack using StackPop expression
        stack_val = self.pop(hidden_for_formatter = True)
        self.reg_store(reg_index, stack_val)

    def get_reg(self, reg_index: int):
        '''GET_REG operation'''
        reg_val = self.reg_load(reg_index)
        self.stack_push(reg_val)

    def pop_to(self, offset: int):
        '''POP_TO operation - pop and store to STACK[sp + offset]'''
        val = self.pop(hidden_for_formatter = True)
        # offset is relative to sp AFTER pop (new_sp + offset)
        slot_index = self.sp_get() + offset // WORD_SIZE
        self.add_instruction(LowLevelILStackStore(val, offset = offset, slot_index = slot_index))

    def pop_jmp_zero(self, true_target, false_target):
        '''POP_JMP_ZERO operation - branch if popped value is zero'''
        # Pop from stack using StackPop expression
        cond = self.pop(hidden_for_formatter = True)
        # Create EQ(cond, 0) without adding as instruction
        # This is just used as the branch condition expression
        zero = self.const_int(0)
        is_zero = LowLevelILEq(cond, zero)
        # Create If with both targets explicitly specified
        self.add_instruction(LowLevelILIf(is_zero, true_target, false_target))

    def pop_jmp_not_zero(self, true_target, false_target):
        '''POP_JMP_NOT_ZERO operation - branch if popped value is not zero'''
        # NOT_ZERO is the inverse of ZERO, so swap the targets
        self.pop_jmp_zero(false_target, true_target)

    def pop_bytes(self, num_bytes: int, *, hidden_for_formatter: bool = False):
        '''POP operation - discard N bytes from stack'''
        # Convert bytes to words
        if num_bytes % WORD_SIZE != 0:
            raise ValueError(f'num_bytes ({num_bytes}) must be a multiple of WORD_SIZE ({WORD_SIZE})')

        num_words = num_bytes // WORD_SIZE
        self.emit_sp_add(-num_words, hidden_for_formatter = hidden_for_formatter)

    def pop_n(self, count: int, *, hidden_for_formatter: bool = False):
        '''POP_N operation - discard N slots from stack'''

        if count <= 0:
            raise ValueError(f'count ({count}) must be positive')

        self.emit_sp_add(-count, hidden_for_formatter = hidden_for_formatter)

    def load_global(self, index: int):
        '''LOAD_GLOBAL operation - push global variable onto stack'''
        global_val = LowLevelILGlobalLoad(index)
        self.stack_push(global_val)

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
