'''LLIL Builder'''

from dataclasses import dataclass
from typing import Union, Optional, List, NamedTuple, Tuple

from ir.core import IRParameter
from .llil import *


class _VirtualStack:
    '''Encapsulates the builder's virtual stack with save/restore support.'''

    def __init__(self):
        self._items: List[LowLevelILExpr] = []

    def push(self, expr: LowLevelILExpr):
        self._items.append(expr)

    def pop(self) -> LowLevelILExpr:
        if not self._items:
            raise RuntimeError('Vstack underflow: attempting to pop from empty vstack')
        return self._items.pop()

    def peek(self, offset: int = -1) -> LowLevelILExpr:
        if not self._items:
            raise RuntimeError('Vstack empty: cannot peek')
        return self._items[offset]

    def peek_many(self, count: int) -> List[LowLevelILExpr]:
        '''Peek last count items (LIFO order)'''
        if len(self._items) < count:
            raise RuntimeError(f'Vstack has only {len(self._items)} items, cannot peek {count}')

        # Get last count items and reverse (LIFO order)
        return self._items[-count:][::-1]

    def size(self) -> int:
        return len(self._items)

    def index_of_slot(self, slot_index: int) -> Optional[int]:
        '''List index of the entry tracking slot_index, or None if that slot is not tracked'''
        for index in range(len(self._items) - 1, -1, -1):
            entry_slot = self._items[index].slot_index
            if entry_slot == slot_index:
                return index

            if entry_slot < slot_index:
                break

        return None

    def replace(self, index: int, expr: LowLevelILExpr):
        self._items[index] = expr

    def snapshot(self) -> List[LowLevelILExpr]:
        return list(self._items)

    def restore(self, snapshot: List[LowLevelILExpr]):
        self._items = list(snapshot)


class StackShape(NamedTuple):
    '''What code after an edge observes of a stack state apart from slot values: predecessors may push
    different values into one slot (SSA merges them), but must agree on the stack layout.'''
    sp: int
    slots: Tuple[int, ...]


@dataclass
class StackSnapshot:
    sp: int
    values: List[LowLevelILExpr]

    def shape(self) -> StackShape:
        return StackShape(self.sp, tuple(value.slot_index for value in self.values))


class LowLevelILBuilder:
    '''Mid-level builder with convenience methods'''

    def __init__(self, function: Optional[LowLevelILFunction] = None):
        self.function = function
        self.current_block: Optional[LowLevelILBasicBlock] = None
        self.__current_sp: int = 0  # Track current stack pointer state (for block sp_in/sp_out) - PRIVATE
        self.frame_base_sp: Optional[int] = None  # Stack pointer at function entry (for frame-relative access)
        self.__vstack = _VirtualStack()  # Virtual stack for expression tracking
        self.saved_stacks: dict[int, StackSnapshot] = {}  # block start -> the state every edge into it must match
        # (source block, terminal, target) of every edge whose stack state was recorded
        self._recorded_edges: set[tuple[LowLevelILBasicBlock, LowLevelILInstruction, LowLevelILBasicBlock]] = set()
        self.__current_address: int = 0  # Current source instruction address
        if function is not None:
            self._seed_entry_state()

    # === Function and Block Creation ===

    def create_function(self, name: str, start_addr: int, params: Union[List[IRParameter], int] = None, *, num_params: int = None, is_common_func: bool = False):
        '''Create function inside builder

        Args:
            params: List of IRParameter, or int for backward compatibility (num_params)
            num_params: Deprecated, use params instead
            is_common_func: Whether this is a shared/included function (syscall wrapper)
        '''
        if self.function is not None:
            raise RuntimeError('Function already created')

        # Handle backward compatibility: num_params keyword or int positional
        if num_params is not None:
            params = [IRParameter(f'arg{i + 1}') for i in range(num_params)]

        elif isinstance(params, int):
            params = [IRParameter(f'arg{i + 1}') for i in range(params)]

        self.function = LowLevelILFunction(name, start_addr, params, is_common_func = is_common_func)
        self._seed_entry_state()

    def _seed_entry_state(self):
        '''The entry block starts with only the parameters on the stack (fp = 0 points at the first one), none
        of them tracked on the vstack. Recorded directly - it is the entry's state, not an edge.'''
        self.__sp_set(self.function.num_params)
        self.frame_base_sp = 0
        self.function.frame_base_sp = 0
        self.saved_stacks[self.function.start_addr] = self.save_stack_state()

    def create_basic_block(self, start: int, label: str = None) -> LowLevelILBasicBlock:
        '''Create basic block and automatically add to function'''
        if self.function is None:
            raise RuntimeError('No function created. Call create_function() first.')

        # Get next block index
        index = len(self.function.basic_blocks)
        # Create block
        block = LowLevelILBasicBlock(start, index, label = label)
        # Automatically add to function
        self.function.add_basic_block(block)
        return block

    # === Source Address Tracking ===

    def set_current_address(self, addr: int) -> None:
        """Set current source instruction address for subsequent LLIL instructions"""
        self.__current_address = addr

    def get_current_address(self) -> int:
        """Get current source instruction address"""
        return self.__current_address

    # === Stack Pointer Management (Public Interface) ===

    def sp_get(self) -> int:
        '''Get current stack pointer value'''
        return self.__current_sp

    def __sp_set(self, value: int):
        '''Set shadow SP to absolute value (does NOT emit IL) - PRIVATE'''
        self.__current_sp = value

    def __sp_adjust(self, delta: int):
        '''Adjust shadow SP by delta (does NOT emit IL) - PRIVATE'''
        self.__current_sp += delta

    def _cleanup_stack(self, argc: int) -> list[LowLevelILExpr]:
        '''Clean up stack and vstack without emitting IL - PRIVATE'''

        popped_values = []

        if argc > 0:
            self.__sp_adjust(-argc)
            # Pop from vstack (will raise if underflow - indicates bug in caller)
            for _ in range(argc):
                popped_values.append(self.__vstack_pop())

        return popped_values

    def emit_sp_add(self, delta: int, *, hidden_for_formatter: bool = False) -> LowLevelILSpAdd:
        '''Emit SpAdd IL and sync shadow sp (single entry point for SP changes)'''
        sp_add = LowLevelILSpAdd(delta)
        sp_add.options.hidden_for_formatter = hidden_for_formatter
        self.add_instruction(sp_add)
        # Note: add_instruction will handle the sp update via its existing logic
        return sp_add

    def _discard_vstack_to(self, new_sp: int):
        '''Sync the vstack after a bulk stack-pointer decrease.'''
        while self.__vstack.size() and self.__vstack.peek().slot_index >= new_sp:
            self.__vstack_pop()

        # Exact contiguity, not just increasing order - that would miss a hole left by an
        # earlier, unrelated desync.
        expected_slot = new_sp - 1
        for entry in reversed(self.__vstack.snapshot()):
            if entry.slot_index != expected_slot:
                raise RuntimeError(
                    f'Vstack desync after discard: expected slot_index {expected_slot}, '
                    f'found {entry.slot_index}'
                )
            expected_slot -= 1

    # === Virtual Stack Management (Public Interface) ===

    def __vstack_push(self, expr: LowLevelILExpr):
        '''Push expression to vstack (only accepts LowLevelILExpr)'''
        if not isinstance(expr, LowLevelILExpr):
            raise TypeError(f'vstack only accepts LowLevelILExpr, got {type(expr).__name__}')
        self.__vstack.push(expr)

    def __vstack_pop(self) -> LowLevelILExpr:
        '''Pop expression from vstack (returns LowLevelILExpr)'''
        return self.__vstack.pop()

    def vstack_peek(self, offset: int = -1) -> LowLevelILExpr:
        '''Peek at top of vstack without popping (returns LowLevelILExpr)'''
        return self.__vstack.peek(offset)

    def vstack_peek_many(self, count: int) -> List[LowLevelILExpr]:
        '''Peek at multiple items from vstack in LIFO order'''
        return self.__vstack.peek_many(count)

    def vstack_size(self) -> int:
        '''Get current vstack size'''
        return self.__vstack.size()

    def vstack_entry_at_slot(self, slot_index: int) -> Optional[LowLevelILExpr]:
        '''The vstack entry tracking slot_index, or None if that slot is not on the vstack'''
        index = self.__vstack.index_of_slot(slot_index)
        return None if index is None else self.__vstack.peek(index)

    def _refresh_stored_slot(self, store: Union[LowLevelILStackStore, LowLevelILFrameStore]):
        '''An in-place store gives its slot a new value, so a vstack entry still tracking that slot
        is replaced by a fresh StackLoad - identity checks on the old entry then see the overwrite.'''
        if isinstance(store, LowLevelILStackStore):
            slot_index = store.slot_index

        else:
            slot_index = self.frame_base_sp + store.offset // WORD_SIZE

        index = self.__vstack.index_of_slot(slot_index)
        if index is None:
            return

        self.__vstack.replace(index, LowLevelILStackLoad(offset = 0, slot_index = slot_index))

    def _require_registered_block(self, block: LowLevelILBasicBlock):
        '''Raise unless block belongs to this function.'''
        if not self.function.owns_block(block):
            name = block.label if isinstance(block, LowLevelILBasicBlock) else repr(block)
            raise RuntimeError(f'{name} is not a block of {self.function.name}')

    def _finish_block(self):
        '''Record the current block's exit sp, if any.'''
        if self.current_block is not None:
            self.current_block.sp_out = self.sp_get()

    def _start_block(self, block: LowLevelILBasicBlock):
        '''Start a registered block using the active stack state (create_function seeds the entry's).'''
        self.current_block = block
        block.sp_in = self.sp_get()

    def set_current_block(self, block: LowLevelILBasicBlock):
        '''Set the current basic block for instruction insertion'''
        self._require_registered_block(block)
        self._finish_block()
        self._start_block(block)

    def begin_block(self, block: LowLevelILBasicBlock):
        '''Close the current block, restore `block`'s recorded stack state, and open it.'''
        self._require_registered_block(block)
        self._finish_block()
        self.restore_stack_for_offset(block.start)
        self._start_block(block)

    def save_stack_state(self) -> StackSnapshot:
        '''Snapshot current stack pointer and virtual stack'''
        return StackSnapshot(self.sp_get(), self.__vstack.snapshot())

    def restore_stack_state(self, snapshot: StackSnapshot):
        '''Restore a trusted snapshot; its tracked slots determine slot storage.'''
        self.__sp_set(snapshot.sp)
        self.__vstack.restore(snapshot.values)

    def save_stack_for_offset(self, offset: int):
        '''Merge the current stack state into `offset`'s: the first merge records it, every later one must
        bring the same shape. Records no CFG edge - terminals record theirs via _record_edge_state.'''
        snapshot = self.save_stack_state()
        recorded = self.saved_stacks.get(offset)
        if recorded is None:
            self.saved_stacks[offset] = snapshot
            return

        incoming, expected = snapshot.shape(), recorded.shape()
        if incoming != expected:
            source = self.current_block.block_name if self.current_block is not None else 'outside any block'
            raise RuntimeError(
                f'Stack state mismatch on an edge from {source} into {offset:#x}: '
                f'incoming {incoming}, expected {expected}'
            )

    def restore_stack_for_offset(self, offset: int):
        '''Restore the stack state recorded for `offset`'''
        snapshot = self.saved_stacks.get(offset)
        if snapshot is None:
            raise RuntimeError(f'No stack state recorded for the block at {offset:#x} - no lifted edge reaches it')

        self.restore_stack_state(snapshot)

    def _record_edge_state(self, terminal: LowLevelILInstruction, target: LowLevelILBasicBlock):
        '''Record the CFG edge terminal -> target and merge the stack state it carries into target - only while
        terminal still ends the current block, so the state is the one the edge carries.'''
        self._require_registered_block(target)
        block = self.current_block
        if block is None or not block.instructions or block.instructions[-1] is not terminal:
            raise RuntimeError(
                f'Edge into {target.block_name} recorded for {terminal}, which does not end the current block'
            )

        self._recorded_edges.add((block, terminal, target))
        self.save_stack_for_offset(target.start)

    def _require_recorded_edges(self):
        '''After build_cfg: the recorded edges must be exactly the CFG's, so every real edge had its stack
        state checked and no stale or manual record stands in for one.'''
        cfg_edges = {
            (block, block.instructions[-1], target)
            for block in self.function.basic_blocks
            for target in block.outgoing_edges
        }

        def first(edges):
            return min(edges, key = lambda edge: (edge[0].index, edge[2].index))

        missing = cfg_edges - self._recorded_edges
        if missing:
            block, _, target = first(missing)
            raise RuntimeError(f'CFG edge {block.block_name} -> {target.block_name} has no recorded stack state')

        extra = self._recorded_edges - cfg_edges
        if extra:
            block, _, target = first(extra)
            raise RuntimeError(f'Recorded edge {block.block_name} -> {target.block_name} is not a CFG edge')

    def get_block_by_addr(self, addr: int) -> Optional[LowLevelILBasicBlock]:
        '''Get block by start address'''
        return self.function.get_block_by_addr(addr)

    def get_block_by_label(self, label: str) -> Optional[LowLevelILBasicBlock]:
        '''Get block by label name'''
        return self.function.get_block_by_label(label)

    def add_instruction(self, inst: LowLevelILInstruction):
        '''Add instruction to current block and update stack pointer tracking'''
        if self.current_block is None:
            raise RuntimeError('No current basic block set')

        # Set source address from current context
        inst.address = self.__current_address

        self.current_block.add_instruction(inst)

        # Update stack pointer based on instruction type
        if isinstance(inst, LowLevelILSpAdd):
            self.__sp_adjust(inst.delta)

        elif isinstance(inst, (LowLevelILStackStore, LowLevelILFrameStore)):
            self._refresh_stored_slot(inst)

    # === Virtual Stack Management ===

    def _to_expr(self, value: Union[LowLevelILExpr, int, float, str]) -> LowLevelILExpr:
        '''Convert value to expression (always returns LowLevelILExpr)'''
        if isinstance(value, LowLevelILExpr):
            return value

        elif isinstance(value, LowLevelILInstruction):
            # Should not happen - only Expr should be passed
            raise TypeError(f'Expected LowLevelILExpr, got {type(value).__name__}. Statements cannot be used as expressions.')

        elif isinstance(value, int):
            return self.const_int(value)

        elif isinstance(value, float):
            return self.const_float(value)

        elif isinstance(value, str):
            return self.const_str(value)

        else:
            raise TypeError(f'Cannot convert {type(value)} to expression')

    def push(self, value: Union[LowLevelILExpr, int, float, str], *, hidden_for_formatter: bool = False) -> LowLevelILExpr:
        '''Push value onto stack: StackStore + SpAdd (see docs/LLIL_DESIGN.md)'''
        expr = self._to_expr(value)
        slot_index = self.sp_get()
        # 1. StackStore(sp+0, value)
        self.add_instruction(LowLevelILStackStore(expr, offset = 0, slot_index = slot_index))
        # 2. SpAdd(+1)
        self.emit_sp_add(1, hidden_for_formatter = hidden_for_formatter)
        # Track on vstack: always use StackLoad reference
        # SCCP will propagate constants where needed
        self.__vstack_push(LowLevelILStackLoad(offset = 0, slot_index = slot_index))

        return expr

    def pop(self, *, hidden_for_formatter: bool = False) -> LowLevelILExpr:
        '''Pop value from stack and emit SpAdd'''
        self.emit_sp_add(-1, hidden_for_formatter = hidden_for_formatter)
        return self.__vstack_pop()

    # === Stack and Frame Operations ===

    def stack_load(self, offset: int, slot_index: int) -> LowLevelILStackLoad:
        '''STACK[sp + offset] (no sp change) - returns expression'''
        return LowLevelILStackLoad(offset = offset, slot_index = slot_index)

    def stack_store(self, value: Union[LowLevelILExpr, int, str], offset: int):
        '''STACK[sp + offset] = value (no sp change)'''
        self._store_slot(self._to_expr(value), self._slot_index(offset), offset)

    def frame_load(self, offset: int) -> 'LowLevelILFrameLoad':
        '''STACK[frame + offset] - Frame-relative load (for function parameters)'''
        return LowLevelILFrameLoad(offset)

    def frame_store(self, value: Union[LowLevelILExpr, int, str], offset: int):
        '''STACK[frame + offset] = value - Frame-relative store (for function parameters)'''
        expr = self._to_expr(value)
        self.add_instruction(LowLevelILFrameStore(expr, offset))

    def load_frame(self, offset: int):
        '''Load from frame + offset and push to stack'''
        frame_val = self.frame_load(offset)
        self.push(frame_val)

    def frame_addr(self, offset: int) -> 'LowLevelILFrameAddr':
        '''&STACK[frame + offset] - Frame-relative address (for function parameters)'''
        return LowLevelILFrameAddr(offset)

    # === Slot Storage (one rule for every access by slot) ===

    def _slot_index(self, offset: int) -> int:
        '''Absolute slot of the byte offset from sp'''
        return self.sp_get() + offset // WORD_SIZE

    def _is_param_slot(self, slot_index: int) -> bool:
        '''The caller pushed the arguments into the slots starting at the frame base'''
        return self.frame_base_sp <= slot_index < self.frame_base_sp + self.function.num_params

    def _holds_parameter(self, slot_index: int) -> bool:
        '''Whether slot_index still holds the caller's parameter, so accesses to it are frame-relative (argN).
        A push starts a new lifetime - in a parameter slot too - and the vstack tracks every pushed slot until
        it is popped, never a parameter: a live parameter is a parameter slot below sp that no entry tracks.'''
        return (
            self._is_param_slot(slot_index)
            and slot_index < self.sp_get()
            and self.vstack_entry_at_slot(slot_index) is None
        )

    def _frame_offset(self, slot_index: int) -> int:
        '''Byte offset of slot_index from the frame base'''
        return (slot_index - self.frame_base_sp) * WORD_SIZE

    def _require_live_slot(self, slot_index: int, access: str):
        '''A slot at or above sp holds no live value, so reading it or taking its address is not modelled'''
        if slot_index >= self.sp_get():
            raise NotImplementedError(
                f'{access} of slot {slot_index} at or above sp={self.sp_get()} is not supported - '
                f'the slot holds no live value'
            )

    def _load_slot(self, slot_index: int, offset: int) -> LowLevelILExpr:
        '''Read of a live slot (offset: its byte offset from sp)'''
        self._require_live_slot(slot_index, 'Read')
        if self._holds_parameter(slot_index):
            return self.frame_load(self._frame_offset(slot_index))

        return self.stack_load(offset, slot_index)

    def _slot_address(self, slot_index: int) -> LowLevelILExpr:
        '''Address of a live slot'''
        self._require_live_slot(slot_index, 'Address')
        if self._holds_parameter(slot_index):
            return self.frame_addr(self._frame_offset(slot_index))

        return LowLevelILStackAddr(slot_index)

    def _store_slot(self, value: LowLevelILExpr, slot_index: int, offset: int):
        '''In-place store (offset: the slot's byte offset from sp); a slot at or above sp is a dead stack slot'''
        if self._holds_parameter(slot_index):
            self.frame_store(value, self._frame_offset(slot_index))

        else:
            self.add_instruction(LowLevelILStackStore(value, offset = offset, slot_index = slot_index))

    def load_stack(self, offset: int):
        '''Load from sp + offset and push to stack'''
        self.push(self._load_slot(self._slot_index(offset), offset))

    def push_stack_addr(self, offset: int):
        '''Push the address of stack location (sp + offset)'''
        self.push(self._slot_address(self._slot_index(offset)))

    # === Register Operations ===

    def reg_store(self, reg_index: int, value: Union[LowLevelILExpr, int]):
        '''R[index] = value (store expression to register)'''
        expr = self._to_expr(value)
        self.add_instruction(LowLevelILRegStore(reg_index, expr))

    def reg_load(self, reg_index: int) -> LowLevelILRegLoad:
        '''R[index]'''
        return LowLevelILRegLoad(reg_index)

    # === Constants ===

    def const_int(self, value: int, is_hex: bool = False) -> LowLevelILConst:
        '''Integer constant'''
        return LowLevelILConst(value, is_hex)

    def const_float(self, value: float) -> LowLevelILConst:
        '''Float constant'''
        return LowLevelILConst(value, False)

    def const_str(self, value: str) -> LowLevelILConst:
        '''String constant'''
        return LowLevelILConst(value, False)

    def const_raw(self, value: int) -> LowLevelILConst:
        '''Raw constant (type-less, displayed as hex)'''
        return LowLevelILConst(value, is_hex = False, is_raw = True)

    # === Binary Operations ===

    def _binary_op(self, op_class, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = False) -> LowLevelILExpr:
        '''Generic binary operation handler'''
        # Get operands - both must be None or both must be provided
        if lhs is None and rhs is None:
            # Implicit mode: pop both from vstack (emit SpAdd for each)
            rhs = self.pop(hidden_for_formatter = hidden_for_formatter)  # First pop gets right operand (top of stack)
            lhs = self.pop(hidden_for_formatter = hidden_for_formatter)  # Second pop gets left operand (below it)
        elif lhs is not None and rhs is not None:
            # Explicit mode: both provided
            lhs = self._to_expr(lhs)
            rhs = self._to_expr(rhs)
        else:
            raise ValueError('Binary operation requires both operands or neither (lhs and rhs must both be None or both be provided)')

        # Create operation with operands
        op = op_class(lhs, rhs)

        # Binary operations are expressions, not statements
        # Only add as instruction if we're pushing (making it a statement via StackPush)
        if push:
            # Use push() to properly set slot_index and maintain sp
            self.push(op, hidden_for_formatter = hidden_for_formatter)
        else:
            # If not pushing, add the operation itself (e.g., for comparisons in branches)
            self.add_instruction(op)

        return op

    def add(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''ADD operation - computes lhs + rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILAdd, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def sub(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''SUB operation - computes lhs - rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILSub, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def mul(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''MUL operation - computes lhs * rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILMul, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def div(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''DIV operation - computes lhs / rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILDiv, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def mod(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''MOD operation - computes lhs % rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILMod, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    # === Comparison Operations ===

    def eq(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''EQ operation - computes lhs == rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILEq, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def ne(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''NE operation - computes lhs != rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILNe, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def lt(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''LT operation - computes lhs < rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILLt, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def le(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''LE operation - computes lhs <= rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILLe, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def gt(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''GT operation - computes lhs > rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILGt, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def ge(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''GE operation - computes lhs >= rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILGe, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    # === Bitwise Operations ===

    def bitwise_and(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''Bitwise AND operation - computes lhs & rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILAnd, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def bitwise_or(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''Bitwise OR operation - computes lhs | rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILOr, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    # === Logical Operations ===

    def logical_and(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''Logical AND operation - computes lhs && rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILLogicalAnd, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    def logical_or(self, lhs = None, rhs = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''Logical OR operation - computes lhs || rhs (pops rhs first, then lhs)'''
        return self._binary_op(LowLevelILLogicalOr, lhs, rhs, push = push, hidden_for_formatter = hidden_for_formatter)

    # === Unary Operations ===

    def neg(self, operand = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''NEG operation - arithmetic negation -x (pops operand if not provided)'''
        if operand is None:
            operand = self.pop(hidden_for_formatter = hidden_for_formatter)
        else:
            operand = self._to_expr(operand)
        op = LowLevelILNeg(operand)
        if push:
            self.push(op, hidden_for_formatter = hidden_for_formatter)
        else:
            self.add_instruction(op)
        return op

    def bitwise_not(self, operand = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''NOT operation - bitwise NOT ~x (pops operand if not provided)'''
        if operand is None:
            operand = self.pop(hidden_for_formatter = hidden_for_formatter)
        else:
            operand = self._to_expr(operand)
        op = LowLevelILBitwiseNot(operand)
        if push:
            self.push(op, hidden_for_formatter = hidden_for_formatter)
        else:
            self.add_instruction(op)
        return op

    def test_zero(self, operand = None, *, push: bool = True, hidden_for_formatter: bool = True):
        '''TEST_ZERO operation - test if x == 0 (pops operand if not provided)'''
        if operand is None:
            operand = self.pop(hidden_for_formatter = hidden_for_formatter)
        else:
            operand = self._to_expr(operand)
        op = LowLevelILTestZero(operand)
        if push:
            self.push(op, hidden_for_formatter = hidden_for_formatter)
        else:
            self.add_instruction(op)
        return op

    # === Control Flow ===

    def _resolve_block(self, target: Union[str, LowLevelILBasicBlock]) -> LowLevelILBasicBlock:
        '''A jump target given as a block or a label name, checked to be one of this function's blocks'''
        if not isinstance(target, str):
            self._require_registered_block(target)
            return target

        block = self.get_block_by_label(target)
        if block is None:
            raise ValueError(f'Undefined label: {target}')

        return block

    def jmp(self, target: Union[str, LowLevelILBasicBlock]):
        '''Unconditional jump - target can be label or block'''
        target = self._resolve_block(target)
        jmp_inst = LowLevelILJmp(target)
        self.add_instruction(jmp_inst)
        self._record_edge_state(jmp_inst, target)

    def branch_if(self, condition: LowLevelILInstruction,
                  true_target: Union[str, LowLevelILBasicBlock],
                  false_target: Union[str, LowLevelILBasicBlock]):
        '''Conditional branch - targets can be labels or blocks'''
        true_target = self._resolve_block(true_target)
        false_target = self._resolve_block(false_target)
        if_inst = LowLevelILIf(condition, true_target, false_target)
        self.add_instruction(if_inst)
        self._record_edge_state(if_inst, true_target)
        self._record_edge_state(if_inst, false_target)

    def call(self, target: str,
             return_target: LowLevelILBasicBlock,
             args: List[LowLevelILExpr] = None) -> LowLevelILCall:
        '''Function call (terminal instruction). Records no edge: the return edge's stack state is known only
        after the callee's cleanup, so the caller records it.'''
        self._require_registered_block(return_target)
        call_inst = LowLevelILCall(target, return_target, args)
        self.add_instruction(call_inst)
        return call_inst

    def ret(self):
        '''Return'''
        self.add_instruction(LowLevelILRet())

    # === Special ===

    def debug_line(self, line_no: int):
        '''Debug line number'''
        self.add_instruction(LowLevelILDebug('line', line_no))


class LLILFormatter:
    '''Formatting layer for beautiful output'''

    @classmethod
    def indent_lines(cls, lines: List[str], indent: str) -> List[str]:
        '''Add indentation to multiple lines'''
        return [indent + line for line in lines]

    @classmethod
    def format_instruction(cls, inst: LowLevelILInstruction) -> str:
        '''Format a single instruction - can be customized per instruction type'''
        # For now, use the instruction's __str__ method
        # This can be extended with custom formatting logic for specific instruction types
        return str(inst)

    # Map operation to expression template
    __expr_templates = {
        LowLevelILOperation.LLIL_ADD            : '{lhs} + {rhs}',
        LowLevelILOperation.LLIL_SUB            : '{lhs} - {rhs}',
        LowLevelILOperation.LLIL_MUL            : '{lhs} * {rhs}',
        LowLevelILOperation.LLIL_DIV            : '{lhs} / {rhs}',
        LowLevelILOperation.LLIL_MOD            : '{lhs} % {rhs}',
        LowLevelILOperation.LLIL_EQ             : '({lhs} == {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_NE             : '({lhs} != {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_LT             : '({lhs} < {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_LE             : '({lhs} <= {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_GT             : '({lhs} > {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_GE             : '({lhs} >= {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_AND            : '{lhs} & {rhs}',
        LowLevelILOperation.LLIL_OR             : '{lhs} | {rhs}',
        LowLevelILOperation.LLIL_LOGICAL_AND    : '({lhs} && {rhs}) ? 1 : 0',
        LowLevelILOperation.LLIL_LOGICAL_OR     : '({lhs} || {rhs}) ? 1 : 0',

        LowLevelILOperation.LLIL_NEG            : '-{operand}',
        LowLevelILOperation.LLIL_BITWISE_NOT    : '~{operand}',
        LowLevelILOperation.LLIL_TEST_ZERO      : '({operand} == 0) ? 1 : 0',
    }

    @classmethod
    def _format_binary_op_expanded(cls, binary_op: LowLevelILBinaryOp) -> List[str]:
        '''Format binary operation with expanded pseudo-code'''

        template = cls.__expr_templates[binary_op.operation]
        expr = template.format(lhs = 'lhs', rhs = 'rhs')

        lines = []
        lines.append(f'rhs = STACK[--sp]  ; {binary_op.rhs}')
        lines.append(f'lhs = STACK[--sp]  ; {binary_op.lhs}')
        lines.append(f'STACK[sp++] = {expr}')

        return lines

    @classmethod
    def _format_unary_op_expanded(cls, unary_op: 'LowLevelILUnaryOp') -> List[str]:
        '''Format unary operation with expanded pseudo-code'''

        template = cls.__expr_templates[unary_op.operation]
        expr = template.format(operand = 'operand')

        lines = []
        lines.append(f'operand = STACK[--sp]  ; {unary_op.operand}')
        lines.append(f'STACK[sp++] = {expr}')

        return lines

    @classmethod
    def _format_simplified(cls, inst: LowLevelILInstruction) -> List[str]:
        '''Format instruction with simplified display (not expanded, just cleaner)'''
        # RegStore: show as pop from stack
        if isinstance(inst, LowLevelILRegStore):
            return [f'REG[{inst.reg_index}] = STACK[--sp]  ; {inst.value}']

        # If instruction: simplify condition display
        if isinstance(inst, LowLevelILIf):
            true_name = inst.true_target.block_name
            false_name = inst.false_target.block_name

            cond = inst.condition

            rhs = cond.rhs
            lhs = cond.lhs
            opr = cond.operation_name

            if not isinstance(lhs, Constant):
                lhs = f'STACK[--sp]'

            return [f'if ({lhs} {opr} {rhs}) goto {true_name} else {false_name}']

        line = str(inst)

        if isinstance(inst, LowLevelILStackStore) and inst.offset != 0:
            line = f'STACK[{inst.slot_index}] = STACK[--sp] ; {inst.value}'

        elif isinstance(inst, (LowLevelILStackStore, LowLevelILStackLoad)):
            line = f'{line} ; [{inst.slot_index}]'

        elif isinstance(inst, LowLevelILFrameStore):
            word_offset = inst.offset // WORD_SIZE
            location = f'fp + {word_offset}' if word_offset >= 0 else f'fp - {-word_offset}'
            line = f'STACK[{location}] = STACK[--sp] ; {inst.value}'

        return [line]

    @classmethod
    def format_instruction_expanded(cls, inst: LowLevelILInstruction) -> List[str]:
        '''Format instruction with expanded stack operations (multi-line)'''

        if isinstance(inst, LowLevelILStackStore) and inst.offset == 0:
            # StackStore containing a binary operation: expand the binary op
            if isinstance(inst.value, LowLevelILBinaryOp):
                return cls._format_binary_op_expanded(inst.value)

            # StackStore containing a unary operation: expand the unary op
            if isinstance(inst.value, LowLevelILUnaryOp):
                return cls._format_unary_op_expanded(inst.value)

        # Binary operations: pop 2, compute, push 1
        elif isinstance(inst, LowLevelILBinaryOp):
            return cls._format_binary_op_expanded(inst)

        # Unary operations: pop 1, compute, push 1
        elif isinstance(inst, LowLevelILUnaryOp):
            return cls._format_unary_op_expanded(inst)

        return None

    @classmethod
    def format_instruction_sequence(cls, instructions: List[LowLevelILInstruction], indent: str = '  ') -> list[str]:
        '''Format sequence of instructions - returns list of lines'''
        result = []

        for inst in instructions:
            # Skip instructions marked as hidden for formatter
            if inst.options.hidden_for_formatter:
                continue

            if result and isinstance(inst, LowLevelILDebug):
                result.append('')

            # Use expanded format for multi-line instructions
            expanded = cls.format_instruction_expanded(inst)
            if expanded:
                # Multi-line instruction
                result.extend(cls.indent_lines(expanded, indent))

            else:
                lines = cls._format_simplified(inst)
                result.extend(cls.indent_lines(lines, indent))

        return result

    @classmethod
    def format_llil_function(cls, func: LowLevelILFunction) -> list[str]:
        assert isinstance(func, LowLevelILFunction)

        '''Format entire LLIL function with beautiful output - returns list of lines'''
        result = [
            f'; ---------- {func.name} ----------',
        ]

        for block in func.basic_blocks:
            # Block header: {block_N}(addr), label, [sp = N, fp = M]

            block_info = [
                f'block_{block.index}(0x{block.start:04X})',
                block.label,
            ]

            # Show sp and fp (fp only on first block)
            if block.index == 0 and func.frame_base_sp is not None:
                block_info.append(f'[sp = {block.sp_in}, fp = {func.frame_base_sp}]')
            else:
                block_info.append(f'[sp = {block.sp_in}]')

            result.append(', '.join(block_info))

            # Format instructions - now returns list
            indent = '  '
            result.extend(cls.format_instruction_sequence(block.instructions, indent))
            result.append('')

        return result

    @classmethod
    def to_dot(cls, func: LowLevelILFunction) -> str:
        '''Generate Graphviz DOT format for CFG visualization'''
        lines = []
        lines.append(f'digraph "{func.name}" {{')
        lines.append('    rankdir=TB;')
        lines.append('    node [shape=box, fontname="Courier New", fontsize=10];')
        lines.append('    edge [fontname="Courier New", fontsize=9];')
        lines.append('')

        # Add nodes (basic blocks)
        for block in func.basic_blocks:
            label_parts = []

            # Block header: block_N(0xADDR), label, [sp = N, fp = M]
            # Use same format as format_llil_function
            header_parts = [
                f'block_{block.index}(0x{block.start:X})',
                block.label,
            ]

            # Show sp and fp (fp only on first block)
            if block.index == 0 and func.frame_base_sp is not None:
                header_parts.append(f'[sp = {block.sp_in}, fp = {func.frame_base_sp}]')
            else:
                header_parts.append(f'[sp = {block.sp_in}]')

            header = ', '.join(header_parts) + '\\l'
            label_parts.append(header)
            label_parts.append('-' * 40 + '\\l')

            # Format instructions using expand format (same as format_llil_function)
            formatted_lines = cls.format_instruction_sequence(block.instructions, '')
            for line in formatted_lines:
                # Escape for DOT format
                escaped = line.replace('\\', '\\\\').replace('"', '\\"')
                label_parts.append(escaped + '\\l')

            label = ''.join(label_parts)

            # Node styling
            if block.index == 0:
                # Entry block
                lines.append(f'    {block.block_name} [label="{label}", style=filled, fillcolor=lightgreen];')
            elif block.has_terminal and isinstance(block.instructions[-1], LowLevelILRet):
                # Exit block
                lines.append(f'    {block.block_name} [label="{label}", style=filled, fillcolor=lightblue];')
            else:
                lines.append(f'    {block.block_name} [label="{label}"];')

        lines.append('')

        # Add edges
        for block in func.basic_blocks:
            if not block.outgoing_edges:
                continue

            last_inst = block.instructions[-1] if block.instructions else None

            for target in block.outgoing_edges:
                # Determine edge label and style
                edge_label = ''
                edge_style = ''

                if isinstance(last_inst, LowLevelILIf):
                    # Conditional branch
                    if target == last_inst.true_target:
                        edge_label = 'true'
                        edge_style = ', color=green'
                    elif last_inst.false_target and target == last_inst.false_target:
                        edge_label = 'false'
                        edge_style = ', color=red'
                    else:
                        edge_label = 'fall-through'
                        edge_style = ', style=dashed'
                elif isinstance(last_inst, LowLevelILGoto):
                    edge_label = 'goto'
                    edge_style = ', color=blue'
                else:
                    # Fall-through
                    edge_label = 'fall-through'
                    edge_style = ', style=dashed'

                if edge_label:
                    lines.append(f'    {block.block_name} -> {target.block_name} [label="{edge_label}"{edge_style}];')
                else:
                    lines.append(f'    {block.block_name} -> {target.block_name}{edge_style};')

        lines.append('}')
        return '\n'.join(lines)
