#!/usr/bin/env python3
"""Unit tests for slot lifetimes in the LLIL builder. A parameter slot is
frame storage (argN) only while it still holds the caller's parameter; once the function pops the parameter, a push
into the slot starts a stack lifetime, and every access to the slot uses that storage."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILFrameLoad, LowLevelILStackAddr, LowLevelILStackLoad, LowLevelILStackStore, WORD_SIZE
from ir.llil.llil_builder import LowLevelILBuilder
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from tests.shared.llil_utils import FOURTH_BLOCK_START, SECOND_BLOCK_START, THIRD_BLOCK_START, make_builder


PUSHED_VALUE = 10
STORED_VALUE = 99
CONDITION_VALUE = 0
LEFT_VALUE = 1
RIGHT_VALUE = 2
TAIL_ARG_VALUE = 0.5
TAIL_ARG_REG = 1
GLOBAL_INDEX = 0
SECOND_GLOBAL_INDEX = 1
MODULE_NAME = ''
TAIL_FUNC_NAME = 'Tail'
REG_INDEX = 0
SYSCALL_SUBSYSTEM = 1
SYSCALL_FUNC = 2
IN_PLACE = "in place, which the decompiler can't follow - work on a LOAD_STACK copy instead$"


def last_pushed_value(builder: LowLevelILBuilder):
    """The value the last push stored (a push emits its store, then its SpAdd)"""
    return builder.current_block.instructions[-2].value


def production_statements(builder: FalcomVMBuilder) -> list[str]:
    """Every statement of the production MLIL, in order"""
    mlil = convert_falcom_llil_to_mlil_stack(builder.finalize())
    return [str(inst) for block in mlil.basic_blocks for inst in block.instructions]


class TestRepushedParameterSlot(unittest.TestCase):
    """After the function pops a parameter and pushes into its slot, every access uses the push's stack storage.
    Before, these accesses picked the parameter by slot number and read or wrote the popped parameter."""

    def test_pop_to_writes_the_pushed_slot(self):
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)            # the parameter is popped; sp 1->0
        builder.push_int(PUSHED_VALUE)          # slot 0 re-pushed; sp 0->1
        builder.push_int(STORED_VALUE)          # sp 1->2
        builder.pop_to(-WORD_SIZE)              # slot 0 = STORED_VALUE; sp 2->1

        store = builder.current_block.instructions[-1]
        self.assertIsInstance(store, LowLevelILStackStore)
        self.assertEqual(store.slot_index, 0)

        builder.set_global(GLOBAL_INDEX)
        builder.ret()
        self.assertEqual(production_statements(builder), [f'var_s0 = {PUSHED_VALUE}', f'var_s0 = {STORED_VALUE}',
                                                          f'GLOBAL[{GLOBAL_INDEX}] = var_s0', 'return REG[0]'])

    def test_load_stack_reads_the_pushed_slot(self):
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)
        builder.push_int(PUSHED_VALUE)
        builder.load_stack(-WORD_SIZE)          # slot 0

        loaded = last_pushed_value(builder)
        self.assertIsInstance(loaded, LowLevelILStackLoad)
        self.assertEqual(loaded.slot_index, 0)

        builder.set_global(GLOBAL_INDEX)
        builder.pop_bytes(WORD_SIZE)
        builder.ret()
        self.assertEqual(production_statements(builder),
                         [f'var_s0 = {PUSHED_VALUE}', f'GLOBAL[{GLOBAL_INDEX}] = var_s0', 'return REG[0]'])

    def test_address_is_the_pushed_slot(self):
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)
        builder.push_int(PUSHED_VALUE)
        builder.push_stack_addr(-WORD_SIZE)     # slot 0

        address = last_pushed_value(builder)
        self.assertIsInstance(address, LowLevelILStackAddr)
        self.assertEqual(address.slot_index, 0)

    def test_lower_parameter_stays_live_while_a_higher_one_is_repushed(self):
        builder = make_builder(num_params=2)
        builder.pop_bytes(WORD_SIZE)            # slot 1 (arg1) popped; sp 2->1
        builder.push_int(PUSHED_VALUE)          # slot 1 re-pushed; sp 1->2
        builder.load_stack(-2 * WORD_SIZE)      # slot 0: still the caller's arg2; sp 2->3
        self.assertIsInstance(last_pushed_value(builder), LowLevelILFrameLoad)
        builder.load_stack(-2 * WORD_SIZE)      # slot 1: the pushed value; sp 3->4
        self.assertIsInstance(last_pushed_value(builder), LowLevelILStackLoad)

        builder.set_global(SECOND_GLOBAL_INDEX)
        builder.set_global(GLOBAL_INDEX)
        builder.pop_bytes(2 * WORD_SIZE)
        builder.ret()
        self.assertEqual(production_statements(builder), [f'var_s1 = {PUSHED_VALUE}',
                                                          f'GLOBAL[{SECOND_GLOBAL_INDEX}] = var_s1',
                                                          f'GLOBAL[{GLOBAL_INDEX}] = arg2', 'return REG[0]'])

    def test_dereference_through_a_repushed_slot_raises(self):
        """The slot now holds a pushed pointer, which may point into this function's own frame."""
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)
        builder.push_int(PUSHED_VALUE)          # slot 0 re-pushed

        with self.assertRaises(NotImplementedError):
            builder.load_stack_deref(-WORD_SIZE)

        builder.push_int(STORED_VALUE)
        with self.assertRaises(NotImplementedError):
            builder.pop_to_deref(-WORD_SIZE)    # after its pop, sp 1 - offset targets slot 0


class TestAccessAtOrAboveSp(unittest.TestCase):
    """A slot at or above sp holds no live value: reads, addresses and dereferences raise instead of reviving a
    popped parameter as argN, and a store there is a dead stack store."""

    def test_read_raises(self):
        for num_params in (0, 1):
            with self.subTest(num_params=num_params):
                builder = make_builder(num_params)
                builder.pop_bytes(num_params * WORD_SIZE)   # sp 0: any parameter is popped

                with self.assertRaises(NotImplementedError):
                    builder.load_stack(0)

    def test_address_raises(self):
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)

        with self.assertRaises(NotImplementedError):
            builder.push_stack_addr(0)

    def test_dereference_raises(self):
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)

        with self.assertRaises(NotImplementedError):
            builder.load_stack_deref(0)

    def test_pop_to_zero_is_a_dead_stack_store(self):
        builder = make_builder(num_params=1)
        builder.pop_bytes(WORD_SIZE)            # the parameter is popped; sp 1->0
        builder.push_int(PUSHED_VALUE)          # sp 0->1
        builder.pop_to(0)                       # pops slot 0, then writes the slot it just popped

        store = builder.current_block.instructions[-1]
        self.assertIsInstance(store, LowLevelILStackStore)
        self.assertEqual(store.slot_index, 0)


class TestAccessBelowTheStack(unittest.TestCase):
    """A slot below the frame base is the caller's: reads and addresses raise (a store there fails in the parser
    first)"""

    BELOW_ONE_PARAMETER = -3 * WORD_SIZE    # with 1 parameter and 1 push (sp 2): slot -1

    def builder(self) -> FalcomVMBuilder:
        builder = make_builder(num_params=1)
        builder.push_int(PUSHED_VALUE)
        return builder

    def test_reads_and_addresses_raise(self):
        for access, emit in (
            ('Read', lambda builder: builder.load_stack(self.BELOW_ONE_PARAMETER)),
            ('Address', lambda builder: builder.push_stack_addr(self.BELOW_ONE_PARAMETER)),
        ):
            with self.subTest(access=access):
                with self.assertRaisesRegex(NotImplementedError, rf'^{access} of slot -1 below the stack'):
                    emit(self.builder())

    def test_dereference_raises_as_not_a_parameter(self):
        # Guard: a dereference needs a parameter slot, a rule older than the below-stack one
        with self.assertRaisesRegex(NotImplementedError, '^dereferences slot -1, which holds no caller parameter: '):
            self.builder().load_stack_deref(self.BELOW_ONE_PARAMETER)


class TestParameterUsedInPlace(unittest.TestCase):
    """The vstack never tracks a parameter, so an opcode consuming or reading one in place can't be lifted: it fails
    naming the parameter's slot - parameters counted from the top, where arg1 is - instead of the vstack"""

    def assert_in_place(self, emit, uses: str, num_params: int = 1):
        builder = make_builder(num_params)
        with self.assertRaisesRegex(RuntimeError, rf'^uses {uses} {IN_PLACE}'):
            emit(builder)

    def test_consumer_names_the_parameter_slot(self):
        for opcode, emit in (
            ('SET_REG', lambda builder: builder.set_reg(REG_INDEX)),
            ('NEG', lambda builder: builder.neg()),
            ('SET_GLOBAL', lambda builder: builder.set_global(GLOBAL_INDEX)),
            ('POP_TO', lambda builder: builder.pop_to(0)),
        ):
            with self.subTest(opcode):
                self.assert_in_place(emit, r'the slot of parameter 1 \(arg1\)')

    def test_reader_names_the_parameter_slots(self):
        for opcode, emit in (
            ('SYSCALL', lambda builder: builder.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2)),
            ('POPN', lambda builder: builder.popn(2)),
        ):
            with self.subTest(opcode):
                self.assert_in_place(emit, r'the slots of parameters 1-2 \(arg1, arg2\)', num_params=2)

    def test_binary_op_names_both_parameters(self):
        self.assert_in_place(lambda builder: builder.add(), r'the slots of parameters 1-2 \(arg1, arg2\)',
                             num_params=2)

    def test_repushed_parameter_slot_is_not_named(self):
        """arg1 popped and its slot pushed again: the push is a value the function pushed, only arg2 is used in place"""
        def emit(builder):
            builder.pop_bytes(WORD_SIZE)
            builder.push_int(PUSHED_VALUE)
            builder.add()

        self.assert_in_place(emit, r'the slot of parameter 2 \(arg2\)', num_params=2)

    def test_overwritten_parameter_slot_is_still_its_slot(self):
        def emit(builder):
            builder.push_int(STORED_VALUE)
            builder.pop_to(-WORD_SIZE)              # into the parameter's slot
            builder.set_reg(REG_INDEX)

        self.assert_in_place(emit, r'the slot of parameter 1 \(arg1\)')

    def test_tail_call_forwarding_a_parameter(self):
        """A copy on the stack would sit above the parameter, which the tail call can't leave: it goes through a
        register"""
        builder = make_builder(num_params=1)
        with self.assertRaisesRegex(RuntimeError, r"^forwards the slot of parameter 1 \(arg1\) to a tail call, which "
                                                  r"the decompiler can't follow - pass LOAD_STACK copies through "
                                                  r'registers \(SET_REG, pop the parameters, GET_REG\)$'):
            builder.call_script_no_return(MODULE_NAME, TAIL_FUNC_NAME, 1)

    def test_shortfall_below_the_parameters_keeps_the_vstack_error(self):
        """Not a parameter: a broken builder invariant, which the parser keeps a pop from reaching"""
        with self.assertRaisesRegex(RuntimeError, '^Vstack underflow'):
            make_builder().set_reg(REG_INDEX)


class TestLiveParameterSlot(unittest.TestCase):
    """Guards: while the function still holds a parameter, its slot stays frame-relative, and a push that starts a
    new lifetime keeps producing today's stack slots."""

    def test_tail_call_argument_stays_a_stack_value(self):
        builder = make_builder(num_params=1)
        builder.push(builder.const_float(TAIL_ARG_VALUE))
        builder.set_reg(TAIL_ARG_REG)
        builder.pop_bytes(WORD_SIZE)                # the whole frame, the parameter included
        builder.get_reg(TAIL_ARG_REG)               # the tail call's argument lands in slot 0
        self.assertIsInstance(builder.current_block.instructions[-2], LowLevelILStackStore)
        builder.call_script_no_return(MODULE_NAME, TAIL_FUNC_NAME, 1)

        self.assertEqual(production_statements(builder), [f'REG[{TAIL_ARG_REG}] = {TAIL_ARG_VALUE}',
                                                          f't1 = .{TAIL_FUNC_NAME}(REG[{TAIL_ARG_REG}])',
                                                          'return t1'])

    def test_both_arms_repushing_a_parameter_slot_are_accepted(self):
        builder = make_builder(num_params=1)
        left = builder.create_basic_block(SECOND_BLOCK_START, 'left')
        right = builder.create_basic_block(THIRD_BLOCK_START, 'right')
        join = builder.create_basic_block(FOURTH_BLOCK_START, 'join')
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(left, right)

        builder.begin_block(left)
        builder.pop_n(1)
        builder.push_int(LEFT_VALUE)
        builder.jmp(join)
        builder.begin_block(right)
        builder.pop_n(1)
        builder.push_int(RIGHT_VALUE)
        builder.jmp(join)                           # must not raise

        builder.begin_block(join)
        builder.set_global(GLOBAL_INDEX)
        stored = builder.current_block.instructions[-1].value
        self.assertIsInstance(stored, LowLevelILStackLoad)
        self.assertEqual(stored.slot_index, 0)


if __name__ == '__main__':
    unittest.main()
