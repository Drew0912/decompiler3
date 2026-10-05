#!/usr/bin/env python3
'''Unit tests for slot lifetimes in the LLIL builder. A parameter slot is
frame storage (argN) only while it still holds the caller's parameter; once the function pops the parameter, a push
into the slot starts a stack lifetime, and every access to the slot uses that storage.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.core import IRParameter
from ir.llil.llil import (
    LowLevelILBasicBlock, LowLevelILFrameLoad, LowLevelILFrameStore, LowLevelILFunction, LowLevelILStackAddr,
    LowLevelILStackLoad, LowLevelILStackStore, WORD_SIZE,
)
from ir.llil.llil_builder import LowLevelILBuilder
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from ir.mlil.mlil import MLILCallScript, MLILConst, MLILStoreGlobal, MLILVar


FUNC_START = 0x1000
SECOND_BLOCK_START = FUNC_START + 0x10
THIRD_BLOCK_START = FUNC_START + 0x20
FOURTH_BLOCK_START = FUNC_START + 0x30
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


def make_builder(num_params: int) -> FalcomVMBuilder:
    builder = FalcomVMBuilder()
    builder.create_function('slot_lifetime_test', FUNC_START, num_params = num_params)
    builder.set_current_block(builder.create_basic_block(FUNC_START, 'slot_lifetime_test'))
    return builder


def make_existing_function_builder() -> LowLevelILBuilder:
    '''A builder around an already constructed 1-parameter function, not create_function, with its entry block
    begun - which restores the entry state the constructor recorded'''
    function = LowLevelILFunction('existing_function_test', FUNC_START, [IRParameter('arg1')])
    block = LowLevelILBasicBlock(FUNC_START)
    function.add_basic_block(block)
    builder = LowLevelILBuilder(function)
    builder.begin_block(block)
    return builder


def last_pushed_value(builder: LowLevelILBuilder):
    '''The value the last push stored (a push emits its store, then its SpAdd)'''
    return builder.current_block.instructions[-2].value


def global_stores(builder: FalcomVMBuilder) -> dict:
    '''GLOBAL index -> stored value, after the production MLIL pipeline'''
    mlil = convert_falcom_llil_to_mlil(builder.finalize(), optimize = True)
    return {
        inst.index: inst.value
        for block in mlil.basic_blocks for inst in block.instructions
        if isinstance(inst, MLILStoreGlobal)
    }


class TestRepushedParameterSlot(unittest.TestCase):
    '''After the function pops a parameter and pushes into its slot, every access uses the push's stack storage.
    Before, these accesses picked the parameter by slot number and read or wrote the popped parameter.'''

    def assert_const(self, value, expected):
        self.assertIsInstance(value, MLILConst)
        self.assertEqual(value.value, expected)

    def test_pop_to_writes_the_pushed_slot(self):
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)            # the parameter is popped; sp 1->0
        builder.push_int(PUSHED_VALUE)          # slot 0 re-pushed; sp 0->1
        builder.push_int(STORED_VALUE)          # sp 1->2
        builder.pop_to(-WORD_SIZE)              # slot 0 = STORED_VALUE; sp 2->1

        store = builder.current_block.instructions[-1]
        self.assertIsInstance(store, LowLevelILStackStore)
        self.assertEqual(store.slot_index, 0)

        builder.set_global(GLOBAL_INDEX)
        builder.ret()
        self.assert_const(global_stores(builder)[GLOBAL_INDEX], STORED_VALUE)

    def test_load_stack_reads_the_pushed_slot(self):
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)
        builder.push_int(PUSHED_VALUE)
        builder.load_stack(-WORD_SIZE)          # slot 0

        loaded = last_pushed_value(builder)
        self.assertIsInstance(loaded, LowLevelILStackLoad)
        self.assertEqual(loaded.slot_index, 0)

        builder.set_global(GLOBAL_INDEX)
        builder.pop_bytes(WORD_SIZE)
        builder.ret()
        self.assert_const(global_stores(builder)[GLOBAL_INDEX], PUSHED_VALUE)

    def test_address_is_the_pushed_slot(self):
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)
        builder.push_int(PUSHED_VALUE)
        builder.push_stack_addr(-WORD_SIZE)     # slot 0

        address = last_pushed_value(builder)
        self.assertIsInstance(address, LowLevelILStackAddr)
        self.assertEqual(address.slot_index, 0)

    def test_lower_parameter_stays_live_while_a_higher_one_is_repushed(self):
        builder = make_builder(num_params = 2)
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
        stores = global_stores(builder)
        self.assert_const(stores[SECOND_GLOBAL_INDEX], PUSHED_VALUE)
        self.assertIsInstance(stores[GLOBAL_INDEX], MLILVar)
        self.assertEqual(stores[GLOBAL_INDEX].var.name, 'arg2')

    def test_dereference_through_a_repushed_slot_raises(self):
        '''The slot now holds a pushed pointer, which may point into this function's own frame.'''
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)
        builder.push_int(PUSHED_VALUE)          # slot 0 re-pushed

        with self.assertRaises(NotImplementedError):
            builder.load_stack_deref(-WORD_SIZE)

        builder.push_int(STORED_VALUE)
        with self.assertRaises(NotImplementedError):
            builder.pop_to_deref(-WORD_SIZE)    # after its pop, sp 1 - offset targets slot 0


class TestAccessAtOrAboveSp(unittest.TestCase):
    '''A slot at or above sp holds no live value: reads, addresses and dereferences raise instead of reviving a
    popped parameter as argN, and a store there is a dead stack store.'''

    def test_read_raises(self):
        for num_params in (0, 1):
            with self.subTest(num_params = num_params):
                builder = make_builder(num_params)
                builder.pop_bytes(num_params * WORD_SIZE)   # sp 0: any parameter is popped

                with self.assertRaises(NotImplementedError):
                    builder.load_stack(0)

    def test_address_raises(self):
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)

        with self.assertRaises(NotImplementedError):
            builder.push_stack_addr(0)

    def test_dereference_raises(self):
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)

        with self.assertRaises(NotImplementedError):
            builder.load_stack_deref(0)

    def test_pop_to_zero_is_a_dead_stack_store(self):
        builder = make_builder(num_params = 1)
        builder.pop_bytes(WORD_SIZE)            # the parameter is popped; sp 1->0
        builder.push_int(PUSHED_VALUE)          # sp 0->1
        builder.pop_to(0)                       # pops slot 0, then writes the slot it just popped

        store = builder.current_block.instructions[-1]
        self.assertIsInstance(store, LowLevelILStackStore)
        self.assertEqual(store.slot_index, 0)


class TestAccessBelowTheStack(unittest.TestCase):
    '''A slot below the frame base is the caller's: reads, addresses, dereferences and stores raise'''

    BELOW_ONE_PARAMETER = -3 * WORD_SIZE    # with 1 parameter and 1 push (sp 2): slot -1

    def builder(self) -> FalcomVMBuilder:
        builder = make_builder(num_params = 1)
        builder.push_int(PUSHED_VALUE)
        return builder

    def test_every_access_raises(self):
        for access, emit in (
            ('Read', lambda builder: builder.load_stack(self.BELOW_ONE_PARAMETER)),
            ('Address', lambda builder: builder.push_stack_addr(self.BELOW_ONE_PARAMETER)),
            ('Store', lambda builder: builder.pop_to(self.BELOW_ONE_PARAMETER + WORD_SIZE)),  # after its pop, sp 1
        ):
            with self.subTest(access = access):
                with self.assertRaisesRegex(NotImplementedError, rf'^{access} of slot -1 below the stack'):
                    emit(self.builder())

    def test_dereference_raises(self):
        with self.assertRaises(NotImplementedError):
            self.builder().load_stack_deref(self.BELOW_ONE_PARAMETER)

    def test_lowest_slot_is_still_in_the_frame(self):
        builder = self.builder()
        builder.load_stack(self.BELOW_ONE_PARAMETER + WORD_SIZE)    # slot 0, the parameter

        self.assertIsInstance(last_pushed_value(builder), LowLevelILFrameLoad)


class TestLiveParameterSlot(unittest.TestCase):
    '''Guards: while the function still holds a parameter, its slot stays frame-relative, and a push that starts a
    new lifetime keeps producing today's stack slots.'''

    def test_live_parameter_read_is_frame_relative(self):
        builder = make_builder(num_params = 1)
        builder.load_stack(-WORD_SIZE)              # slot 0

        self.assertIsInstance(last_pushed_value(builder), LowLevelILFrameLoad)

    def test_tail_call_argument_stays_a_stack_value(self):
        builder = make_builder(num_params = 1)
        builder.push(builder.const_float(TAIL_ARG_VALUE))
        builder.set_reg(TAIL_ARG_REG)
        builder.pop_bytes(WORD_SIZE)                # the whole frame, the parameter included
        builder.get_reg(TAIL_ARG_REG)               # the tail call's argument lands in slot 0
        self.assertIsInstance(builder.current_block.instructions[-2], LowLevelILStackStore)
        builder.call_script_no_return(MODULE_NAME, TAIL_FUNC_NAME, 1)

        mlil = convert_falcom_llil_to_mlil(builder.finalize(), optimize = True)
        call = next(
            inst for block in mlil.basic_blocks for inst in block.instructions if isinstance(inst, MLILCallScript)
        )
        self.assertIsInstance(call.args[0], MLILConst)
        self.assertEqual(call.args[0].value, TAIL_ARG_VALUE)

    def test_both_arms_repushing_a_parameter_slot_are_accepted(self):
        builder = make_builder(num_params = 1)
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


class TestExistingFunctionBuilder(unittest.TestCase):
    '''LowLevelILBuilder(function) starts from the entry state create_function records, so the slot rule has a
    frame base; the caller-less legacy stack_store follows the same rule as every other access.'''

    def test_constructor_seeds_the_entry_state(self):
        builder = make_existing_function_builder()
        builder.load_stack(-WORD_SIZE)                  # slot 0: the caller's parameter

        self.assertIsInstance(last_pushed_value(builder), LowLevelILFrameLoad)

    def test_stack_store_follows_the_slot_rule(self):
        builder = make_existing_function_builder()

        builder.stack_store(STORED_VALUE, -WORD_SIZE)   # slot 0: the live parameter
        self.assertIsInstance(builder.current_block.instructions[-1], LowLevelILFrameStore)

        builder.stack_store(STORED_VALUE, 0)            # slot 1, at sp: a dead stack slot
        store = builder.current_block.instructions[-1]
        self.assertIsInstance(store, LowLevelILStackStore)
        self.assertEqual(store.slot_index, 1)


if __name__ == '__main__':
    unittest.main()
