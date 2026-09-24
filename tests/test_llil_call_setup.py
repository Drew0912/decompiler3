#!/usr/bin/env python3
'''Unit tests for LLIL call-setup tracking: each pending call setup (PUSH_CURRENT_FUNC_ID +
PUSH_RET_ADDR, or PUSH_CALLER_FRAME) is a record carried in stack snapshots, consumed only by the
matching kind of call, and only while every slot it pushed is still in place.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILCall, WORD_SIZE
from ir.llil.llil_builder import StackSnapshot
from falcom.ed9.ir.llil.llil_builder import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS, FalcomVMBuilder
from falcom.ed9.ir.llil.llil_ext import LowLevelILCallScript


FUNC_START = 0x2000
BLOCK_STRIDE = 0x10
ARG_VALUE = 7
FILLER_VALUE = 123
REPLACEMENT_VALUE = 999
STORED_VALUE = 5
CONDITION_VALUE = 1
LOCAL_PARAM_COUNT = 2
MODULE_NAME = 'module'


def make_builder(num_params: int = 0) -> FalcomVMBuilder:
    builder = FalcomVMBuilder()
    builder.create_function('call_setup_test', FUNC_START, num_params = num_params)
    builder.set_current_block(builder.create_basic_block(FUNC_START, 'entry'))
    return builder


def add_block(builder: FalcomVMBuilder, name: str):
    start = FUNC_START + BLOCK_STRIDE * len(builder.function.basic_blocks)
    return builder.create_basic_block(start, name)


def last_instruction(builder: FalcomVMBuilder):
    return builder.current_block.instructions[-1]


class TestLocalCallSetup(unittest.TestCase):
    def test_call_consumes_its_setup(self):
        builder = make_builder()
        ret_block = add_block(builder, 'ret')
        builder.push_func_id()
        builder.push_ret_addr(ret_block)
        builder.push_int(ARG_VALUE)
        arg_load = builder.vstack_peek()

        builder.call('f')

        self.assertIsInstance(last_instruction(builder), LowLevelILCall)
        self.assertEqual(last_instruction(builder).args, [arg_load])
        builder.begin_block(ret_block)
        builder.ret()   # no setup left pending

    def test_call_before_push_ret_addr_raises(self):
        builder = make_builder()
        builder.push_func_id()

        with self.assertRaises(RuntimeError):
            builder.call('f')

    def test_push_ret_addr_without_push_func_id_raises(self):
        builder = make_builder()

        with self.assertRaises(RuntimeError):
            builder.push_ret_addr(add_block(builder, 'ret'))

    def test_push_ret_addr_after_balanced_push_pop_is_accepted(self):
        builder = make_builder()
        ret_block = add_block(builder, 'ret')
        builder.push_func_id()
        builder.push_int(FILLER_VALUE)
        builder.pop_n(1)
        builder.push_ret_addr(ret_block)

        builder.call('f')

    def test_push_ret_addr_over_replaced_func_id_raises(self):
        builder = make_builder()
        builder.push_func_id()
        builder.pop_n(1)
        builder.push_int(REPLACEMENT_VALUE)

        with self.assertRaises(RuntimeError):
            builder.push_ret_addr(add_block(builder, 'ret'))

    def test_push_ret_addr_above_an_extra_value_raises(self):
        builder = make_builder()
        builder.push_func_id()
        builder.push_int(FILLER_VALUE)

        with self.assertRaises(RuntimeError):
            builder.push_ret_addr(add_block(builder, 'ret'))


class TestCallSetupCorruption(unittest.TestCase):
    '''Anything that changes a setup slot between the setup and its call is caught at the call.'''

    def make_local_setup(self, builder: FalcomVMBuilder):
        builder.push_func_id()
        builder.push_ret_addr(add_block(builder, 'ret'))

    def test_pop_and_repush_over_ret_addr_raises(self):
        builder = make_builder()
        self.make_local_setup(builder)
        builder.pop_n(1)
        builder.push_int(REPLACEMENT_VALUE)

        with self.assertRaises(RuntimeError):
            builder.call('f')

    def test_popped_ret_addr_raises(self):
        builder = make_builder()
        self.make_local_setup(builder)
        builder.pop_n(1)

        with self.assertRaises(RuntimeError):
            builder.call('f')

    def test_pop_to_over_ret_addr_raises(self):
        builder = make_builder()
        self.make_local_setup(builder)            # slots 0, 1
        builder.push_int(FILLER_VALUE)            # slot 2
        builder.push_int(REPLACEMENT_VALUE)       # slot 3
        builder.pop_to(-2 * WORD_SIZE)            # sp 4 -> 3, stores into slot 1

        with self.assertRaises(RuntimeError):
            builder.call('f')

    def test_pop_to_over_first_script_pointer_slot_raises(self):
        builder = make_builder()
        builder.push_caller_frame(add_block(builder, 'ret'))   # slots 0-4; 2 and 3 hold the script pointer
        builder.push_int(REPLACEMENT_VALUE)                      # slot 5
        builder.pop_to(-3 * WORD_SIZE)                           # sp 6 -> 5, stores into slot 2

        with self.assertRaises(RuntimeError):
            builder.call_script(MODULE_NAME, 'f', 0)

    def test_pop_to_over_local_setup_in_parameter_range_raises(self):
        builder = make_builder(LOCAL_PARAM_COUNT)
        builder.pop_n(LOCAL_PARAM_COUNT)          # the setup reuses the parameter slots
        self.make_local_setup(builder)            # slots 0, 1
        builder.push_int(FILLER_VALUE)
        builder.push_int(REPLACEMENT_VALUE)
        builder.pop_to(-2 * WORD_SIZE)            # slot 1 is a parameter slot: emitted as a frame store

        with self.assertRaises(RuntimeError):
            builder.call('f')

    def test_pop_to_over_script_setup_in_parameter_range_raises(self):
        builder = make_builder(CALLER_FRAME_SLOTS)
        builder.pop_n(CALLER_FRAME_SLOTS)
        builder.push_caller_frame(add_block(builder, 'ret'))   # slots 0-4, all parameter slots
        builder.push_int(REPLACEMENT_VALUE)
        builder.pop_to(-2 * WORD_SIZE)                           # stores into slot 3

        with self.assertRaises(RuntimeError):
            builder.call_script(MODULE_NAME, 'f', 0)

    def test_local_call_on_script_setup_raises(self):
        builder = make_builder()
        builder.push_caller_frame(add_block(builder, 'ret'))

        with self.assertRaises(RuntimeError):
            builder.call('f')

    def test_script_call_on_local_setup_raises(self):
        builder = make_builder()
        self.make_local_setup(builder)

        with self.assertRaises(RuntimeError):
            builder.call_script(MODULE_NAME, 'f', 0)

    def test_script_call_with_wrong_arg_count_raises(self):
        builder = make_builder()
        builder.push_caller_frame(add_block(builder, 'ret'))
        builder.push_int(ARG_VALUE)

        with self.assertRaises(RuntimeError):
            builder.call_script(MODULE_NAME, 'f', 0)


class TestCallSetupInSnapshots(unittest.TestCase):
    def test_setup_before_a_branch_serves_both_arms(self):
        builder = make_builder()
        left = add_block(builder, 'left')
        right = add_block(builder, 'right')
        ret_block = add_block(builder, 'ret')
        builder.push_func_id()
        builder.push_ret_addr(ret_block)
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(left, right)
        builder.save_stack_for_offset(left.start)
        builder.save_stack_for_offset(right.start)

        builder.begin_block(left)
        builder.call('f')
        builder.begin_block(right)
        builder.call('g')

        self.assertEqual(last_instruction(builder).target, 'g')

    def test_snapshot_before_push_ret_addr_is_not_changed_by_it(self):
        builder = make_builder()
        builder.push_func_id()
        snapshot = builder.save_stack_state()
        builder.push_ret_addr(add_block(builder, 'ret'))

        builder.restore_stack_state(snapshot)

        with self.assertRaises(RuntimeError):
            builder.call('f')   # the restored setup is still waiting for its return address

    def test_restore_rejects_plain_stack_snapshot(self):
        builder = make_builder()

        with self.assertRaises(TypeError):
            builder.restore_stack_state(StackSnapshot(0, []))

    def test_finalize_accepts_setup_pending_at_last_lifted_block(self):
        builder = make_builder()
        mid = add_block(builder, 'mid')
        ret_block = add_block(builder, 'ret')
        detour = add_block(builder, 'detour')
        builder.push_func_id()
        builder.push_ret_addr(ret_block)
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(mid, detour)
        builder.save_stack_for_offset(mid.start)
        builder.save_stack_for_offset(detour.start)

        builder.begin_block(mid)
        builder.call('f')
        builder.begin_block(ret_block)
        builder.ret()
        builder.begin_block(detour)   # lifted last, ends with the setup still pending
        builder.jmp(mid)

        builder.finalize()


class TestNestedCallSetups(unittest.TestCase):
    def test_script_call_inside_script_call_arguments(self):
        builder = make_builder()
        inner_ret = add_block(builder, 'inner_ret')
        outer_ret = add_block(builder, 'outer_ret')
        builder.push_caller_frame(outer_ret)
        builder.push_int(ARG_VALUE)
        outer_arg = builder.vstack_peek()
        builder.push_caller_frame(inner_ret)
        builder.call_script(MODULE_NAME, 'inner', 0)
        inner_call = last_instruction(builder)

        builder.begin_block(inner_ret)
        builder.call_script(MODULE_NAME, 'outer', 1)
        outer_call = last_instruction(builder)
        builder.begin_block(outer_ret)
        builder.ret()

        self.assertIsInstance(outer_call, LowLevelILCallScript)
        self.assertIsNot(inner_call.caller_frame, outer_call.caller_frame)
        self.assertEqual(outer_call.args, [outer_arg])
        self.assertIs(outer_call.return_target, outer_ret)

    def test_local_call_inside_script_call_setup(self):
        builder = make_builder()
        inner_ret = add_block(builder, 'inner_ret')
        outer_ret = add_block(builder, 'outer_ret')
        builder.push_caller_frame(outer_ret)
        builder.push_func_id()
        builder.push_ret_addr(inner_ret)
        builder.call('f')

        builder.begin_block(inner_ret)
        builder.call_script(MODULE_NAME, 'outer', 0)

        self.assertIs(last_instruction(builder).return_target, outer_ret)

    def test_script_call_inside_local_call_setup(self):
        builder = make_builder()
        inner_ret = add_block(builder, 'inner_ret')
        outer_ret = add_block(builder, 'outer_ret')
        builder.push_func_id()
        builder.push_ret_addr(outer_ret)
        builder.push_caller_frame(inner_ret)
        builder.call_script(MODULE_NAME, 'inner', 0)

        builder.begin_block(inner_ret)
        builder.call('f')

        self.assertIs(last_instruction(builder).return_target, outer_ret)


class TestCallSetupAtExits(unittest.TestCase):
    def make_abandoned_setup(self, builder: FalcomVMBuilder):
        builder.push_func_id()
        builder.push_ret_addr(add_block(builder, 'ret'))
        builder.pop_n(LOCAL_SETUP_SLOTS)   # sp back to empty, setup never called

    def test_return_with_pending_setup_raises(self):
        builder = make_builder()
        self.make_abandoned_setup(builder)

        with self.assertRaises(RuntimeError):
            builder.ret()

    def test_tail_call_with_pending_setup_raises(self):
        builder = make_builder()
        self.make_abandoned_setup(builder)

        with self.assertRaises(RuntimeError):
            builder.call_script_no_return(MODULE_NAME, 'f', 0)


class TestStoresBelowAPendingSetup(unittest.TestCase):
    '''An in-place store only invalidates the slot it writes, never the setup above it.'''

    def test_store_to_a_local_below_the_setup_leaves_it_callable(self):
        builder = make_builder()
        builder.push_int(FILLER_VALUE)            # slot 0, a local
        builder.push_func_id()                    # slots 1, 2
        builder.push_ret_addr(add_block(builder, 'ret'))
        builder.push_int(STORED_VALUE)            # slot 3
        builder.pop_to(-3 * WORD_SIZE)            # sp 4 -> 3, stores into slot 0

        builder.call('f')

    def test_store_to_a_parameter_below_the_setup_leaves_it_callable(self):
        builder = make_builder(LOCAL_PARAM_COUNT)
        builder.push_func_id()                    # slots 2, 3
        builder.push_ret_addr(add_block(builder, 'ret'))
        builder.push_int(STORED_VALUE)            # slot 4
        builder.pop_to(-4 * WORD_SIZE)            # sp 5 -> 4, stores into parameter slot 0

        builder.call('f')


if __name__ == '__main__':
    unittest.main()
