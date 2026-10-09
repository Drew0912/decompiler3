#!/usr/bin/env python3
'''Unit tests for LLIL call-setup tracking: each pending call setup (PUSH_CURRENT_FUNC_ID +
PUSH_RET_ADDR, or PUSH_CALLER_FRAME) is a record carried in stack snapshots and consumed by its call -
across branches, joins, nested calls and stores below it. Malformed setups never reach the builder: the
parser's stack simulation rejects them first (test_scp_stack_simulation.py).'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILCall, WORD_SIZE
from falcom.ed9.disasm.stack_effects import LOCAL_SETUP_SLOTS
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.llil.llil_ext import LowLevelILCallScript
from tests.shared.llil_utils import FUNC_START, make_builder


BLOCK_STRIDE = 0x10
ARG_VALUE = 7
FILLER_VALUE = 123
STORED_VALUE = 5
CONDITION_VALUE = 1
LOCAL_PARAM_COUNT = 2
NO_ARGS = 0
ONE_ARG = 1
MODULE_NAME = 'module'


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

        builder.call('f', ONE_ARG)

        self.assertIsInstance(last_instruction(builder), LowLevelILCall)
        self.assertEqual(last_instruction(builder).args, [arg_load])
        builder.begin_block(ret_block)
        builder.ret()   # no setup left pending

    def test_push_ret_addr_after_balanced_push_pop_is_accepted(self):
        builder = make_builder()
        ret_block = add_block(builder, 'ret')
        builder.push_func_id()
        builder.push_int(FILLER_VALUE)
        builder.pop_n(1)
        builder.push_ret_addr(ret_block)

        builder.call('f', NO_ARGS)


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

        builder.begin_block(left)
        builder.call('f', NO_ARGS)
        builder.begin_block(right)
        builder.call('g', NO_ARGS)

        self.assertEqual(last_instruction(builder).target, 'g')

    def test_snapshot_before_push_ret_addr_is_not_changed_by_it(self):
        builder = make_builder()
        builder.push_func_id()
        snapshot = builder.save_stack_state()
        builder.push_ret_addr(add_block(builder, 'ret'))

        builder.restore_stack_state(snapshot)

        # The restored setup is still waiting for its return address (a restore keeping the completed setup would
        # raise at its popped return-address slot instead)
        with self.assertRaises(RuntimeError) as caught:
            builder.call('f', NO_ARGS)

        self.assertEqual(str(caught.exception),
                         'LOCAL call, but the innermost pending call setup has no return address yet')

    def test_finalize_accepts_setup_pending_at_last_lifted_block(self):
        builder = make_builder()
        mid = add_block(builder, 'mid')
        ret_block = add_block(builder, 'ret')
        detour = add_block(builder, 'detour')
        builder.push_func_id()
        builder.push_ret_addr(ret_block)
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(mid, detour)

        builder.begin_block(mid)
        builder.call('f', NO_ARGS)
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
        builder.call('f', NO_ARGS)

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
        builder.call('f', NO_ARGS)

        self.assertIs(last_instruction(builder).return_target, outer_ret)


class TestStoresBelowAPendingSetup(unittest.TestCase):
    '''An in-place store only invalidates the slot it writes, never the setup above it.'''

    def test_store_to_a_local_below_the_setup_leaves_it_callable(self):
        builder = make_builder()
        builder.push_int(FILLER_VALUE)            # slot 0, a local
        builder.push_func_id()                    # slots 1, 2
        builder.push_ret_addr(add_block(builder, 'ret'))
        builder.push_int(STORED_VALUE)            # slot 3
        builder.pop_to(-3 * WORD_SIZE)            # sp 4 -> 3, stores into slot 0

        builder.call('f', NO_ARGS)

    def test_store_to_a_parameter_below_the_setup_leaves_it_callable(self):
        builder = make_builder(LOCAL_PARAM_COUNT)
        builder.push_func_id()                    # slots 2, 3
        builder.push_ret_addr(add_block(builder, 'ret'))
        builder.push_int(STORED_VALUE)            # slot 4
        builder.pop_to(-4 * WORD_SIZE)            # sp 5 -> 4, stores into parameter slot 0

        builder.call('f', NO_ARGS)


class TestCallSetupsAtJoins(unittest.TestCase):
    '''Arms that bring the same pending setups to a join are accepted, whatever values they push above them.'''

    def make_branch(self, builder: FalcomVMBuilder):
        left = add_block(builder, 'left')
        right = add_block(builder, 'right')
        join = add_block(builder, 'join')
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(left, right)
        return left, right, join

    def make_branch_after_local_setup(self, builder: FalcomVMBuilder):
        ret_block = add_block(builder, 'ret')
        builder.push_func_id()                    # slots 0, 1
        builder.push_ret_addr(ret_block)
        return self.make_branch(builder)

    def test_arms_pushing_their_own_equal_setup_are_accepted(self):
        builder = make_builder()
        left, right, join = self.make_branch(builder)
        ret_block = add_block(builder, 'ret')
        for arm in (left, right):
            builder.begin_block(arm)
            builder.push_func_id()
            builder.push_ret_addr(ret_block)
            builder.jmp(join)

        builder.begin_block(join)
        builder.call('f', NO_ARGS)
        builder.begin_block(ret_block)
        builder.ret()

        builder.finalize()

    def test_argument_pushed_differently_on_each_arm_is_accepted(self):
        builder = make_builder()
        left, right, join = self.make_branch_after_local_setup(builder)
        for arm, value in ((left, ARG_VALUE), (right, FILLER_VALUE)):
            builder.begin_block(arm)
            builder.push_int(value)
            builder.jmp(join)

        builder.begin_block(join)
        builder.call('f', ONE_ARG)

        self.assertEqual(last_instruction(builder).args[0].slot_index, LOCAL_SETUP_SLOTS)


if __name__ == '__main__':
    unittest.main()
