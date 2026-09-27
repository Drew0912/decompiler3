#!/usr/bin/env python3
'''Unit tests for POP/POP_N virtual-stack synchronization.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILCall, WORD_SIZE
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


FUNC_START = 0x1000
SECOND_BLOCK_START = FUNC_START + 0x10


def make_builder(num_params: int = 0, *, name: str = 'stack_sync_test') -> FalcomVMBuilder:
    builder = FalcomVMBuilder()
    builder.create_function(name, FUNC_START, num_params = num_params)
    entry = builder.create_basic_block(FUNC_START, name)
    builder.set_current_block(entry)
    return builder


class TestPopKeepsVstackInSync(unittest.TestCase):
    '''pop_bytes/pop_n discard the matching vstack entries, not just move sp - before the fix, a
    later operation could read a stale, already-discarded entry instead of the value actually
    beneath it.'''

    def test_single_word_pop_then_arithmetic(self):
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        builder.pop_bytes(WORD_SIZE)   # discard the '2'
        builder.push_int(3)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 0)   # the '1'
        self.assertEqual(add_inst.rhs.slot_index, 1)   # the fresh '3', not the stale '2'
        self.assertEqual(builder.vstack_size(), 1)

    def test_multi_word_pop_then_arithmetic(self):
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        builder.push_int(3)
        builder.push_int(4)
        builder.pop_bytes(2 * WORD_SIZE)   # discard '3' and '4' in one POP
        builder.push_int(5)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 1)   # the '2'
        self.assertEqual(add_inst.rhs.slot_index, 2)   # the fresh '5'
        self.assertEqual(builder.vstack_size(), 2)

    def test_pop_n_keeps_vstack_in_sync(self):
        builder = make_builder()

        builder.push_int(10)
        builder.push_int(20)
        builder.pop_n(1)   # discard the '20'
        builder.push_int(30)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 0)
        self.assertEqual(add_inst.rhs.slot_index, 1)

    def test_debug_log_then_arithmetic(self):
        # DEBUG_LOG discards its logged args via pop_n internally - same bug class.
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        builder.debug_log(1)   # logs and discards the '2'
        builder.push_int(3)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 0)
        self.assertEqual(add_inst.rhs.slot_index, 1)

    def test_pop_then_call_args_are_not_stale(self):
        builder = make_builder()
        ret_block = builder.create_basic_block(SECOND_BLOCK_START, 'stack_sync_test_ret')

        builder.push_int(999)
        builder.push_int(888)
        builder.pop_bytes(WORD_SIZE)   # unrelated discard, fully resolved before call setup

        builder.push_func_id()
        builder.push_ret_addr(ret_block)
        builder.push(builder.const_int(42))
        arg_load = builder.vstack_peek()
        builder.call('some_func')

        call_inst = builder.current_block.instructions[-1]
        self.assertIsInstance(call_inst, LowLevelILCall)
        self.assertEqual(call_inst.args, [arg_load])

    def test_pop_before_branch_preserves_trimmed_state(self):
        builder = make_builder()
        target = builder.create_basic_block(SECOND_BLOCK_START, 'stack_sync_test_target')

        builder.push_int(1)
        builder.push_int(2)
        builder.pop_bytes(WORD_SIZE)   # vstack should now hold just slot 0

        builder.save_stack_for_offset(target.start)

        saved = builder.saved_stacks[target.start]
        self.assertEqual(len(saved.values), 1)
        self.assertEqual(saved.values[0].slot_index, 0)

    def test_pop_into_parameter_area_empties_vstack_without_error(self):
        # Parameters occupy slots [0, num_params) and are never pushed to the vstack, so a POP
        # that crosses all the way into that area should just empty the vstack, not raise.
        builder = make_builder(num_params = 2)

        builder.push_int(1)
        builder.push_int(2)
        builder.pop_bytes(4 * WORD_SIZE)   # sp 4 -> 0, through both pushes and into params

        self.assertEqual(builder.sp_get(), 0)
        self.assertEqual(builder.vstack_size(), 0)

    def test_pop_no_longer_has_a_script_pointer_override(self):
        '''FalcomVMBuilder.pop() is deleted (its isinstance(expr, LowLevelILConstScript) check
        was unreachable - the vstack only ever holds LowLevelILStackLoad), so pop() now resolves
        straight to the base class and behaves like an ordinary single pop.'''
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        popped = builder.pop()

        self.assertEqual(popped.slot_index, 1)
        self.assertEqual(builder.vstack_size(), 1)
        self.assertEqual(builder.sp_get(), 1)


class TestPopValidation(unittest.TestCase):
    '''pop_bytes/pop_n reject a malformed or out-of-range discard instead of silently corrupting
    sp or leaving an untracked hole in the vstack.'''

    def test_pop_bytes_rejects_negative(self):
        builder = make_builder()
        builder.push_int(1)

        with self.assertRaises(ValueError):
            builder.pop_bytes(-WORD_SIZE)

    def test_pop_bytes_rejects_oversized(self):
        builder = make_builder()
        builder.push_int(1)   # sp = 1

        with self.assertRaises(ValueError):
            builder.pop_bytes(2 * WORD_SIZE)   # would drive sp to -1

    def test_pop_bytes_zero_is_still_a_legal_no_op(self):
        builder = make_builder()
        builder.push_int(1)

        builder.pop_bytes(0)

        self.assertEqual(builder.sp_get(), 1)
        self.assertEqual(builder.vstack_size(), 1)

    def test_pop_bytes_rejects_non_word_aligned_size(self):
        builder = make_builder()
        builder.push_int(1)
        builder.push_int(2)

        with self.assertRaises(ValueError):
            builder.pop_bytes(WORD_SIZE + 1)

    def test_pop_n_rejects_zero_and_negative(self):
        builder = make_builder()
        builder.push_int(1)

        with self.assertRaises(ValueError):
            builder.pop_n(0)

        with self.assertRaises(ValueError):
            builder.pop_n(-1)

    def test_pop_n_rejects_oversized(self):
        builder = make_builder()
        builder.push_int(1)   # sp = 1

        with self.assertRaises(ValueError):
            builder.pop_n(2)   # would drive sp to -1


if __name__ == '__main__':
    unittest.main()
