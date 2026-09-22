#!/usr/bin/env python3
'''Unit tests for LLIL lifting-order/state-management fixes (Step J).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILBasicBlock
from ir.llil.llil_builder import StackSnapshot
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


FUNC_START = 0x1000
SECOND_BLOCK_START = FUNC_START + 0x10
UNREGISTERED_BLOCK_OFFSET = 0x9999
DELIBERATELY_DIFFERENT_SP = 9
SENTINEL_SP_OUT = 999


def make_builder(num_params: int = 0, *, name: str = 'lift_order_test') -> FalcomVMBuilder:
    builder = FalcomVMBuilder()
    builder.create_function(name, FUNC_START, num_params = num_params)
    entry = builder.create_basic_block(FUNC_START, name)
    builder.set_current_block(entry)
    return builder


class TestReindexInBlockOrder(unittest.TestCase):
    '''reindex_in_block_order() keeps inst_index/iter_instructions() ordered by basic_blocks list
    position, independent of the order instructions were actually registered in - needed once a
    lifter translates blocks in a different order than it creates them.'''

    def test_noop_when_already_registered_in_block_order(self):
        builder = make_builder()
        second = builder.create_basic_block(SECOND_BLOCK_START, 'second')

        builder.debug_line(1)
        builder.set_current_block(second)
        builder.debug_line(2)

        before = [inst.inst_index for inst in builder.function.iter_instructions()]
        builder.function.reindex_in_block_order()
        after = [inst.inst_index for inst in builder.function.iter_instructions()]

        self.assertEqual(before, after)
        self.assertEqual([0, 1], after)

    def test_reassigns_when_registered_out_of_block_order(self):
        builder = make_builder()
        second = builder.create_basic_block(SECOND_BLOCK_START, 'second')
        entry = builder.function.basic_blocks[0]

        # basic_blocks list order is [entry, second] (creation order), but register second's
        # instruction before entry's - simulating a lifter that translates out of that order.
        builder.set_current_block(second)
        builder.debug_line(2)
        second_inst = second.instructions[-1]

        builder.set_current_block(entry)
        builder.debug_line(1)
        first_inst = entry.instructions[-1]

        self.assertEqual(second_inst.inst_index, 0)
        self.assertEqual(first_inst.inst_index, 1)

        builder.function.reindex_in_block_order()

        self.assertEqual(first_inst.inst_index, 0)
        self.assertEqual(second_inst.inst_index, 1)
        self.assertIs(builder.function.get_instruction_by_index(0), first_inst)
        self.assertIs(builder.function.get_instruction_by_index(1), second_inst)
        self.assertIs(builder.function.get_instruction_block_by_index(0), entry)
        self.assertIs(builder.function.get_instruction_block_by_index(1), second)

    def test_finalize_leaves_function_already_reindexed(self):
        builder = make_builder()
        second = builder.create_basic_block(SECOND_BLOCK_START, 'second')

        builder.jmp(second)
        builder.set_current_block(second)
        builder.ret()

        func = builder.finalize()
        before = [(inst.inst_index, id(inst)) for inst in func.iter_instructions()]
        func.reindex_in_block_order()
        after = [(inst.inst_index, id(inst)) for inst in func.iter_instructions()]

        self.assertEqual(before, after)


class TestBlockLifecycle(unittest.TestCase):
    '''begin_block/set_current_block/finalize() split "close the old block" from "open the new
    one" with a restore in between, fixing a bug where the previous block's sp_out was recorded
    from the next block's just-restored sp instead of its own true exit sp.'''

    def test_begin_block_records_previous_blocks_true_exit_sp(self):
        builder = make_builder()
        entry = builder.function.basic_blocks[0]
        other = builder.create_basic_block(SECOND_BLOCK_START, 'other')

        builder.push_int(1)
        builder.saved_stacks[SECOND_BLOCK_START] = StackSnapshot(sp = DELIBERATELY_DIFFERENT_SP, values = [])

        builder.begin_block(other)

        self.assertEqual(entry.sp_out, 1)
        self.assertEqual(other.sp_in, DELIBERATELY_DIFFERENT_SP)

    def test_set_current_block_validates_before_mutating_previous_block(self):
        builder = make_builder()
        entry = builder.function.basic_blocks[0]
        builder.push_int(1)

        unregistered = LowLevelILBasicBlock(UNREGISTERED_BLOCK_OFFSET)

        with self.assertRaises(RuntimeError):
            builder.set_current_block(unregistered)

        self.assertEqual(entry.sp_out, 0)

    def test_begin_block_validates_before_mutating_previous_block(self):
        builder = make_builder()
        entry = builder.function.basic_blocks[0]
        builder.push_int(1)

        unregistered = LowLevelILBasicBlock(UNREGISTERED_BLOCK_OFFSET)

        with self.assertRaises(RuntimeError):
            builder.begin_block(unregistered)

        self.assertEqual(entry.sp_out, 0)

    def test_finalize_closes_the_active_block_without_an_explicit_end_call(self):
        '''A caller that only ever calls set_current_block (as tests/demos do, never begin_block)
        still gets its last block closed once finalize() runs.'''
        builder = make_builder()
        entry = builder.function.basic_blocks[0]
        entry.sp_out = SENTINEL_SP_OUT

        builder.ret()
        builder.finalize()

        self.assertEqual(entry.sp_out, 0)


if __name__ == '__main__':
    unittest.main()
