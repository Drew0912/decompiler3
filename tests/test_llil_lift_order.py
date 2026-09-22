#!/usr/bin/env python3
'''Unit tests for LLIL lifting-order/state-management fixes (Step J).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


FUNC_START = 0x1000
SECOND_BLOCK_START = FUNC_START + 0x10


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

        # Before reindexing, registration order (not block order) is what inst_index reflects.
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


if __name__ == '__main__':
    unittest.main()
