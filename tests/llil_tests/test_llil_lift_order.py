#!/usr/bin/env python3
'''Unit tests for LLIL lifting order and block state: instructions are indexed in block order, blocks
lift in reverse post-order, every terminal records the stack state its edges carry, and a join whose arms
hold different lifetimes in one slot raises.'''

from dataclasses import replace
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILEq, WORD_SIZE
from falcom.ed9.disasm.basic_block import BasicBlock
from falcom.ed9.ir.llil import ED9VMLifter
from tests.shared.llil_utils import (
    FOURTH_BLOCK_START, FUNC_START, SECOND_BLOCK_START, THIRD_BLOCK_START, make_builder,
)


DELIBERATELY_DIFFERENT_SP = 9
CONDITION_VALUE = 0
LEFT_VALUE = 1
RIGHT_VALUE = 2
SEED_PARAM_COUNT = 2
NO_ARGS = 0


def make_rpo_lifter() -> ED9VMLifter:
    '''_compute_rpo touches no lifter/parser state, so any non-None parser satisfies the
    constructor.'''
    return ED9VMLifter(parser = object())


def make_diamond(num_params: int = 0):
    '''entry tests a pushed constant and branches to left or right; join is created but not reached yet'''
    builder = make_builder(num_params = num_params)
    left = builder.create_basic_block(SECOND_BLOCK_START, 'left')
    right = builder.create_basic_block(THIRD_BLOCK_START, 'right')
    join = builder.create_basic_block(FOURTH_BLOCK_START, 'join')
    builder.push_int(CONDITION_VALUE)
    builder.pop_jmp_zero(left, right)
    return builder, left, right, join


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

    def test_finalize_numbers_in_block_order(self):
        builder = make_builder()
        second = builder.create_basic_block(SECOND_BLOCK_START, 'second')
        entry = builder.function.basic_blocks[0]

        # second's instruction is registered before entry's, as when the lifter translates out of block order
        builder.set_current_block(second)
        builder.ret()
        ret_inst = second.instructions[-1]
        builder.set_current_block(entry)
        builder.jmp(second)
        jmp_inst = entry.instructions[-1]

        func = builder.finalize()

        self.assertEqual((jmp_inst.inst_index, ret_inst.inst_index), (0, 1))
        self.assertEqual(list(func.iter_instructions()), [jmp_inst, ret_inst])


class TestBlockLifecycle(unittest.TestCase):
    '''begin_block opens a block with its recorded stack state, not the previous block's exit state.'''

    def test_begin_block_opens_the_block_with_its_saved_sp(self):
        builder = make_builder()
        other = builder.create_basic_block(SECOND_BLOCK_START, 'other')

        builder.push_int(1)
        builder.saved_stacks[SECOND_BLOCK_START] = replace(
            builder.save_stack_state(), sp = DELIBERATELY_DIFFERENT_SP, values = []
        )

        builder.begin_block(other)

        self.assertEqual(other.sp_in, DELIBERATELY_DIFFERENT_SP)


class TestComputeRPO(unittest.TestCase):
    '''_compute_rpo over the disassembler CFG (BasicBlock/succs), independent of the LLIL
    builder entirely.'''

    def test_diamond_places_join_after_both_arms(self):
        entry = BasicBlock(start_offset = FUNC_START)
        a = BasicBlock(start_offset = SECOND_BLOCK_START)
        b = BasicBlock(start_offset = THIRD_BLOCK_START)
        join = BasicBlock(start_offset = FOURTH_BLOCK_START)
        entry.add_branch(a)
        entry.add_branch(b)
        a.add_branch(join)
        b.add_branch(join)

        order = make_rpo_lifter()._compute_rpo(entry)

        self.assertEqual(order[0], entry)
        self.assertEqual(order[-1], join)
        self.assertLess(order.index(a), order.index(join))
        self.assertLess(order.index(b), order.index(join))

    def test_loop_back_edge_places_body_after_header_and_exit(self):
        '''The exact shape that broke finalize()'s old blanket check: header.succs=[body, exit],
        body -> header. RPO must place header first; body (which can legitimately carry state
        across the back edge) ends up last, not exit (the real RETURN path).'''
        header = BasicBlock(start_offset = FUNC_START)
        body = BasicBlock(start_offset = SECOND_BLOCK_START)
        exit_block = BasicBlock(start_offset = THIRD_BLOCK_START)
        header.add_branch(body)
        header.add_branch(exit_block)
        body.add_branch(header)

        order = make_rpo_lifter()._compute_rpo(header)

        self.assertEqual(order, [header, exit_block, body])

    def test_rpo_is_not_secretly_address_order(self):
        '''entry -> higher-address block -> lower-address block (the original counterexample
        shape). RPO must visit the lower-address block AFTER the higher-address one, proving it
        isn't just re-deriving address order.'''
        entry = BasicBlock(start_offset = FUNC_START)
        higher = BasicBlock(start_offset = THIRD_BLOCK_START)
        lower = BasicBlock(start_offset = SECOND_BLOCK_START)
        entry.add_branch(higher)
        higher.add_branch(lower)

        order = make_rpo_lifter()._compute_rpo(entry)

        self.assertEqual(order, [entry, higher, lower])
        self.assertEqual(sorted(order, key = lambda b: b.offset), [entry, lower, higher])


class TestRPOIntegration(unittest.TestCase):
    '''The mechanisms RPO depends on for safety - real per-exit validation and call-return edge
    saving - proven together at the builder level.'''

    def test_loop_with_carried_state_does_not_confuse_the_exit_check(self):
        '''header/body/exit, matching TestComputeRPO's own loop shape, with one parameter: body is
        lifted last and ends at sp 1 (the parameter is still on the stack) as it jumps back; exit pops
        the parameter and returns. Neither finalize() nor ret() should be confused by body being
        lifted last.'''
        builder = make_builder(num_params = 1)
        header = builder.function.basic_blocks[0]
        exit_block = builder.create_basic_block(SECOND_BLOCK_START, 'exit')
        body = builder.create_basic_block(THIRD_BLOCK_START, 'body')

        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(exit_block, body)

        builder.begin_block(exit_block)   # RPO lifts exit before body - see TestComputeRPO
        builder.pop_bytes(WORD_SIZE)       # exit path pops the parameter
        builder.ret()                      # must not raise

        builder.begin_block(body)
        builder.jmp(header)   # back edge - same stack as the header's entry state

        builder.finalize()   # must not raise either

    def test_original_counterexample_lifts_without_raising(self):
        '''entry -> JMP farther; farther: POP, JMP ret_block; ret_block: RETURN - the original
        hand-traced counterexample where address-order lifting would reach a RETURN block before
        its true predecessor had run.'''
        builder = make_builder()
        entry = builder.function.basic_blocks[0]
        farther = builder.create_basic_block(THIRD_BLOCK_START, 'farther')
        ret_block = builder.create_basic_block(SECOND_BLOCK_START, 'ret_block')   # lower address

        builder.push_int(1)
        builder.jmp(farther)

        builder.begin_block(farther)
        builder.pop_bytes(WORD_SIZE)
        builder.jmp(ret_block)

        builder.begin_block(ret_block)
        builder.ret()   # must not raise - sp is genuinely 0 here, restored from farther's edge state

        builder.finalize()

    def test_call_return_state_correct_even_when_not_lift_order_adjacent(self):
        '''call() records its own return edge, so the return block's state doesn't depend on
        whatever happens to be lifted immediately before it.'''
        builder = make_builder()
        call_block = builder.create_basic_block(SECOND_BLOCK_START, 'call_block')
        other_branch = builder.create_basic_block(THIRD_BLOCK_START, 'other_branch')
        ret_target = builder.create_basic_block(FOURTH_BLOCK_START, 'ret_target')

        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(call_block, other_branch)

        builder.begin_block(call_block)
        builder.push_func_id()
        builder.push_ret_addr(ret_target)
        builder.call('some_func', NO_ARGS)   # records the edge into ret_target itself

        builder.begin_block(other_branch)   # lifted before ret_target, leaves unrelated state
        builder.push_int(999)
        builder.pop_bytes(WORD_SIZE)
        builder.ret()

        builder.begin_block(ret_target)
        builder.ret()   # must see sp=0 regardless of what other_branch did in between

        builder.finalize()


class TestEntrySeed(unittest.TestCase):
    '''create_function records the entry state: only the parameters on the stack, none tracked.'''

    def test_entry_block_starts_with_only_the_parameters(self):
        builder = make_builder(num_params = SEED_PARAM_COUNT)

        self.assertEqual(builder.function.basic_blocks[0].sp_in, SEED_PARAM_COUNT)
        self.assertEqual(builder.vstack_size(), 0)
        self.assertEqual((builder.frame_base_sp, builder.function.frame_base_sp), (0, 0))

    def test_back_edge_into_entry_with_the_entry_state_is_accepted(self):
        builder = make_builder(num_params = SEED_PARAM_COUNT)
        entry = builder.function.basic_blocks[0]
        body = builder.create_basic_block(SECOND_BLOCK_START, 'body')
        builder.jmp(body)

        builder.begin_block(body)
        builder.jmp(entry)   # must not raise


class TestStrictEdgeState(unittest.TestCase):
    '''The first edge into a block records its state; every other edge must bring the same shape.'''

    def test_join_with_different_values_in_one_slot_is_accepted(self):
        builder, left, right, join = make_diamond()
        builder.begin_block(left)
        builder.push_int(LEFT_VALUE)
        builder.jmp(join)
        builder.begin_block(right)
        builder.push_int(RIGHT_VALUE)
        builder.jmp(join)

        builder.begin_block(join)

        self.assertEqual(builder.vstack_peek().slot_index, 0)   # the join reads the slot, whichever arm wrote it

    def test_parameter_kept_on_one_arm_and_repushed_on_the_other_raises(self):
        '''The arms hold different lifetimes in slot 0 - the caller's parameter (arg1) and a pushed value
        (var_s0) - so no single name is right for a read after the join.'''
        builder, left, right, join = make_diamond(num_params = 1)
        builder.begin_block(left)
        builder.pop_n(1)
        builder.push_int(LEFT_VALUE)
        builder.jmp(join)
        builder.begin_block(right)

        with self.assertRaises(RuntimeError):
            builder.jmp(join)


class TestEdgeRecording(unittest.TestCase):
    '''Each terminal records the stack state of its own edges.'''

    def test_terminals_record_their_edges(self):
        builder, left, right, join = make_diamond()

        builder.begin_block(left)
        condition = LowLevelILEq(builder.const_int(CONDITION_VALUE), builder.const_int(CONDITION_VALUE))
        builder.branch_if(condition, join, right)
        builder.begin_block(right)
        builder.jmp(join)
        builder.begin_block(join)
        builder.ret()

        builder.finalize()   # every edge recorded without a manual save


if __name__ == '__main__':
    unittest.main()
