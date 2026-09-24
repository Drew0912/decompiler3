#!/usr/bin/env python3
'''Unit tests for LLIL lifting-order/state-management fixes (Step J).'''

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILBasicBlock, WORD_SIZE
from falcom.ed9.disasm.basic_block import BasicBlock
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


FUNC_START = 0x1000
SECOND_BLOCK_START = FUNC_START + 0x10
THIRD_BLOCK_START = FUNC_START + 0x20
UNREGISTERED_BLOCK_OFFSET = 0x9999
DELIBERATELY_DIFFERENT_SP = 9
SENTINEL_SP_OUT = 999


def make_rpo_lifter() -> ED9VMLifter:
    '''_compute_rpo touches no lifter/parser state, so any non-None parser satisfies the
    constructor.'''
    return ED9VMLifter(parser = object())


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
        builder.saved_stacks[SECOND_BLOCK_START] = replace(
            builder.save_stack_state(), sp = DELIBERATELY_DIFFERENT_SP, values = []
        )

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


class TestComputeRPO(unittest.TestCase):
    '''_compute_rpo over the disassembler CFG (BasicBlock/succs), independent of the LLIL
    builder entirely.'''

    def test_diamond_places_join_after_both_arms(self):
        entry = BasicBlock(start_offset = FUNC_START)
        a = BasicBlock(start_offset = FUNC_START + 0x10)
        b = BasicBlock(start_offset = FUNC_START + 0x20)
        join = BasicBlock(start_offset = FUNC_START + 0x30)
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
        body = BasicBlock(start_offset = FUNC_START + 0x10)
        exit_block = BasicBlock(start_offset = FUNC_START + 0x20)
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
        '''header/body/exit, matching TestComputeRPO's own loop shape: body legitimately carries
        state across the back edge; exit reaches RETURN cleanly. Neither finalize() nor ret()
        should be confused by body being lifted last.'''
        builder = make_builder()
        header = builder.function.basic_blocks[0]
        exit_block = builder.create_basic_block(SECOND_BLOCK_START, 'exit')
        body = builder.create_basic_block(THIRD_BLOCK_START, 'body')

        builder.push_int(42)   # loop-carried value - never popped along the body path
        builder.push_int(0)    # condition
        builder.pop_jmp_zero(exit_block, body)
        builder.save_stack_for_offset(exit_block.start)
        builder.save_stack_for_offset(body.start)

        builder.begin_block(exit_block)   # RPO lifts exit before body - see TestComputeRPO
        builder.pop_bytes(WORD_SIZE)       # exit path cleans up the loop-carried value
        builder.ret()                      # must not raise

        builder.begin_block(body)
        builder.jmp(header)   # back edge - body's own carried value is still on the stack here
        builder.save_stack_for_offset(header.start)

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
        builder.save_stack_for_offset(farther.start)

        builder.begin_block(farther)
        builder.pop_bytes(WORD_SIZE)
        builder.jmp(ret_block)
        builder.save_stack_for_offset(ret_block.start)

        builder.begin_block(ret_block)
        builder.ret()   # must not raise - sp is genuinely 0 here, restored from farther's save

        builder.finalize()

    def test_call_return_state_correct_even_when_not_lift_order_adjacent(self):
        '''call()'s own save_stack_for_offset means the return block's state doesn't depend on
        whatever happens to be lifted immediately before it.'''
        builder = make_builder()
        other_branch = builder.create_basic_block(SECOND_BLOCK_START, 'other_branch')
        ret_target = builder.create_basic_block(THIRD_BLOCK_START, 'ret_target')

        builder.push_func_id()
        builder.push_ret_addr(ret_target)
        builder.call('some_func')   # should save_stack_for_offset(ret_target.start) internally

        builder.begin_block(other_branch)   # lifted before ret_target, leaves unrelated state
        builder.push_int(999)
        builder.pop_bytes(WORD_SIZE)
        builder.ret()

        builder.begin_block(ret_target)
        builder.ret()   # must see sp=0 regardless of what other_branch did in between

        builder.finalize()


class TestReachableEmptyBlocks(unittest.TestCase):
    '''Every reachable block must end in a terminal - an empty one has none, so control would
    leave the function without passing an exit check.'''

    def test_jump_to_empty_block_raises_at_finalize(self):
        builder = make_builder()
        empty = builder.create_basic_block(SECOND_BLOCK_START, 'empty')
        builder.jmp(empty)

        with self.assertRaises(RuntimeError):
            builder.finalize()

    def test_unreferenced_empty_block_is_allowed(self):
        builder = make_builder()
        builder.create_basic_block(SECOND_BLOCK_START, 'unused')
        builder.ret()

        builder.finalize()


if __name__ == '__main__':
    unittest.main()
