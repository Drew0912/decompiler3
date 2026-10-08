#!/usr/bin/env python3
'''Unit tests for LLIL lifting order and block state: instructions are indexed in block order, blocks
lift in reverse post-order, every CFG edge records the stack state it carries, and a join or back edge
with a different stack height raises.'''

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILBasicBlock, LowLevelILEq, LowLevelILJmp, WORD_SIZE
from ir.llil.llil_builder import LowLevelILBuilder
from falcom.ed9.disasm.basic_block import BasicBlock
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


FUNC_START = 0x1000
SECOND_BLOCK_START = FUNC_START + 0x10
THIRD_BLOCK_START = FUNC_START + 0x20
FOURTH_BLOCK_START = FUNC_START + 0x30
UNREGISTERED_BLOCK_OFFSET = 0x9999
DELIBERATELY_DIFFERENT_SP = 9
SENTINEL_SP_OUT = 999
CONDITION_VALUE = 0
LEFT_VALUE = 1
RIGHT_VALUE = 2
SEED_PARAM_COUNT = 2
NO_ARGS = 0
MODULE_NAME = 'module'


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

    def test_duplicate_block_start_raises(self):
        builder = make_builder()
        builder.create_basic_block(SECOND_BLOCK_START, 'first')

        with self.assertRaises(RuntimeError):
            builder.create_basic_block(SECOND_BLOCK_START, 'second')


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

    def test_back_edge_into_entry_with_a_different_sp_raises(self):
        builder = make_builder(num_params = SEED_PARAM_COUNT)
        entry = builder.function.basic_blocks[0]
        body = builder.create_basic_block(SECOND_BLOCK_START, 'body')
        builder.jmp(body)

        builder.begin_block(body)
        builder.push_int(LEFT_VALUE)

        with self.assertRaises(RuntimeError):
            builder.jmp(entry)


class TestStrictEdgeState(unittest.TestCase):
    '''The first edge into a block records its state; every other edge must bring the same shape.'''

    def make_diamond(self, num_params: int = 0):
        builder = make_builder(num_params = num_params)
        left = builder.create_basic_block(SECOND_BLOCK_START, 'left')
        right = builder.create_basic_block(THIRD_BLOCK_START, 'right')
        join = builder.create_basic_block(FOURTH_BLOCK_START, 'join')
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(left, right)
        return builder, left, right, join

    def test_begin_block_without_recorded_state_raises(self):
        builder = make_builder()
        orphan = builder.create_basic_block(SECOND_BLOCK_START, 'orphan')

        with self.assertRaises(RuntimeError):
            builder.begin_block(orphan)

    def test_join_with_different_sp_raises(self):
        builder, left, right, join = self.make_diamond()
        builder.begin_block(left)
        builder.push_int(LEFT_VALUE)
        builder.jmp(join)
        builder.begin_block(right)

        with self.assertRaises(RuntimeError):
            builder.jmp(join)

    def test_join_with_different_values_in_one_slot_is_accepted(self):
        builder, left, right, join = self.make_diamond()
        builder.begin_block(left)
        builder.push_int(LEFT_VALUE)
        builder.jmp(join)
        builder.begin_block(right)
        builder.push_int(RIGHT_VALUE)
        builder.jmp(join)

        builder.begin_block(join)

        self.assertEqual(builder.vstack_peek().slot_index, 0)   # the join reads the slot, whichever arm wrote it

    def test_back_edge_with_a_grown_stack_raises(self):
        builder = make_builder()
        header = builder.create_basic_block(SECOND_BLOCK_START, 'header')
        exit_block = builder.create_basic_block(THIRD_BLOCK_START, 'exit')
        body = builder.create_basic_block(FOURTH_BLOCK_START, 'body')
        builder.jmp(header)
        builder.begin_block(header)
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(exit_block, body)
        builder.begin_block(body)
        builder.push_int(LEFT_VALUE)

        with self.assertRaises(RuntimeError):
            builder.jmp(header)

    def enter_caller_after_return_block_lifted_at_sp_one(self):
        builder, direct, caller, ret_block = self.make_diamond()
        builder.begin_block(direct)
        builder.push_int(LEFT_VALUE)
        builder.jmp(ret_block)
        builder.begin_block(ret_block)   # lifted with sp 1
        builder.begin_block(caller)
        return builder, ret_block

    def test_local_call_return_into_a_lifted_block_with_a_different_sp_raises(self):
        builder, ret_block = self.enter_caller_after_return_block_lifted_at_sp_one()
        builder.push_func_id()
        builder.push_ret_addr(ret_block)

        with self.assertRaises(RuntimeError):
            builder.call('f', NO_ARGS)   # returns at sp 0

    def test_script_call_return_into_a_lifted_block_with_a_different_sp_raises(self):
        builder, ret_block = self.enter_caller_after_return_block_lifted_at_sp_one()
        builder.push_caller_frame(ret_block)

        with self.assertRaises(RuntimeError):
            builder.call_script(MODULE_NAME, 'f', 0)   # returns at sp 0

    def test_parameter_kept_on_one_arm_and_repushed_on_the_other_raises(self):
        '''The arms hold different lifetimes in slot 0 - the caller's parameter (arg1) and a pushed value
        (var_s0) - so no single name is right for a read after the join.'''
        builder, left, right, join = self.make_diamond(num_params = 1)
        builder.begin_block(left)
        builder.pop_n(1)
        builder.push_int(LEFT_VALUE)
        builder.jmp(join)
        builder.begin_block(right)

        with self.assertRaises(RuntimeError):
            builder.jmp(join)


class TestEdgeRecording(unittest.TestCase):
    '''Each terminal records the stack state of its own edges; finalize() checks the records are
    exactly the CFG's edges.'''

    def test_terminals_record_their_edges(self):
        builder = make_builder()
        left = builder.create_basic_block(SECOND_BLOCK_START, 'left')
        right = builder.create_basic_block(THIRD_BLOCK_START, 'right')
        join = builder.create_basic_block(FOURTH_BLOCK_START, 'join')
        builder.push_int(CONDITION_VALUE)
        builder.pop_jmp_zero(left, right)

        builder.begin_block(left)
        condition = LowLevelILEq(builder.const_int(CONDITION_VALUE), builder.const_int(CONDITION_VALUE))
        builder.branch_if(condition, join, right)
        builder.begin_block(right)
        builder.jmp(join)
        builder.begin_block(join)
        builder.ret()

        builder.finalize()   # every edge recorded without a manual save

    def test_generic_call_edge_without_a_record_raises_at_finalize(self):
        builder = make_builder()
        ret_block = builder.create_basic_block(SECOND_BLOCK_START, 'ret')
        LowLevelILBuilder.call(builder, 'f', ret_block)   # records nothing
        builder.set_current_block(ret_block)
        builder.ret()

        with self.assertRaisesRegex(RuntimeError, 'no recorded stack state'):
            builder.finalize()

    def test_manual_save_does_not_stand_in_for_a_raw_terminal_edge(self):
        builder = make_builder()
        target = builder.create_basic_block(SECOND_BLOCK_START, 'target')
        builder.save_stack_for_offset(target.start)   # sp 0
        builder.push_int(LEFT_VALUE)
        builder.add_instruction(LowLevelILJmp(target))   # the edge carries sp 1
        builder.begin_block(target)
        builder.ret()

        with self.assertRaisesRegex(RuntimeError, 'no recorded stack state'):
            builder.finalize()

    def test_recorded_edge_outside_the_cfg_raises_at_finalize(self):
        builder = make_builder()
        target = builder.create_basic_block(SECOND_BLOCK_START, 'target')
        other = builder.create_basic_block(THIRD_BLOCK_START, 'other')
        jmp_inst = LowLevelILJmp(target)
        builder.add_instruction(jmp_inst)
        builder._record_edge_state(jmp_inst, target)
        builder._record_edge_state(jmp_inst, other)
        builder.begin_block(target)
        builder.ret()
        builder.begin_block(other)
        builder.ret()

        with self.assertRaisesRegex(RuntimeError, 'not a CFG edge'):
            builder.finalize()

    def test_edge_record_for_a_terminal_that_does_not_end_the_block_raises(self):
        builder = make_builder()
        target = builder.create_basic_block(SECOND_BLOCK_START, 'target')

        with self.assertRaises(RuntimeError):
            builder._record_edge_state(LowLevelILJmp(target), target)


if __name__ == '__main__':
    unittest.main()
