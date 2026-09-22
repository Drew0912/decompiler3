#!/usr/bin/env python3
'''Unit tests for BlockMergePass - Step 10 of the LLIL/MLIL hardening plan. A LowLevelILCall is
a block terminator, so the LLIL->MLIL translator ends every call block with a plain `goto` to its
return block; this pass splices any block whose only way in is another block's unconditional
goto into that block, undoing the split (and any real bytecode JMP that happens to land on a
single-predecessor target).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MLILConst, MLILGoto, MLILIf, MLILRet, MLILCall,
)
from ir.mlil.mlil_ssa import MLILPhi, MLILVariableSSA
from ir.mlil.passes import BlockMergePass


FUNC_START = 0x1000


class TestStraightChainMerge(unittest.TestCase):
    '''The base case: a call-return split collapses back into one block.'''

    def test_call_return_split_merges_into_one_block(self):
        func = MediumLevelILFunction('straight_chain')
        head = func.create_block(start = FUNC_START, label = 'head')
        tail = func.create_block(start = FUNC_START + 4, label = 'tail')

        head.add_instruction(MLILCall('Foo', []))
        head.add_instruction(MLILGoto(tail))
        head.add_outgoing_edge(tail)

        tail.add_instruction(MLILRet(None))

        BlockMergePass().run(func)

        self.assertEqual(func.basic_blocks, [head])
        self.assertEqual(len(head.instructions), 2)
        self.assertIsInstance(head.instructions[0], MLILCall)
        self.assertIsInstance(head.instructions[1], MLILRet)
        self.assertEqual(head.outgoing_edges, [])


class TestMultiHopCascade(unittest.TestCase):
    '''A chain of more than two blocks must fully drain in one pass, not just one hop.'''

    def test_three_block_chain_drains_in_one_sweep(self):
        func = MediumLevelILFunction('chain3')
        a = func.create_block(start = FUNC_START, label = 'a')
        b = func.create_block(start = FUNC_START + 4, label = 'b')
        c = func.create_block(start = FUNC_START + 8, label = 'c')

        a.add_instruction(MLILCall('A', []))
        a.add_instruction(MLILGoto(b))
        a.add_outgoing_edge(b)

        b.add_instruction(MLILCall('B', []))
        b.add_instruction(MLILGoto(c))
        b.add_outgoing_edge(c)

        c.add_instruction(MLILRet(None))

        BlockMergePass().run(func)

        self.assertEqual(func.basic_blocks, [a])
        self.assertEqual(len(a.instructions), 3)
        self.assertIsInstance(a.instructions[-1], MLILRet)


class TestSelfLoopGuard(unittest.TestCase):
    '''A block whose own terminal is a self-goto must never be merged into itself.'''

    def test_self_goto_is_not_merged(self):
        func = MediumLevelILFunction('self_loop')
        entry = func.create_block(start = FUNC_START, label = 'entry')
        loop = func.create_block(start = FUNC_START + 4, label = 'loop')

        entry.add_instruction(MLILCall('Setup', []))
        entry.add_instruction(MLILGoto(loop))
        entry.add_outgoing_edge(loop)

        loop.add_instruction(MLILCall('Body', []))
        loop.add_instruction(MLILGoto(loop))
        loop.add_outgoing_edge(loop)

        BlockMergePass().run(func)

        # loop has two predecessors (entry and itself) and its own goto targets itself -
        # neither condition may ever trigger a merge
        self.assertEqual(func.basic_blocks, [entry, loop])
        self.assertIs(loop.instructions[-1].target, loop)


class TestEntryGuard(unittest.TestCase):
    '''The entry block must never be absorbed as someone else's merge target.'''

    def test_goto_into_entry_does_not_absorb_it(self):
        func = MediumLevelILFunction('loop_into_entry')
        entry = func.create_block(start = FUNC_START, label = 'entry')
        tail = func.create_block(start = FUNC_START + 4, label = 'tail')

        entry.add_instruction(MLILRet(None))

        tail.add_instruction(MLILCall('Body', []))
        tail.add_instruction(MLILGoto(entry))
        tail.add_outgoing_edge(entry)

        BlockMergePass().run(func)

        # by predecessor count alone (entry has exactly one: tail) this looks mergeable -
        # the entry exemption must block it anyway
        self.assertEqual(func.basic_blocks, [entry, tail])
        self.assertIs(func.basic_blocks[0], entry)


class TestDiamondJoinPoint(unittest.TestCase):
    '''A block reachable from two arms of a branch must never be merged into either arm.'''

    def test_join_block_with_two_predecessors_is_not_merged(self):
        func = MediumLevelILFunction('diamond')
        entry = func.create_block(start = FUNC_START, label = 'entry')
        true_arm = func.create_block(start = FUNC_START + 4, label = 'true_arm')
        false_arm = func.create_block(start = FUNC_START + 8, label = 'false_arm')
        join = func.create_block(start = FUNC_START + 12, label = 'join')

        entry.add_instruction(MLILIf(MLILConst(1), true_arm, false_arm))
        entry.add_outgoing_edge(true_arm)
        entry.add_outgoing_edge(false_arm)

        true_arm.add_instruction(MLILCall('T', []))
        true_arm.add_instruction(MLILGoto(join))
        true_arm.add_outgoing_edge(join)

        false_arm.add_instruction(MLILCall('F', []))
        false_arm.add_instruction(MLILGoto(join))
        false_arm.add_outgoing_edge(join)

        join.add_instruction(MLILRet(None))

        BlockMergePass().run(func)

        self.assertEqual(func.basic_blocks, [entry, true_arm, false_arm, join])
        self.assertIs(true_arm.instructions[-1].target, join)
        self.assertIs(false_arm.instructions[-1].target, join)


class TestBackEdgeIntoHead(unittest.TestCase):
    '''Absorbing a block whose own branch loops back to the (merged) head must repoint the
    head's own incoming edge to itself, not leave it pointing at the removed block.'''

    def test_loop_header_absorbing_its_own_back_edge_source(self):
        func = MediumLevelILFunction('back_edge')
        head = func.create_block(start = FUNC_START, label = 'head')
        body = func.create_block(start = FUNC_START + 4, label = 'body')
        exit_block = func.create_block(start = FUNC_START + 8, label = 'exit')

        head.add_instruction(MLILCall('Setup', []))
        head.add_instruction(MLILGoto(body))
        head.add_outgoing_edge(body)

        body.add_instruction(MLILIf(MLILConst(1), head, exit_block))
        body.add_outgoing_edge(head)
        body.add_outgoing_edge(exit_block)

        exit_block.add_instruction(MLILRet(None))

        BlockMergePass().run(func)

        self.assertEqual(func.basic_blocks, [head, exit_block])
        self.assertIs(head.instructions[-1].true_target, head)
        self.assertIs(head.instructions[-1].false_target, exit_block)
        self.assertEqual(head.incoming_edges, [head])
        self.assertEqual(exit_block.incoming_edges, [head])


class TestBackwardListPosition(unittest.TestCase):
    '''Merging must not depend on list order - a target sitting earlier in basic_blocks than
    the head that absorbs it must still merge correctly.'''

    def test_target_appearing_earlier_in_block_list_still_merges(self):
        func = MediumLevelILFunction('backward')
        entry = func.create_block(start = FUNC_START, label = 'entry')
        target = func.create_block(start = FUNC_START + 4, label = 'target')
        head = func.create_block(start = FUNC_START + 8, label = 'head')
        other_arm = func.create_block(start = FUNC_START + 12, label = 'other_arm')

        entry.add_instruction(MLILIf(MLILConst(1), head, other_arm))
        entry.add_outgoing_edge(head)
        entry.add_outgoing_edge(other_arm)

        head.add_instruction(MLILCall('Head', []))
        head.add_instruction(MLILGoto(target))
        head.add_outgoing_edge(target)

        target.add_instruction(MLILRet(None))
        other_arm.add_instruction(MLILRet(None))

        BlockMergePass().run(func)

        self.assertNotIn(target, func.basic_blocks)
        self.assertIn(head, func.basic_blocks)
        self.assertEqual(len(head.instructions), 2)
        self.assertIsInstance(head.instructions[-1], MLILRet)


class TestInstBlockMapRebuild(unittest.TestCase):
    '''_inst_block_map must track every surviving instruction into its new block, and drop the
    dropped goto's entry, once renumber_blocks() runs.'''

    def test_map_points_absorbed_instructions_at_the_surviving_block(self):
        func = MediumLevelILFunction('map_test')
        head = func.create_block(start = FUNC_START, label = 'head')
        target = func.create_block(start = FUNC_START + 4, label = 'target')

        call_inst = MLILCall('Foo', [])
        call_inst.inst_index = 10
        goto_inst = MLILGoto(target)
        goto_inst.inst_index = 11
        ret_inst = MLILRet(None)
        ret_inst.inst_index = 12

        head.add_instruction(call_inst)
        head.add_instruction(goto_inst)
        func.register_instruction(head, call_inst)
        func.register_instruction(head, goto_inst)

        target.add_instruction(ret_inst)
        func.register_instruction(target, ret_inst)

        head.add_outgoing_edge(target)

        BlockMergePass().run(func)

        self.assertEqual(func.basic_blocks, [head])
        self.assertIs(func.get_block_for_instruction(10), head)
        self.assertIs(func.get_block_for_instruction(12), head)
        self.assertIsNone(func.get_block_for_instruction(11))  # the dropped goto


class TestIdempotence(unittest.TestCase):
    '''Running the pass again once nothing is left to merge must be a true no-op.'''

    def test_second_run_is_a_no_op(self):
        func = MediumLevelILFunction('idempotent')
        head = func.create_block(start = FUNC_START, label = 'head')
        tail = func.create_block(start = FUNC_START + 4, label = 'tail')

        head.add_instruction(MLILCall('Foo', []))
        head.add_instruction(MLILGoto(tail))
        head.add_outgoing_edge(tail)
        tail.add_instruction(MLILRet(None))

        BlockMergePass().run(func)
        blocks_after_first = list(func.basic_blocks)
        instructions_after_first = list(head.instructions)

        BlockMergePass().run(func)

        self.assertEqual(func.basic_blocks, blocks_after_first)
        self.assertEqual(head.instructions, instructions_after_first)


class TestUnreachableCycleTermination(unittest.TestCase):
    '''A 2-block cycle with no other predecessors must terminate as a self-loop, not hang.'''

    def test_two_block_cycle_terminates_as_a_self_loop(self):
        func = MediumLevelILFunction('cycle')
        entry = func.create_block(start = FUNC_START, label = 'entry')
        x = func.create_block(start = FUNC_START + 4, label = 'x')
        y = func.create_block(start = FUNC_START + 8, label = 'y')

        entry.add_instruction(MLILRet(None))

        x.add_instruction(MLILGoto(y))
        x.add_outgoing_edge(y)
        y.add_instruction(MLILGoto(x))
        y.add_outgoing_edge(x)

        BlockMergePass().run(func)  # must terminate rather than loop forever

        survivors = [b for b in func.basic_blocks if b is not entry]
        self.assertEqual(len(survivors), 1)
        self.assertIs(survivors[0].instructions[-1].target, survivors[0])


class TestPhiGuard(unittest.TestCase):
    '''This pass only supports pre-SSA MLIL - a Phi node must make it fail loud, not silently
    drop a predecessor's copy.'''

    def test_phi_node_present_raises(self):
        func = MediumLevelILFunction('phi_guard')
        block = func.create_block(start = FUNC_START, label = 'entry')
        var = func.get_or_create_local('var_s0')

        block.add_instruction(MLILPhi(MLILVariableSSA(var, 1), []))
        block.add_instruction(MLILRet(None))

        with self.assertRaises(RuntimeError):
            BlockMergePass().run(func)


class TestInconsistentEdgeInvariant(unittest.TestCase):
    '''A corrupted edge list is a real upstream bug - the pass must fail loud, never merge on
    top of it.'''

    def test_target_with_wrong_recorded_predecessor_raises(self):
        func = MediumLevelILFunction('bad_edges')
        head = func.create_block(start = FUNC_START, label = 'head')
        other = func.create_block(start = FUNC_START + 4, label = 'other')
        target = func.create_block(start = FUNC_START + 8, label = 'target')

        head.add_instruction(MLILGoto(target))
        head.add_outgoing_edge(target)

        # Corrupt it afterward: target's sole recorded predecessor claims to be `other`
        target.incoming_edges = [other]
        target.add_instruction(MLILRet(None))

        with self.assertRaises(RuntimeError):
            BlockMergePass().run(func)


if __name__ == '__main__':
    unittest.main()
