#!/usr/bin/env python3
'''Unit tests for LLIL CFG construction: build_cfg() recomputes every edge from the current terminals and keeps the
previous graph when a rebuild fails; a block belongs to one function, and every edge and every builder entry point
accepts only the function's own blocks.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.core import Terminal
from ir.llil.llil import (
    LowLevelILBasicBlock, LowLevelILCall, LowLevelILConst, LowLevelILEq, LowLevelILFunction, LowLevelILIf,
    LowLevelILJmp, LowLevelILOperation, LowLevelILRet, LowLevelILStatement,
)
from ir.llil.llil_builder import LowLevelILBuilder
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.llil.llil_ext import LowLevelILCallScript


FUNC_START = 0x1000
BLOCK_SPACING = 0x10
FOREIGN_BLOCK_START = 0x9999
CONDITION_VALUE = 0
MODULE_NAME = 'module'


class UnsupportedTerminal(LowLevelILStatement, Terminal):
    '''A terminal kind build_cfg has no edge rule for'''

    def __init__(self):
        super().__init__(LowLevelILOperation.LLIL_RET)

    def __str__(self) -> str:
        return 'unsupported'


def make_function(*labels: str, name: str = 'build_cfg_test'):
    '''A function with one registered, empty block per label, in order from FUNC_START'''
    function = LowLevelILFunction(name, FUNC_START)
    blocks = []
    for position, label in enumerate(labels):
        block = LowLevelILBasicBlock(FUNC_START + position * BLOCK_SPACING, label = label)
        function.add_basic_block(block)
        blocks.append(block)

    return function, blocks


def condition() -> LowLevelILEq:
    return LowLevelILEq(LowLevelILConst(CONDITION_VALUE), LowLevelILConst(CONDITION_VALUE))


def edges(function: LowLevelILFunction) -> list:
    '''Every block's outgoing and incoming edges, by label'''
    return [
        ([target.label for target in block.outgoing_edges], [source.label for source in block.incoming_edges])
        for block in function.basic_blocks
    ]


class TestBuildCfgRebuild(unittest.TestCase):
    '''A rebuild replaces every stale edge; a failed rebuild keeps the previous graph.'''

    def test_rebuild_after_goto_retarget_drops_the_old_edge(self):
        function, (entry, old_target, new_target) = make_function('entry', 'old_target', 'new_target')
        jmp = LowLevelILJmp(old_target)
        entry.add_instruction(jmp)
        old_target.add_instruction(LowLevelILRet())
        new_target.add_instruction(LowLevelILRet())
        function.build_cfg()

        jmp.target = new_target
        function.build_cfg()

        self.assertEqual(entry.outgoing_edges, [new_target])
        self.assertEqual(old_target.incoming_edges, [])
        self.assertEqual(new_target.incoming_edges, [entry])

    def test_rebuild_after_if_arm_retarget_drops_the_old_edge(self):
        function, blocks = make_function('entry', 'true_target', 'old_false', 'new_false')
        entry, true_target, old_false, new_false = blocks
        branch = LowLevelILIf(condition(), true_target, old_false)
        entry.add_instruction(branch)
        for block in (true_target, old_false, new_false):
            block.add_instruction(LowLevelILRet())
        function.build_cfg()

        branch.false_target = new_false
        function.build_cfg()

        self.assertEqual(entry.outgoing_edges, [true_target, new_false])
        self.assertEqual(old_false.incoming_edges, [])

    def test_rebuild_after_call_return_retarget_drops_the_old_edge(self):
        calls = {
            'call': lambda target: LowLevelILCall('f', target),
            'call_script': lambda target: LowLevelILCallScript(MODULE_NAME, 'f', None, [], target),
        }
        for name, make_call in calls.items():
            with self.subTest(name):
                function, (entry, old_return, new_return) = make_function('entry', 'old_return', 'new_return')
                call = make_call(old_return)
                entry.add_instruction(call)
                old_return.add_instruction(LowLevelILRet())
                new_return.add_instruction(LowLevelILRet())
                function.build_cfg()

                call.return_target = new_return
                function.build_cfg()

                self.assertEqual(entry.outgoing_edges, [new_return])
                self.assertEqual(old_return.incoming_edges, [])

    def test_rebuild_after_terminal_becomes_a_return_drops_every_edge(self):
        function, (entry, target) = make_function('entry', 'target')
        entry.add_instruction(LowLevelILJmp(target))
        target.add_instruction(LowLevelILRet())
        function.build_cfg()

        entry.instructions.pop()
        entry.add_instruction(LowLevelILRet())
        function.build_cfg()

        self.assertEqual(edges(function), [([], []), ([], [])])

    def test_empty_block_no_longer_targeted_is_not_reported(self):
        function, (entry, empty, target) = make_function('entry', 'empty', 'target')
        jmp = LowLevelILJmp(empty)
        entry.add_instruction(jmp)
        target.add_instruction(LowLevelILRet())
        with self.assertRaisesRegex(RuntimeError, 'CFG edge target but has no instructions'):
            function.build_cfg()

        jmp.target = target
        function.build_cfg()   # must not raise

        self.assertEqual(empty.incoming_edges, [])

    def test_failed_rebuild_keeps_the_previous_graph(self):
        # Fails once while collecting edges (foreign target), once after (empty target)
        for failure, message in (('foreign', 'not a block of'), ('empty', 'has no instructions')):
            with self.subTest(failure):
                function, (entry, target, empty) = make_function('entry', 'target', 'empty')
                jmp = LowLevelILJmp(target)
                entry.add_instruction(jmp)
                target.add_instruction(LowLevelILRet())
                function.build_cfg()
                before = edges(function)

                jmp.target = LowLevelILBasicBlock(FOREIGN_BLOCK_START) if failure == 'foreign' else empty
                with self.assertRaisesRegex(RuntimeError, message):
                    function.build_cfg()

                self.assertEqual(edges(function), before)


class TestBuildCfgEdges(unittest.TestCase):
    '''Which terminals give which edges.'''

    def test_if_with_both_arms_on_one_block_gives_one_edge(self):
        function, (entry, target) = make_function('entry', 'target')
        entry.add_instruction(LowLevelILIf(condition(), target, target))
        target.add_instruction(LowLevelILRet())

        function.build_cfg()

        self.assertEqual(edges(function), [(['target'], []), ([], ['entry'])])

    def test_return_and_tail_call_have_no_edges(self):
        function, (entry, tail) = make_function('entry', 'tail')
        entry.add_instruction(LowLevelILRet())
        tail.add_instruction(LowLevelILCall('f', None, returns = False))

        function.build_cfg()

        self.assertEqual(edges(function), [([], []), ([], [])])

    def test_tail_call_with_a_return_target_raises(self):
        function, (entry, target) = make_function('entry', 'target')
        entry.add_instruction(LowLevelILCall('f', target, returns = False))
        target.add_instruction(LowLevelILRet())

        with self.assertRaisesRegex(RuntimeError, 'never returns but has a return target'):
            function.build_cfg()

    def test_unsupported_terminal_raises(self):
        function, (entry,) = make_function('entry')
        entry.add_instruction(UnsupportedTerminal())

        with self.assertRaisesRegex(RuntimeError, 'supported terminal'):
            function.build_cfg()

    def test_function_without_a_block_at_its_start_raises(self):
        function = LowLevelILFunction('build_cfg_test', FUNC_START)
        block = LowLevelILBasicBlock(FUNC_START + BLOCK_SPACING)
        function.add_basic_block(block)
        block.add_instruction(LowLevelILRet())

        with self.assertRaisesRegex(RuntimeError, 'no block at its start address'):
            function.build_cfg()


class TestBlockMembership(unittest.TestCase):
    '''A block belongs to one function, and every edge ends at one of the function's own blocks.'''

    def test_target_with_a_hand_set_owner_raises(self):
        function, (entry,) = make_function('entry')
        outside = LowLevelILBasicBlock(FOREIGN_BLOCK_START)
        outside.function = function   # not registered - only add_basic_block does that
        entry.add_instruction(LowLevelILJmp(outside))

        with self.assertRaisesRegex(RuntimeError, 'not a block of'):
            function.build_cfg()

    def test_target_sharing_an_owned_blocks_start_raises(self):
        function, (entry, target) = make_function('entry', 'target')
        entry.add_instruction(LowLevelILJmp(LowLevelILBasicBlock(target.start, label = 'impostor')))
        target.add_instruction(LowLevelILRet())

        with self.assertRaisesRegex(RuntimeError, 'impostor, which is not a block of'):
            function.build_cfg()

    def test_call_returning_into_another_functions_block_raises(self):
        function, (entry,) = make_function('entry')
        _, (other_block,) = make_function('other_block', name = 'other')
        entry.add_instruction(LowLevelILCall('f', other_block))

        with self.assertRaisesRegex(RuntimeError, 'not a block of'):
            function.build_cfg()

    def test_label_target_raises(self):
        function, (entry, _) = make_function('entry', 'target')
        entry.add_instruction(LowLevelILJmp('target'))

        with self.assertRaisesRegex(TypeError, 'not a basic block'):
            function.build_cfg()

    def test_block_of_another_function_cannot_be_added(self):
        _, (block,) = make_function('entry')
        other = LowLevelILFunction('other', FUNC_START)

        with self.assertRaisesRegex(RuntimeError, 'already belongs'):
            other.add_basic_block(block)

    def test_duplicate_label_cannot_be_added(self):
        function, _ = make_function('entry')

        with self.assertRaisesRegex(RuntimeError, 'already labelled'):
            function.add_basic_block(LowLevelILBasicBlock(FUNC_START + BLOCK_SPACING, label = 'entry'))


class TestBuilderRejectsForeignBlocks(unittest.TestCase):
    '''The builder rejects a block outside the function before it records anything for it - even one that
    shares a real block's start, whose recorded stack state it would otherwise take over.'''

    def make_builder(self):
        builder = FalcomVMBuilder()
        builder.create_function('build_cfg_test', FUNC_START, num_params = 0)
        builder.set_current_block(builder.create_basic_block(FUNC_START, 'entry'))
        real = builder.create_basic_block(FUNC_START + BLOCK_SPACING, 'real')
        return builder, real, LowLevelILBasicBlock(real.start, label = 'foreign')

    def test_each_builder_entry_point_rejects_a_foreign_block(self):
        emitters = {
            'jmp': lambda builder, real, foreign: builder.jmp(foreign),
            'branch_if': lambda builder, real, foreign: builder.branch_if(condition(), real, foreign),
            'call': lambda builder, real, foreign: LowLevelILBuilder.call(builder, 'f', foreign),
            'push_ret_addr': lambda builder, real, foreign: (builder.push_func_id(), builder.push_ret_addr(foreign)),
            'push_caller_frame': lambda builder, real, foreign: builder.push_caller_frame(foreign),
        }
        for name, emit in emitters.items():
            with self.subTest(name):
                builder, real, foreign = self.make_builder()
                recorded = dict(builder.saved_stacks)

                with self.assertRaisesRegex(RuntimeError, 'not a block of'):
                    emit(builder, real, foreign)

                self.assertEqual(builder.saved_stacks, recorded)
                self.assertEqual(builder._recorded_edges, set())
                self.assertFalse(builder.current_block.has_terminal)

    def test_edge_record_for_a_directly_added_terminal_rejects_a_foreign_block(self):
        builder, _, foreign = self.make_builder()
        jmp_inst = LowLevelILJmp(foreign)
        builder.add_instruction(jmp_inst)
        recorded = dict(builder.saved_stacks)

        with self.assertRaisesRegex(RuntimeError, 'not a block of'):
            builder._record_edge_state(jmp_inst, foreign)

        self.assertEqual(builder.saved_stacks, recorded)
        self.assertEqual(builder._recorded_edges, set())


if __name__ == '__main__':
    unittest.main()
