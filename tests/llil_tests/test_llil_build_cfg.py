#!/usr/bin/env python3
'''Unit tests for LLIL CFG construction: the edges build_cfg() gives each terminal, a function's block labels
are unique (a script function may be named like another block's loc_ label), and the function's lookups.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import (
    LowLevelILBasicBlock, LowLevelILCall, LowLevelILConst, LowLevelILEq, LowLevelILFunction, LowLevelILIf,
    LowLevelILRet,
)
from tests.shared.llil_utils import BLOCK_STRIDE, FUNC_START, SECOND_BLOCK_START, make_builder


FUNCTION_NAME = 'build_cfg_test'
CONDITION_VALUE = 0
PUSHED_VALUE = 7


def make_function(*labels: str):
    '''A function with one registered, empty block per label, in order from FUNC_START'''
    function = LowLevelILFunction(FUNCTION_NAME, FUNC_START)
    blocks = []
    for position, label in enumerate(labels):
        block = LowLevelILBasicBlock(FUNC_START + position * BLOCK_STRIDE, label = label)
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


class TestBlockLabels(unittest.TestCase):
    '''Block labels are unique within a function: the entry block takes the function's name, so a script function
    named loc_1A0 meets the block at 0x1A0.'''

    def test_duplicate_label_cannot_be_added(self):
        function, _ = make_function('entry')

        with self.assertRaisesRegex(RuntimeError, 'already labelled'):
            function.add_basic_block(LowLevelILBasicBlock(SECOND_BLOCK_START, label = 'entry'))


class TestFunctionLookups(unittest.TestCase):
    '''The function's lookups by instruction index, block address and label, and its block ownership test'''

    def make_function(self):
        builder = make_builder()
        entry = builder.current_block
        builder.push_int(PUSHED_VALUE)
        builder.pop_n(1)
        builder.ret()
        return builder, entry, builder.finalize()

    def test_instruction_lookup_stops_at_the_ends(self):
        _, entry, func = self.make_function()
        count = len(entry.instructions)

        self.assertIs(func.get_instruction_by_index(0), entry.instructions[0])
        self.assertIs(func.get_instruction_by_index(count - 1), entry.instructions[-1])
        self.assertIsNone(func.get_instruction_by_index(-1))
        self.assertIsNone(func.get_instruction_by_index(count))
        self.assertIs(func.get_instruction_block_by_index(0), entry)

    def test_block_lookups(self):
        builder, entry, func = self.make_function()

        self.assertIs(builder.get_block_by_addr(entry.start), entry)
        self.assertIs(builder.get_block_by_label(entry.label), entry)
        self.assertIsNone(builder.get_block_by_addr(entry.start + 1))
        self.assertIsNone(builder.get_block_by_label('missing'))

    def test_a_function_owns_only_its_own_blocks(self):
        _, entry, func = self.make_function()
        _, other_entry, _ = self.make_function()

        self.assertTrue(func.owns_block(entry))
        self.assertFalse(func.owns_block(other_entry))
        self.assertFalse(func.owns_block('block_0'))


if __name__ == '__main__':
    unittest.main()
