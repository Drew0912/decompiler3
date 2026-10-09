#!/usr/bin/env python3
'''Unit tests for LLIL CFG construction: the edges build_cfg() gives each terminal, and a function's block labels
are unique (a script function may be named like another block's loc_ label).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import (
    LowLevelILBasicBlock, LowLevelILCall, LowLevelILConst, LowLevelILEq, LowLevelILFunction, LowLevelILIf,
    LowLevelILRet,
)


FUNC_START = 0x1000
BLOCK_SPACING = 0x10
CONDITION_VALUE = 0


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
            function.add_basic_block(LowLevelILBasicBlock(FUNC_START + BLOCK_SPACING, label = 'entry'))


if __name__ == '__main__':
    unittest.main()
