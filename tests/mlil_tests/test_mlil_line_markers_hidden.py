#!/usr/bin/env python3
"""MediumLevelILFunction.line_markers_hidden: the line markers out of every block while the with-block runs, a nop in
a block of nothing but markers, and the blocks' own lists back afterwards, after an exception too"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import MediumLevelILFunction, MLILCall, MLILDebug, MLILNop, MLILRet

ENTRY_START = 0x10
MARKERS_START = 0x20
LINE = 100


def function_with_markers() -> tuple[MediumLevelILFunction, MLILCall]:
    """entry: a marker, a call, a debug value that is not a line marker; markers: two markers only; exit: a return"""
    func = MediumLevelILFunction('with_markers', ENTRY_START)
    entry = func.create_block(start=ENTRY_START)
    markers = func.create_block(start=MARKERS_START)
    exit_block = func.create_block()
    called = MLILCall('work', [])
    for instr in (MLILDebug('line', LINE), called, MLILDebug('string', 'kept')):
        entry.add_instruction(instr)

    markers.add_instruction(MLILDebug('line', LINE + 1, address=MARKERS_START))
    markers.add_instruction(MLILDebug('line', LINE + 2))
    exit_block.add_instruction(MLILRet(None))
    return func, called


class TestLineMarkersHidden(unittest.TestCase):
    def test_only_line_markers_are_hidden(self):
        func, called = function_with_markers()
        with func.line_markers_hidden():
            entry = func.basic_blocks[0].instructions
            self.assertIs(entry[0], called)
            self.assertEqual([instr.debug_type for instr in entry[1:]], ['string'])

    def test_a_block_of_markers_only_keeps_a_nop_at_their_address(self):
        func, _ = function_with_markers()
        with func.line_markers_hidden():
            [nop] = func.basic_blocks[1].instructions
            self.assertIsInstance(nop, MLILNop)
            self.assertEqual(nop.address, MARKERS_START)

    def test_the_blocks_get_their_own_lists_back_after_an_exception(self):
        func, _ = function_with_markers()
        before = [block.instructions for block in func.basic_blocks]
        with self.assertRaises(RuntimeError):
            with func.line_markers_hidden():
                raise RuntimeError('in the with-block')

        self.assertTrue(all(block.instructions is kept for block, kept in zip(func.basic_blocks, before)))


if __name__ == '__main__':
    unittest.main()
