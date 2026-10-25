#!/usr/bin/env python3
"""reverse_post_order (ir/core/il_cfg.py): the block order the LLIL lifter lifts in and MLIL's dominance analysis
walks"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from assembler.basic_block import BasicBlock
from ir.core import reverse_post_order
from tests.shared.llil_utils import FOURTH_BLOCK_START, FUNC_START, SECOND_BLOCK_START, THIRD_BLOCK_START


class TestReversePostOrder(unittest.TestCase):
    """reverse_post_order over the disassembler CFG (BasicBlock.succs), as the lifter calls it,
    independent of the LLIL builder entirely."""

    def test_diamond_places_join_after_both_arms(self):
        entry = BasicBlock(offset=FUNC_START)
        a = BasicBlock(offset=SECOND_BLOCK_START)
        b = BasicBlock(offset=THIRD_BLOCK_START)
        join = BasicBlock(offset=FOURTH_BLOCK_START)
        entry.add_branch(a)
        entry.add_branch(b)
        a.add_branch(join)
        b.add_branch(join)

        order = reverse_post_order(entry, lambda block: block.succs)

        self.assertEqual(order[0], entry)
        self.assertEqual(order[-1], join)
        self.assertLess(order.index(a), order.index(join))
        self.assertLess(order.index(b), order.index(join))

    def test_loop_back_edge_places_body_after_header_and_exit(self):
        """The exact shape that broke finalize()'s old blanket check: header.succs=[body, exit],
        body -> header. RPO must place header first; body (which can legitimately carry state
        across the back edge) ends up last, not exit (the real RETURN path)."""
        header = BasicBlock(offset=FUNC_START)
        body = BasicBlock(offset=SECOND_BLOCK_START)
        exit_block = BasicBlock(offset=THIRD_BLOCK_START)
        header.add_branch(body)
        header.add_branch(exit_block)
        body.add_branch(header)

        order = reverse_post_order(header, lambda block: block.succs)

        self.assertEqual(order, [header, exit_block, body])

    def test_rpo_is_not_secretly_address_order(self):
        """entry -> higher-address block -> lower-address block (the original counterexample
        shape). RPO must visit the lower-address block AFTER the higher-address one, proving it
        isn't just re-deriving address order."""
        entry = BasicBlock(offset=FUNC_START)
        higher = BasicBlock(offset=THIRD_BLOCK_START)
        lower = BasicBlock(offset=SECOND_BLOCK_START)
        entry.add_branch(higher)
        higher.add_branch(lower)

        order = reverse_post_order(entry, lambda block: block.succs)

        self.assertEqual(order, [entry, higher, lower])
        self.assertEqual(sorted(order, key=lambda b: b.offset), [entry, lower, higher])


if __name__ == '__main__':
    unittest.main()
