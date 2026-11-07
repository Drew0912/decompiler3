#!/usr/bin/env python3
"""Unit tests for iter_ssa_reads(), what an SSA node reads, and the rule copy propagation keeps on top of the shared
traversal"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILBasicBlock, MediumLevelILFunction, MLILVariable, MLILAdd, MLILAddressOf, MLILRet, MLILCall,
)
from ir.mlil_ssa.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILPhi, iter_ssa_reads
from ir.mlil_ssa.passes.pass_ssa_copy_propagation import CopyPropagationPass


class TestIterSSAReads(unittest.TestCase):
    """iter_ssa_reads() gives (variable, reader) in evaluation order: the reader is the
    MLILVarSSA node itself (passes identity-search for it), or the phi for a phi source."""

    def setUp(self):
        self.x = MLILVariable('x')
        self.x1 = MLILVariableSSA(self.x, 1)
        self.x2 = MLILVariableSSA(self.x, 2)

    def test_reader_is_the_variable_node(self):
        first, second = MLILVarSSA(self.x1), MLILVarSSA(self.x2)
        ret = MLILRet(MLILAdd(first, second))

        self.assertEqual(list(iter_ssa_reads(ret)), [(self.x1, first), (self.x2, second)])

    def test_phi_sources_are_read_by_the_phi(self):
        block = MediumLevelILBasicBlock(0)
        phi = MLILPhi(MLILVariableSSA(self.x, 3), [(self.x1, block), (self.x2, block)])

        self.assertEqual(list(iter_ssa_reads(phi)), [(self.x1, phi), (self.x2, phi)])

    def test_skip_excludes_a_read_under_address_of(self):
        plain, taken = MLILVarSSA(self.x1), MLILVarSSA(self.x2)
        call = MLILCall('f', [plain, MLILAddressOf(taken)])

        self.assertEqual([var for var, _ in iter_ssa_reads(call)], [self.x1, self.x2])
        self.assertEqual([var for var, _ in iter_ssa_reads(call, skip=(MLILAddressOf,))], [self.x1])


class TestWalkerRulesKept(unittest.TestCase):
    """Rules individual passes keep on top of the shared traversal."""

    def test_copy_propagation_does_not_count_a_read_under_address_of(self):
        # it never rewrites the operand of &, so that read is not one of its uses
        x1 = MLILVariableSSA(MLILVariable('x'), 1)
        func = MediumLevelILFunction('f')
        func.create_block().add_instruction(MLILCall('f', [MLILVarSSA(x1), MLILAddressOf(MLILVarSSA(x1))]))
        copy_propagation = CopyPropagationPass()
        copy_propagation._count_uses(func)

        self.assertEqual(copy_propagation.use_counts, {x1: 1})


if __name__ == '__main__':
    unittest.main()
