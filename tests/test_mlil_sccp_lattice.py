#!/usr/bin/env python3
'''Unit tests for SCCP constant equality in lattice values and phi merges: int and float constants stay
distinct at equal numeric value, and NaN equals itself (constant_values_equal).'''

import math
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILGoto,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILIf, MLILRet, MLILPhi
from ir.mlil.passes.pass_ssa_sccp import SCCP, LatticeValue


INT_VALUE = 1
FLOAT_VALUE = 1.0
NAN_VALUE = float('nan')


def run_sccp_on_phi(true_value, false_value) -> object:
    '''Run SCCP on a phi with two reachable constant inputs and return its use: MLILConst if the phi
    folded, MLILVarSSA if it did not.'''
    func = MediumLevelILFunction('sccp_phi_test', 0)
    p = MLILVariable('p')
    x = MLILVariable('x')
    func.locals['x'] = x
    p0 = MLILVariableSSA(p, 0)
    x1 = MLILVariableSSA(x, 1)
    x2 = MLILVariableSSA(x, 2)
    x3 = MLILVariableSSA(x, 3)

    entry = MediumLevelILBasicBlock(0)
    true_block = MediumLevelILBasicBlock(1)
    false_block = MediumLevelILBasicBlock(2)
    join = MediumLevelILBasicBlock(3)
    entry.instructions = [MLILIf(MLILVarSSA(p0), true_block, false_block)]
    true_block.instructions = [MLILSetVarSSA(x1, MLILConst(true_value)), MLILGoto(join)]
    false_block.instructions = [MLILSetVarSSA(x2, MLILConst(false_value)), MLILGoto(join)]
    join.instructions = [
        MLILPhi(x3, [(x1, true_block), (x2, false_block)]),
        MLILRet(MLILVarSSA(x3)),
    ]
    entry.add_outgoing_edge(true_block)
    entry.add_outgoing_edge(false_block)
    true_block.add_outgoing_edge(join)
    false_block.add_outgoing_edge(join)
    func.basic_blocks = [entry, true_block, false_block, join]

    SCCP(func).run()

    return join.instructions[-1].value


class TestLatticeConstantEquality(unittest.TestCase):
    def test_int_and_float_constants_are_distinct(self):
        self.assertNotEqual(LatticeValue.constant(INT_VALUE), LatticeValue.constant(FLOAT_VALUE))

    def test_nan_constant_equals_itself(self):
        '''`!=` is what SCCP uses to decide whether a re-visit changed a value.'''
        self.assertFalse(LatticeValue.constant(NAN_VALUE) != LatticeValue.constant(float('nan')))


class TestPhiMerge(unittest.TestCase):
    def test_int_and_float_arms_do_not_fold(self):
        for arms in ((INT_VALUE, FLOAT_VALUE), (FLOAT_VALUE, INT_VALUE)):
            with self.subTest(arms = arms):
                self.assertIsInstance(run_sccp_on_phi(*arms), MLILVarSSA)

    def test_nan_arms_fold(self):
        result = run_sccp_on_phi(NAN_VALUE, float('nan'))
        self.assertIsInstance(result, MLILConst)
        self.assertTrue(math.isnan(result.value))

    def test_equal_arms_still_fold(self):
        for value in (INT_VALUE, FLOAT_VALUE):
            with self.subTest(value = value):
                result = run_sccp_on_phi(value, value)
                self.assertIsInstance(result, MLILConst)
                self.assertIs(type(result.value), type(value))
                self.assertEqual(result.value, value)


if __name__ == '__main__':
    unittest.main()
