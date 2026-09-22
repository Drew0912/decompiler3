#!/usr/bin/env python3
'''Unit tests for SCCP constant folding - DIV/MOD must never fold. Python's // and % don't match
the VM's actual number format (ScpValue: 30-bit int / float32), and the real semantics can't be
verified without running the game (docs/FUTURE_WORK.md), so folding them risked silently
replacing one wrong constant with another. Confirmed live: mp0000_ev.MayaEvented_22_test folded
400 / 30.0 to 13.0 (Python floor-division) instead of leaving it unfolded.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst,
    MLILDiv, MLILMod, MLILAdd,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILIf, MLILRet
from ir.mlil.passes.pass_ssa_sccp import SCCP


def make_func(name: str) -> MediumLevelILFunction:
    return MediumLevelILFunction(name, 0)


def run_sccp_and_get_use(op) -> object:
    '''x = <op>; return x - runs SCCP, returns whatever the return value became (MLILVarSSA(x)
    if x's def was not folded to a constant, MLILConst if it was).'''
    func = make_func('sccp_fold_test')
    x = MLILVariable('x')
    func.locals['x'] = x
    x1 = MLILVariableSSA(x, 1)

    block = MediumLevelILBasicBlock(0)
    block.instructions = [
        MLILSetVarSSA(x1, op),
        MLILRet(MLILVarSSA(x1)),
    ]
    func.basic_blocks = [block]

    SCCP(func).run()

    return block.instructions[-1].value


class TestDivModNeverFold(unittest.TestCase):
    '''The actual scoped fix: DIV/MOD always evaluate to bottom, never a folded constant -
    regardless of operand values, even ones that would be exact under any reasonable semantics.'''

    def test_int_div_does_not_fold(self):
        result = run_sccp_and_get_use(MLILDiv(MLILConst(10), MLILConst(2)))
        self.assertIsInstance(result, MLILVarSSA, 'DIV must not fold, even 10 / 2')

    def test_float_div_does_not_fold(self):
        result = run_sccp_and_get_use(MLILDiv(MLILConst(400), MLILConst(30.0)))
        self.assertIsInstance(result, MLILVarSSA, 'the real corpus bug site: 400 / 30.0 must not fold')

    def test_mod_does_not_fold(self):
        result = run_sccp_and_get_use(MLILMod(MLILConst(10), MLILConst(3)))
        self.assertIsInstance(result, MLILVarSSA, 'MOD must not fold')

    def test_div_by_zero_does_not_fold_and_does_not_raise(self):
        result = run_sccp_and_get_use(MLILDiv(MLILConst(5), MLILConst(0)))
        self.assertIsInstance(result, MLILVarSSA)

    def test_div_derived_branch_condition_does_not_remove_either_successor(self):
        '''A different SCCP consumer than constant substitution: with remove_unreachable=True,
        a branch on a DIV-derived (bottom) value must not be treated as determined - both
        successors have to survive, the same as any other genuinely-unknown condition.'''
        func = make_func('branch_test')
        x = MLILVariable('x')
        func.locals['x'] = x
        x1 = MLILVariableSSA(x, 1)

        entry = MediumLevelILBasicBlock(0)
        true_block = MediumLevelILBasicBlock(1)
        false_block = MediumLevelILBasicBlock(2)
        entry.instructions = [
            MLILSetVarSSA(x1, MLILDiv(MLILConst(10), MLILConst(3))),
            MLILIf(MLILVarSSA(x1), true_block, false_block),
        ]
        true_block.instructions = [MLILRet()]
        false_block.instructions = [MLILRet()]
        entry.add_outgoing_edge(true_block)
        entry.add_outgoing_edge(false_block)
        func.basic_blocks = [entry, true_block, false_block]

        SCCP(func, remove_unreachable = True).run()

        self.assertIn(true_block, func.basic_blocks)
        self.assertIn(false_block, func.basic_blocks)


class TestOtherArithmeticStillFolds(unittest.TestCase):
    '''Representative regression guard: only DIV/MOD were disabled - this op (untouched by the
    diff) still folds, standing in for the rest (SUB/MUL/bitwise/comparisons/etc.), none of
    which this change's code path touches.'''

    def test_add_still_folds(self):
        result = run_sccp_and_get_use(MLILAdd(MLILConst(2), MLILConst(3)))
        self.assertIsInstance(result, MLILConst)
        self.assertEqual(result.value, 5)


if __name__ == '__main__':
    unittest.main()
