#!/usr/bin/env python3
'''Unit tests for SCCP constant folding - DIV/MOD and ops with a float operand must never fold.
Python's arithmetic doesn't match the VM's actual number format (ScpValue: 30-bit int / float32),
and the real semantics can't be verified without running the game (docs/FUTURE_WORK.md), so
folding them risked silently replacing one wrong constant with another. Confirmed live:
mp0000_ev.MayaEvented_22_test folded 400 / 30.0 to 13.0 (Python floor-division) instead of
leaving it unfolded.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst,
    MLILDiv, MLILMod, MLILAdd, MLILMul, MLILLt, MLILNeg,
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


def both_arms_survive(condition, setup = ()) -> bool:
    '''setup; if (condition) return else return - whether SCCP with remove_unreachable keeps both arms'''
    func = make_func('branch_test')
    entry = MediumLevelILBasicBlock(0)
    true_block = MediumLevelILBasicBlock(1)
    false_block = MediumLevelILBasicBlock(2)
    entry.instructions = [*setup, MLILIf(condition, true_block, false_block)]
    true_block.instructions = [MLILRet()]
    false_block.instructions = [MLILRet()]
    entry.add_outgoing_edge(true_block)
    entry.add_outgoing_edge(false_block)
    func.basic_blocks = [entry, true_block, false_block]

    SCCP(func, remove_unreachable = True).run()

    return true_block in func.basic_blocks and false_block in func.basic_blocks


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
        x1 = MLILVariableSSA(MLILVariable('x'), 1)
        self.assertTrue(both_arms_survive(MLILVarSSA(x1), [MLILSetVarSSA(x1, MLILDiv(MLILConst(10), MLILConst(3)))]))


class TestFloatsNeverFold(unittest.TestCase):
    '''Any op with a float operand evaluates to bottom, and a float decides no branch: the VM's float arithmetic
    and truth (float32 rounding, int/float mixing, -0.0) are unverified. Seen live: chr0000.AniBtlCraft01Main
    printed 0.4 * 0.8 as 0.32.'''

    def test_float_ops_do_not_fold(self):
        for op in (MLILMul(MLILConst(0.4), MLILConst(0.8)), MLILAdd(MLILConst(2.0), MLILConst(10)),
                   MLILAdd(MLILConst(10), MLILConst(2.0)), MLILNeg(MLILConst(0.5))):
            with self.subTest(op = str(op)):
                self.assertIsInstance(run_sccp_and_get_use(op), MLILVarSSA)

    def test_float_does_not_decide_a_branch(self):
        x1 = MLILVariableSSA(MLILVariable('x'), 1)
        for condition, setup in ((MLILLt(MLILConst(0.5), MLILConst(1)), []), (MLILConst(0.5), []),
                                 (MLILVarSSA(x1), [MLILSetVarSSA(x1, MLILConst(0.0))])):
            with self.subTest(condition = str(condition)):
                self.assertTrue(both_arms_survive(condition, setup))


class TestIntOpsStillFold(unittest.TestCase):
    '''Representative regression guard: only DIV/MOD and float operands are disabled - int ops
    still fold and decide branches.'''

    def test_int_ops_still_fold(self):
        for op, value in ((MLILAdd(MLILConst(2), MLILConst(3)), 5), (MLILMul(MLILConst(90), MLILConst(2)), 180),
                          (MLILLt(MLILConst(3), MLILConst(5)), 1), (MLILNeg(MLILConst(7)), -7)):
            with self.subTest(op = str(op)):
                result = run_sccp_and_get_use(op)
                self.assertIsInstance(result, MLILConst)
                self.assertEqual(result.value, value)

    def test_int_condition_still_decides_a_branch(self):
        self.assertFalse(both_arms_survive(MLILLt(MLILConst(3), MLILConst(5))))


if __name__ == '__main__':
    unittest.main()
