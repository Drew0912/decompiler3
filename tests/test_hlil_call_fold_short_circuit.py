#!/usr/bin/env python3
'''Unit tests for CallResultFolder short-circuit safety (LLIL/MLIL hardening plan Step 8):
CallResultFolder decides every fold before the &&/|| chains that can gate it exist, so a call
that ran unconditionally in straight-line MLIL can end up as a non-first &&/|| operand in the
final HLIL - turning an always-runs call into a conditionally-runs one, which this VM's strict
evaluation never does. MLILToHLILConverter._unfold_unsafe_folds undoes exactly that case, and
only that case - an already-conditional call landing in the same shape must stay folded.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILCall,
    MLILIf, MLILGoto, MLILRet, MLILConst, MLILLogicalAnd, MLILVar,
)
from ir.hlil.mlil_to_hlil import MLILToHLILConverter


def make_func(name: str) -> MediumLevelILFunction:
    func = MediumLevelILFunction(name, 0)
    for n in ('arg1', 'cond', 'reg0'):
        func.locals[n] = MLILVariable(n)
    return func


class TestNestedUnsafeFoldInsideAnotherFoldsOwnArgument(unittest.TestCase):
    '''One gated, unconditional-pre-fold call can sit inside ANOTHER gated, unconditional-pre-fold
    call's own argument list: inner() folds into outer()'s args (outer(b && inner())), and outer()
    itself folds into the outer if (if (a && outer(...))). Found by Codex (Rule 0 correctness
    review, 2026-09-22): _extract_targets originally treated a matched call as a leaf, so hoisting
    outer() to its own statement carried inner() along unchanged, still gated by its own local
    `b &&` even after outer() itself became unconditional. Both calls must end up as their own
    unconditional statements, in the order they actually ran.'''

    def test_both_calls_are_unfolded_in_evaluation_order(self):
        func = make_func('nested_unsafe_fold')
        a = func.locals['arg1']
        b = MLILVariable('b')
        func.locals['b'] = b
        reg0 = func.locals['reg0']
        reg1 = MLILVariable('reg1')
        func.locals['reg1'] = reg1

        block0 = MediumLevelILBasicBlock(0)
        block1 = MediumLevelILBasicBlock(1)
        block2 = MediumLevelILBasicBlock(2)
        block3 = MediumLevelILBasicBlock(3)
        block4 = MediumLevelILBasicBlock(4)

        block0.instructions = [
            MLILCall('inner', [], reg0),      # unconditional - function entry
            MLILGoto(block1),
        ]
        block1.instructions = [
            # outer()'s own argument reads reg0 - inner()'s result folds in here
            MLILCall('outer', [MLILLogicalAnd(MLILVar(b), MLILVar(reg0))], reg1),
            MLILGoto(block2),
        ]
        block2.instructions = [
            MLILIf(MLILLogicalAnd(MLILVar(a), MLILVar(reg1)), block3, block4),
        ]
        block3.instructions = [MLILRet(MLILConst(1))]
        block4.instructions = [MLILRet(MLILConst(0))]

        func.basic_blocks = [block0, block1, block2, block3, block4]

        hlil_func = MLILToHLILConverter(func).convert()
        rendered = [str(s) for s in hlil_func.body.statements]

        self.assertEqual(rendered[0], 'reg0 = inner()',
                         f'inner() must run first, as its own statement: {rendered}')
        self.assertEqual(rendered[1], 'reg1 = outer(b && reg0)',
                         f'outer() must read the captured reg0, not re-inline inner(): {rendered}')
        self.assertEqual(str(hlil_func.body.statements[2].condition), 'arg1 && reg1',
                         f'the if must read the captured reg1: {rendered}')


class TestUnconditionalCallGatedByNativeAnd(unittest.TestCase):
    '''reg0 = f() runs unconditionally (function entry, straight-line, no branch) and folds
    into becoming the RHS of `arg1 && reg0` - short-circuit-gated where the VM never gated it.
    Must come back out as its own statement.'''

    def test_call_is_unfolded_back_to_its_own_statement(self):
        func = make_func('unconditional_gated')
        arg1 = func.locals['arg1']
        reg0 = func.locals['reg0']

        block0 = MediumLevelILBasicBlock(0)
        block1 = MediumLevelILBasicBlock(1)
        block2 = MediumLevelILBasicBlock(2)
        block3 = MediumLevelILBasicBlock(3)

        block0.instructions = [
            MLILCall('f', [], reg0),          # unconditional - block0 is the entry block
            MLILGoto(block1),
        ]
        block1.instructions = [
            MLILIf(MLILLogicalAnd(MLILVar(arg1), MLILVar(reg0)), block2, block3),
        ]
        block2.instructions = [MLILRet(MLILConst(1))]
        block3.instructions = [MLILRet(MLILConst(0))]

        func.basic_blocks = [block0, block1, block2, block3]

        hlil_func = MLILToHLILConverter(func).convert()
        rendered = str(hlil_func.body.statements)

        first_stmt = hlil_func.body.statements[0]
        self.assertEqual(str(first_stmt), 'reg0 = f()',
                         f'the call must run as its own unconditional statement first, got: {rendered}')

        if_stmt = hlil_func.body.statements[1]
        self.assertEqual(str(if_stmt.condition), 'arg1 && reg0',
                         f'the condition must read the captured variable, not re-inline the call: {rendered}')


class TestAlreadyConditionalCallStaysFolded(unittest.TestCase):
    '''reg0 = f() only runs when block0's own branch takes the block1 arm - already conditional
    before any fold happened. Landing gated (RHS of &&) changes nothing observable, so this must
    stay folded/inlined exactly as CallResultFolder originally decided.'''

    def test_call_stays_inlined(self):
        func = make_func('already_conditional')
        arg1 = func.locals['arg1']
        cond = func.locals['cond']
        reg0 = func.locals['reg0']

        block0 = MediumLevelILBasicBlock(0)
        block1 = MediumLevelILBasicBlock(1)
        block2 = MediumLevelILBasicBlock(2)
        block3 = MediumLevelILBasicBlock(3)
        block4 = MediumLevelILBasicBlock(4)
        block5 = MediumLevelILBasicBlock(5)

        block0.instructions = [MLILIf(MLILVar(cond), block1, block3)]
        block1.instructions = [
            MLILCall('f', [], reg0),          # only reached when block0 took the block1 arm
            MLILGoto(block2),
        ]
        block2.instructions = [
            MLILIf(MLILLogicalAnd(MLILVar(arg1), MLILVar(reg0)), block4, block5),
        ]
        block3.instructions = [MLILRet(MLILConst(0))]
        block4.instructions = [MLILRet(MLILConst(1))]
        block5.instructions = [MLILRet(MLILConst(0))]

        func.basic_blocks = [block0, block1, block2, block3, block4, block5]

        hlil_func = MLILToHLILConverter(func).convert()

        # Only one real path (block0's if) should carry the call - it must not have been
        # promoted to its own top-level statement ahead of everything else.
        top_level = [str(s) for s in hlil_func.body.statements]
        self.assertFalse(any(s == 'reg0 = f()' for s in top_level),
                         f'an already-conditional call must not be unfolded to the top level: {top_level}')


if __name__ == '__main__':
    unittest.main()
