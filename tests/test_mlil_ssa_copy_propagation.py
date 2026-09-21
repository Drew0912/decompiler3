#!/usr/bin/env python3
'''Unit tests for CopyPropagationPass and ExpressionInliningPass - Step 6 of the LLIL/MLIL
hardening plan: copy propagation and expression inlining must not forward a register/global
SSA value past a point where that same storage gets redefined.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst,
    MLILGt, MLILAdd, MLILCall, MLILSyscall, MLILDeref,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILIf, MLILRet, MLILUndef, SSADeconstructor
from ir.mlil.passes import CopyPropagationPass, ExpressionInliningPass


def make_func(name: str) -> MediumLevelILFunction:
    return MediumLevelILFunction(name, 0)


class TestCopyPropagationGlobalSaveRestore(unittest.TestCase):
    '''tmp = GLOBAL[n]; GLOBAL[n] = x; ...; GLOBAL[n] = tmp must keep the restore - forwarding
    GLOBAL[n]'s original value directly to the restore site would make de-SSA collapse it into
    a no-op, since a global's SSA version identity is erased once it lowers back to GLOBALS[n]
    (Fable's finding from Step 3's closure verification, confirmed by direct repro).'''

    def test_restore_survives_copy_propagation_and_deconstruction(self):
        func = make_func('save_restore')
        global5 = func.get_or_create_global_var(5)
        tmp = MLILVariable('tmp')
        func.locals['tmp'] = tmp

        g1 = MLILVariableSSA(global5, 1)
        g2 = MLILVariableSSA(global5, 2)
        g3 = MLILVariableSSA(global5, 3)
        tmp1 = MLILVariableSSA(tmp, 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(g1, MLILConst(99)),     # global5#1 = 99
            MLILSetVarSSA(tmp1, MLILVarSSA(g1)),  # tmp#1 = global5#1        (save)
            MLILSetVarSSA(g2, MLILConst(7)),      # global5#2 = 7            (overwrite)
            MLILSetVarSSA(g3, MLILVarSSA(tmp1)),  # global5#3 = tmp#1        (restore)
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)
        SSADeconstructor(func).deconstruct()

        lines = [str(inst) for inst in block.instructions]
        self.assertIn('GLOBAL[5] = tmp', lines)
        self.assertEqual(lines[-1], 'GLOBAL[5] = tmp', 'the restore must be the final statement, not deleted or reordered away')


class TestCopyPropagationSafeCases(unittest.TestCase):
    '''Regression guards: the redefinition check must not make propagation over-conservative
    for cases that were always safe.'''

    def test_simple_register_copy_with_no_redefinition_still_propagates(self):
        func = make_func('simple')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        a = MLILVariable('a')
        func.locals['a'] = a
        r = MLILVariable('r')
        func.locals['r'] = r

        reg0_1 = MLILVariableSSA(reg0, 1)
        a1 = MLILVariableSSA(a, 1)
        r1 = MLILVariableSSA(r, 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(reg0_1, MLILConst(42)),
            MLILSetVarSSA(a1, MLILVarSSA(reg0_1)),   # a#1 = reg0#1, used once
            MLILSetVarSSA(r1, MLILVarSSA(a1)),        # r#1 = a#1
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'r#1 = reg0#1')

    def test_multi_hop_chain_resolves_to_true_root(self):
        func = make_func('chain')
        for n in ('c', 'b', 'a', 'r'):
            func.locals[n] = MLILVariable(n)

        c1 = MLILVariableSSA(func.locals['c'], 1)
        b1 = MLILVariableSSA(func.locals['b'], 1)
        a1 = MLILVariableSSA(func.locals['a'], 1)
        r1 = MLILVariableSSA(func.locals['r'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(c1, MLILConst(7)),
            MLILSetVarSSA(b1, MLILVarSSA(c1)),
            MLILSetVarSSA(a1, MLILVarSSA(b1)),
            MLILSetVarSSA(r1, MLILVarSSA(a1)),
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'r#1 = c#1')

    def test_register_read_used_more_than_once_keeps_local_name(self):
        func = make_func('multiuse')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        for n in ('y', 'z1', 'z2'):
            func.locals[n] = MLILVariable(n)

        reg0_1 = MLILVariableSSA(reg0, 1)
        y1 = MLILVariableSSA(func.locals['y'], 1)
        z1 = MLILVariableSSA(func.locals['z1'], 1)
        z2 = MLILVariableSSA(func.locals['z2'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(reg0_1, MLILConst(5)),
            MLILSetVarSSA(y1, MLILVarSSA(reg0_1)),  # y#1 = reg0#1
            MLILSetVarSSA(z1, MLILVarSSA(y1)),       # read 1 of y#1
            MLILSetVarSSA(z2, MLILVarSSA(y1)),       # read 2 of y#1 -> used twice
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)

        self.assertEqual(str(block.instructions[2]), 'z1#1 = y#1')
        self.assertEqual(str(block.instructions[3]), 'z2#1 = y#1')


class TestCopyPropagationLocalRootStopsAtUnsafeLink(unittest.TestCase):
    '''t#1 = reg0#1; call (clobbers reg0); a#1 = t#1; use(a#1) must resolve to the LOCAL t#1,
    not keep walking to reg0#1 - the plan calls this out explicitly as the shape where a naive
    "always resolve to the ultimate root" implementation would reintroduce the bug.'''

    def test_chain_through_a_call_boundary_stops_at_the_local(self):
        func = make_func('chain_call_boundary')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        for n in ('t', 'a', 'u'):
            func.locals[n] = MLILVariable(n)

        reg0_1 = MLILVariableSSA(reg0, 1)
        reg0_2 = MLILVariableSSA(reg0, 2)
        t1 = MLILVariableSSA(func.locals['t'], 1)
        a1 = MLILVariableSSA(func.locals['a'], 1)
        u1 = MLILVariableSSA(func.locals['u'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(reg0_1, MLILConst(1)),
            MLILSetVarSSA(t1, MLILVarSSA(reg0_1)),  # t#1 = reg0#1
            MLILCall(0x1000, [], output = None),
            MLILSetVarSSA(reg0_2, MLILUndef()),      # reg0#2 = <undef>  (call's pseudo-def)
            MLILSetVarSSA(a1, MLILVarSSA(t1)),       # a#1 = t#1
            MLILSetVarSSA(u1, MLILVarSSA(a1)),       # use(a#1)
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)

        last = str(block.instructions[-1])
        self.assertEqual(last, 'u#1 = t#1', 'must stop at the local t#1, not resolve through it to reg0#1')


class TestExpressionInliningRegisterReadAcrossCall(unittest.TestCase):
    '''A register/global read wrapped in a compound expression must not inline across a call
    that clobbers that storage - _is_impure_read previously checked for MLILLoadReg/
    MLILLoadGlobal, node shapes that never occur in SSA-form expressions (a register/global
    read is MLILVarSSA at this layer), so the guard never fired at all.'''

    def test_register_comparison_not_inlined_across_intervening_call(self):
        func = make_func('inline_across_call')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        for n in ('x', 'r'):
            func.locals[n] = MLILVariable(n)

        reg0_1 = MLILVariableSSA(reg0, 1)
        reg0_2 = MLILVariableSSA(reg0, 2)
        x1 = MLILVariableSSA(func.locals['x'], 1)
        r1 = MLILVariableSSA(func.locals['r'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILGt(MLILVarSSA(reg0_1), MLILConst(0))),  # x#1 = reg0#1 > 0
            MLILCall(0x1234, [], output = None),
            MLILSetVarSSA(reg0_2, MLILUndef()),                            # call's pseudo-def
            MLILSetVarSSA(r1, MLILVarSSA(x1)),                             # r#1 = x#1
        ]
        func.basic_blocks = [block]

        ExpressionInliningPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'r#1 = x#1', 'must not have inlined reg0#1 > 0 past the call')

    def test_register_comparison_still_inlines_when_safe(self):
        func = make_func('inline_safe')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        func.locals['x'] = MLILVariable('x')

        reg0_1 = MLILVariableSSA(reg0, 1)
        x1 = MLILVariableSSA(func.locals['x'], 1)

        true_block = MediumLevelILBasicBlock(1)
        false_block = MediumLevelILBasicBlock(2)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILGt(MLILVarSSA(reg0_1), MLILConst(0))),
            MLILIf(MLILVarSSA(x1), true_block, false_block),
        ]
        func.basic_blocks = [block, true_block, false_block]

        ExpressionInliningPass().run(func)

        self.assertIn('reg0#1', str(block.instructions[-1]))

    def test_deref_read_still_requires_strict_adjacency(self):
        '''MLILDeref has no trackable base variable for the reachability check, so it must
        keep the original strict "must be the immediately next instruction" requirement.'''
        func = make_func('inline_deref')
        ptr = MLILVariable('ptr')
        func.locals['ptr'] = ptr
        func.locals['x'] = MLILVariable('x')
        func.locals['spacer'] = MLILVariable('spacer')
        func.locals['r'] = MLILVariable('r')

        ptr1 = MLILVariableSSA(ptr, 1)
        x1 = MLILVariableSSA(func.locals['x'], 1)
        spacer1 = MLILVariableSSA(func.locals['spacer'], 1)
        r1 = MLILVariableSSA(func.locals['r'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILDeref(MLILVarSSA(ptr1))),  # x#1 = *ptr#1
            MLILSetVarSSA(spacer1, MLILConst(0)),             # unrelated statement in between
            MLILSetVarSSA(r1, MLILVarSSA(x1)),                # r#1 = x#1
        ]
        func.basic_blocks = [block]

        ExpressionInliningPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'r#1 = x#1', 'a deref read must not inline across any intervening statement')

    def test_deref_read_still_inlines_when_adjacent(self):
        '''Regression guard: falling back to strict adjacency for untrackable (deref) impure
        reads must not turn into an unconditional refusal to ever inline them.'''
        func = make_func('inline_deref_adjacent')
        func.locals['ptr'] = MLILVariable('ptr')
        func.locals['x'] = MLILVariable('x')

        ptr1 = MLILVariableSSA(func.locals['ptr'], 1)
        x1 = MLILVariableSSA(func.locals['x'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILDeref(MLILVarSSA(ptr1))),  # x#1 = *ptr#1
            MLILRet(MLILVarSSA(x1)),                          # return x#1  (immediately adjacent)
        ]
        func.basic_blocks = [block]

        ExpressionInliningPass().run(func)

        self.assertIn('*ptr#1', str(block.instructions[-1]), 'an adjacent deref read must still inline')


class TestCopyPropagationCallOutputCountsAsRedefinition(unittest.TestCase):
    '''A call is not only a redefinition via its MLILUndef pseudo-defs for the registers/globals
    it clobbers - the ONE variable receiving its own result is also a redefinition, represented
    differently (the call instruction's own .output field, not a separate MLILSetVarSSA). Both
    CopyPropagationPass and ExpressionInliningPass must recognize this shape too.'''

    def test_copy_propagation_does_not_forward_past_a_calls_own_output(self):
        func = make_func('call_output_redefines')
        global5 = func.get_or_create_global_var(5)
        func.locals['tmp'] = MLILVariable('tmp')

        g1 = MLILVariableSSA(global5, 1)
        g2 = MLILVariableSSA(global5, 2)  # written by the call's own .output, not a SetVarSSA
        g3 = MLILVariableSSA(global5, 3)
        tmp1 = MLILVariableSSA(func.locals['tmp'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(g1, MLILConst(99)),
            MLILSetVarSSA(tmp1, MLILVarSSA(g1)),          # tmp#1 = global5#1        (save)
            MLILSyscall(0, 1, [], g2),                     # a call whose OWN result overwrites global5
            MLILSetVarSSA(g3, MLILVarSSA(tmp1)),           # global5#3 = tmp#1        (restore)
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)
        SSADeconstructor(func).deconstruct()

        lines = [str(inst) for inst in block.instructions]
        self.assertIn('GLOBAL[5] = tmp', lines, 'the restore must survive - global5#1 must not be forwarded past the call output')

    def test_expression_inlining_does_not_cross_a_calls_own_output(self):
        func = make_func('call_output_redefines_inline')
        global5 = func.get_or_create_global_var(5)
        for n in ('x', 'r'):
            func.locals[n] = MLILVariable(n)

        g1 = MLILVariableSSA(global5, 1)
        g2 = MLILVariableSSA(global5, 2)
        x1 = MLILVariableSSA(func.locals['x'], 1)
        r1 = MLILVariableSSA(func.locals['r'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILGt(MLILVarSSA(g1), MLILConst(0))),  # x#1 = global5#1 > 0
            MLILSyscall(0, 1, [], g2),                                  # call's own result overwrites global5
            MLILSetVarSSA(r1, MLILVarSSA(x1)),                          # r#1 = x#1
        ]
        func.basic_blocks = [block]

        ExpressionInliningPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'r#1 = x#1', 'must not inline global5#1 > 0 past the call output')


class TestCopyPropagationEntryVersionSource(unittest.TestCase):
    '''A copy source seeded at function entry (a parameter, or a register/global read before
    any assignment in the function) has no MLILSetVarSSA/MLILPhi defining it - the reachability
    check must be anchored at the COPY's own definition, not the source's, or every such copy
    would be conservatively (and incorrectly) treated as unsafe to propagate.'''

    def test_register_entry_version_with_no_recorded_definition_still_propagates(self):
        func = make_func('entry_version')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        func.locals['tmp'] = MLILVariable('tmp')

        reg0_entry = MLILVariableSSA(reg0, 0)  # entry version - never assigned via MLILSetVarSSA
        tmp1 = MLILVariableSSA(func.locals['tmp'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(tmp1, MLILVarSSA(reg0_entry)),  # tmp#1 = reg0#0 (reg0's entry value)
            MLILRet(MLILVarSSA(tmp1)),
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'return reg0#0')


if __name__ == '__main__':
    unittest.main()
