#!/usr/bin/env python3
'''Unit tests for CopyPropagationPass and ExpressionInliningPass: copy propagation and expression
inlining must not forward a register/global SSA value past a point where that same storage gets
redefined.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst,
    MLILGt, MLILCall, MLILSyscall, MLILDeref, MLILLoadGlobal,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILIf, MLILRet, MLILUndef, SSADeconstructor
from ir.mlil.passes import CopyPropagationPass, ExpressionInliningPass, SSADeadCodeEliminationPass
from ir.mlil.passes.pass_ssa_copy_propagation import reaches_without_redefinition
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil

SORA2_ANI_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en' / 'ani'


def make_func(name: str) -> MediumLevelILFunction:
    return MediumLevelILFunction(name, 0)


class TestCopyPropagationGlobalSaveRestore(unittest.TestCase):
    '''tmp = GLOBAL[n]; GLOBAL[n] = x; ...; GLOBAL[n] = tmp must keep the restore - forwarding
    GLOBAL[n]'s original value directly to the restore site would make de-SSA collapse it into
    a no-op, since a global's SSA version identity is erased once it lowers back to GLOBALS[n].'''

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
    that clobbers that storage - the inliner's impure-read check previously looked for MLILLoadReg/
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


class TestExpressionInliningUnraisedGlobalRead(unittest.TestCase):
    '''A global that is only ever READ (never stored) in this function is never raised into
    an SSA-tracked variable by SSA construction (mlil_ssa.py's _raise_globals leaves it alone)
    - it survives as a bare MLILLoadGlobal even in SSA form. Since it has no SSA base variable,
    reaches_without_redefinition cannot track it; it must be treated as untrackable (poisoned),
    like MLILDeref, not as pure - a prior rewrite of the inliner's impure-read check (switching to
    MLILVarSSA-based detection for the common raised case) dropped this case entirely, making
    every such read freely movable with no adjacency check at all, not even the old strict one.'''

    def test_unraised_global_read_not_inlined_across_call(self):
        func = make_func('unraised_global')
        for n in ('x', 'r'):
            func.locals[n] = MLILVariable(n)

        x1 = MLILVariableSSA(func.locals['x'], 1)
        r1 = MLILVariableSSA(func.locals['r'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILGt(MLILLoadGlobal(7), MLILConst(0))),  # x#1 = GLOBAL[7] > 0 (never stored -> unraised)
            MLILCall(0x1234, [], output = None),
            MLILSetVarSSA(r1, MLILVarSSA(x1)),
        ]
        func.basic_blocks = [block]

        ExpressionInliningPass().run(func)

        self.assertEqual(str(block.instructions[-1]), 'r#1 = x#1', 'an unraised global read must not inline across a call')

    def test_unraised_global_read_still_inlines_when_adjacent(self):
        '''Regression guard: the untrackable fallback must not become an unconditional refusal.'''
        func = make_func('unraised_global_adjacent')
        func.locals['x'] = MLILVariable('x')

        x1 = MLILVariableSSA(func.locals['x'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILGt(MLILLoadGlobal(7), MLILConst(0))),
            MLILRet(MLILVarSSA(x1)),
        ]
        func.basic_blocks = [block]

        ExpressionInliningPass().run(func)

        self.assertIn('GLOBAL[7]', str(block.instructions[-1]), 'an adjacent unraised global read must still inline')


class TestCopyPropagationMultiUseAppliesAtEveryHop(unittest.TestCase):
    '''The "read more than once keeps its own name" rule must apply at every hop of a copy
    chain, not just the hop whose immediate source is the register/global itself:
    t#1 = reg0#1; a#1 = t#1; z1#1 = a#1; z2#1 = a#1 must stop at a#1 (used twice), even though
    t#1 - a#1's own direct source - is used only once, so the original single-hop check never
    saw a#1's use count at all.'''

    def test_multi_use_local_two_hops_from_register_keeps_its_name(self):
        func = make_func('multiuse_two_hop')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        for n in ('t', 'a', 'z1', 'z2'):
            func.locals[n] = MLILVariable(n)

        reg0_1 = MLILVariableSSA(reg0, 1)
        t1 = MLILVariableSSA(func.locals['t'], 1)
        a1 = MLILVariableSSA(func.locals['a'], 1)
        z1_1 = MLILVariableSSA(func.locals['z1'], 1)
        z2_1 = MLILVariableSSA(func.locals['z2'], 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(reg0_1, MLILConst(5)),
            MLILSetVarSSA(t1, MLILVarSSA(reg0_1)),   # t#1 = reg0#1, used once (by a#1)
            MLILSetVarSSA(a1, MLILVarSSA(t1)),        # a#1 = t#1, used TWICE (z1, z2)
            MLILSetVarSSA(z1_1, MLILVarSSA(a1)),
            MLILSetVarSSA(z2_1, MLILVarSSA(a1)),
        ]
        func.basic_blocks = [block]

        CopyPropagationPass().run(func)

        self.assertEqual(str(block.instructions[-2]), 'z1#1 = a#1', 'must stop at a#1, not spread reg0#1 over both reads')
        self.assertEqual(str(block.instructions[-1]), 'z2#1 = a#1', 'must stop at a#1, not spread reg0#1 over both reads')


class TestCopyPropagationBackwardReachabilityAcrossBranch(unittest.TestCase):
    '''reaches_without_redefinition walks backward from the use, so a def sitting in a block
    that itself branches (e.g. ends in `if (cond) ...`) can still forward safely into whichever
    arm has that block as its SOLE predecessor - the block's OTHER successor is irrelevant to
    whether the one path actually taken is hazard-free. Found and sized against the real corpus
    before implementing (350-file capped census, per notes/corpus_run_rules.md): 12 distinct
    sites across 9 ai_* files, 0 soundness violations (no case the old forward-only walk
    accepted was ever rejected by the backward walk).'''

    def test_copy_forwards_through_a_branching_def_block_into_its_sole_successor(self):
        func = make_func('branch_then_safe_use')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        func.locals['a'] = MLILVariable('a')
        func.locals['c'] = MLILVariable('c')
        func.locals['r'] = MLILVariable('r')

        reg0_1 = MLILVariableSSA(reg0, 1)
        a1 = MLILVariableSSA(func.locals['a'], 1)
        c1 = MLILVariableSSA(func.locals['c'], 1)
        r1 = MLILVariableSSA(func.locals['r'], 1)

        b1 = MediumLevelILBasicBlock(1)
        b2 = MediumLevelILBasicBlock(2)
        b0 = MediumLevelILBasicBlock(0)
        b0.instructions = [
            MLILSetVarSSA(reg0_1, MLILConst(5)),
            MLILSetVarSSA(a1, MLILVarSSA(reg0_1)),   # a#1 = reg0#1 - b0 (a#1's own def block) branches next
            MLILIf(MLILVarSSA(c1), b1, b2),
        ]
        b1.instructions = [
            MLILSetVarSSA(r1, MLILVarSSA(a1)),        # r#1 = a#1 - b1's only predecessor is b0
        ]
        b0.add_outgoing_edge(b1)
        b0.add_outgoing_edge(b2)
        func.basic_blocks = [b0, b1, b2]

        CopyPropagationPass().run(func)

        self.assertEqual(str(b1.instructions[-1]), 'r#1 = reg0#1',
                          'a safe copy must still resolve through a branching def block into its sole successor')


class TestReachabilityScansUseBlockPrefix(unittest.TestCase):
    '''reaches_without_redefinition must also scan the use block's own instructions before the
    use - a redefinition sitting there runs after every predecessor, so forwarding the old value
    past it changes what the use reads.'''

    def build_branch(self, func, b0_tail, b1_instructions):
        '''b0: ...b0_tail; if (c#1) b1 else b2 - b1 is the use block, b0 its sole predecessor'''
        func.locals['c'] = MLILVariable('c')
        c1 = MLILVariableSSA(func.locals['c'], 1)
        b0 = MediumLevelILBasicBlock(0)
        b1 = MediumLevelILBasicBlock(1)
        b2 = MediumLevelILBasicBlock(2)
        b0.instructions = b0_tail + [MLILIf(MLILVarSSA(c1), b1, b2)]
        b1.instructions = b1_instructions
        b2.instructions = [MLILRet(MLILConst(0))]
        b0.add_outgoing_edge(b1)
        b0.add_outgoing_edge(b2)
        func.basic_blocks = [b0, b1, b2]
        return b0, b1

    def test_global_restore_inside_branch_survives_deconstruction(self):
        func = make_func('restore_in_branch')
        global5 = func.get_or_create_global_var(5)
        func.locals['tmp'] = MLILVariable('tmp')
        g1, g2, g3 = (MLILVariableSSA(global5, n) for n in (1, 2, 3))
        tmp1 = MLILVariableSSA(func.locals['tmp'], 1)

        _, b1 = self.build_branch(func, [
            MLILSetVarSSA(g1, MLILConst(99)),
            MLILSetVarSSA(tmp1, MLILVarSSA(g1)),     # tmp#1 = global5#1          (save)
        ], [
            MLILSetVarSSA(g2, MLILConst(7)),         # global5#2 = 7              (overwrite, use block prefix)
            MLILSetVarSSA(g3, MLILVarSSA(tmp1)),     # global5#3 = tmp#1          (restore)
            MLILRet(MLILConst(0)),
        ])

        CopyPropagationPass().run(func)
        SSADeconstructor(func).deconstruct()

        self.assertIn('GLOBAL[5] = tmp', [str(inst) for inst in b1.instructions], 'the restore must survive')

    def test_global_read_not_forwarded_past_store_in_use_block(self):
        func = make_func('store_in_use_block')
        global5 = func.get_or_create_global_var(5)
        func.locals['t'] = MLILVariable('t')
        g1, g2 = MLILVariableSSA(global5, 1), MLILVariableSSA(global5, 2)
        t1 = MLILVariableSSA(func.locals['t'], 1)

        _, b1 = self.build_branch(func, [
            MLILSetVarSSA(t1, MLILVarSSA(g1)),       # t#1 = global5#1
        ], [
            MLILSetVarSSA(g2, MLILConst(7)),         # global5#2 = 7
            MLILRet(MLILVarSSA(t1)),                 # return t#1 - must not become global5#1
        ])

        CopyPropagationPass().run(func)

        self.assertEqual(str(b1.instructions[-1]), 'return t#1')

    def test_entry_register_not_forwarded_past_call_in_use_block(self):
        func = make_func('entry_reg_past_call')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        func.locals['saved'] = MLILVariable('saved')
        reg0_entry, reg0_1 = MLILVariableSSA(reg0, 0), MLILVariableSSA(reg0, 1)
        saved1 = MLILVariableSSA(func.locals['saved'], 1)

        _, b1 = self.build_branch(func, [
            MLILSetVarSSA(saved1, MLILVarSSA(reg0_entry)),  # saved#1 = reg0#0 (entry value)
        ], [
            MLILCall(0x1234, [], output = None),
            MLILSetVarSSA(reg0_1, MLILUndef()),             # call's pseudo-def clobbers reg0
            MLILRet(MLILVarSSA(saved1)),
        ])

        CopyPropagationPass().run(func)

        self.assertEqual(str(b1.instructions[-1]), 'return saved#1', 'must not read reg0 after the call')

    def test_expression_not_inlined_past_store_in_use_block(self):
        func = make_func('inline_past_store_in_use_block')
        global5 = func.get_or_create_global_var(5)
        func.locals['x'] = MLILVariable('x')
        g1, g2 = MLILVariableSSA(global5, 1), MLILVariableSSA(global5, 2)
        x1 = MLILVariableSSA(func.locals['x'], 1)
        b3 = MediumLevelILBasicBlock(3)
        b4 = MediumLevelILBasicBlock(4)

        _, b1 = self.build_branch(func, [
            MLILSetVarSSA(x1, MLILGt(MLILVarSSA(g1), MLILConst(0))),  # x#1 = global5#1 > 0
        ], [
            MLILSetVarSSA(g2, MLILConst(-5)),                          # global5#2 = -5
            MLILIf(MLILVarSSA(x1), b3, b4),                            # if (x#1)
        ])
        func.basic_blocks += [b3, b4]

        ExpressionInliningPass().run(func)

        self.assertIn('x#1', str(b1.instructions[-1]), 'must not inline global5#1 > 0 past the store')

    def test_harmless_prefix_still_forwards_across_branch(self):
        func = make_func('harmless_prefix')
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        for n in ('a', 'spacer', 'r'):
            func.locals[n] = MLILVariable(n)
        reg0_1 = MLILVariableSSA(reg0, 1)
        a1, spacer1, r1 = (MLILVariableSSA(func.locals[n], 1) for n in ('a', 'spacer', 'r'))

        _, b1 = self.build_branch(func, [
            MLILSetVarSSA(reg0_1, MLILConst(5)),
            MLILSetVarSSA(a1, MLILVarSSA(reg0_1)),    # a#1 = reg0#1
        ], [
            MLILSetVarSSA(spacer1, MLILConst(0)),     # unrelated prefix statement
            MLILSetVarSSA(r1, MLILVarSSA(a1)),        # r#1 = a#1
            MLILRet(MLILVarSSA(r1)),
        ])

        CopyPropagationPass().run(func)

        self.assertEqual(str(b1.instructions[1]), 'r#1 = reg0#1', 'a harmless prefix must not block forwarding')


class TestCallClobberSurvivesDeadCodeElimination(unittest.TestCase):
    '''Dead-code elimination drops an unread call output and dead register pseudo-defs, so on the
    next optimizer round the call itself is the only evidence that it clobbered a register - the
    reachability check must still treat it as a redefinition.'''

    def reg0_func(self, name):
        func = make_func(name)
        reg0 = MLILVariable('reg0')
        func.register_vars[0] = reg0
        func.locals['t'] = MLILVariable('t')
        return func, reg0, MLILVariableSSA(func.locals['t'], 1)

    def optimize_rounds(self, func):
        '''Two optimizer rounds with dead-code elimination in between, as SSAOptimizer runs them'''
        CopyPropagationPass().run(func)
        SSADeadCodeEliminationPass().run(func)
        CopyPropagationPass().run(func)

    def test_dropped_call_output_still_blocks_forward_into_branch(self):
        func, reg0, t1 = self.reg0_func('dropped_output')
        func.locals['c'] = MLILVariable('c')
        reg0_1, reg0_2 = MLILVariableSSA(reg0, 1), MLILVariableSSA(reg0, 2)
        c1 = MLILVariableSSA(func.locals['c'], 1)
        b0, b1, b2 = (MediumLevelILBasicBlock(n) for n in range(3))
        b0.instructions = [
            MLILCall('produce', [], output = reg0_1),
            MLILSetVarSSA(t1, MLILVarSSA(reg0_1)),                # t#1 = reg0#1        (save)
            MLILIf(MLILVarSSA(c1), b1, b2),
        ]
        b1.instructions = [
            MLILCall('clobber', [], output = reg0_2),             # unread output - dead-code elimination drops it
            MLILCall('consume', [MLILVarSSA(t1)]),
            MLILRet(MLILConst(0)),
        ]
        b2.instructions = [MLILRet(MLILConst(0))]
        b0.add_outgoing_edge(b1)
        b0.add_outgoing_edge(b2)
        func.basic_blocks = [b0, b1, b2]

        self.optimize_rounds(func)

        self.assertEqual(str(b1.instructions[0]), 'clobber()', 'the unread output must have been dropped')
        self.assertEqual(str(b1.instructions[1]), 'consume(t#1)', 'reg0#1 must not be read after the clobbering call')

    def test_dropped_pseudo_def_still_blocks_forward_in_same_block(self):
        func, reg0, t1 = self.reg0_func('dropped_pseudo_def')
        reg0_1, reg0_2 = MLILVariableSSA(reg0, 1), MLILVariableSSA(reg0, 2)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILCall('produce', [], output = reg0_1),
            MLILSetVarSSA(t1, MLILVarSSA(reg0_1)),                # t#1 = reg0#1        (save)
            MLILSyscall(6, 35, []),
            MLILSetVarSSA(reg0_2, MLILUndef()),                   # the syscall's dead pseudo-def
            MLILCall('consume', [MLILVarSSA(t1)]),
            MLILRet(MLILConst(0)),
        ]
        func.basic_blocks = [block]

        self.optimize_rounds(func)

        lines = [str(inst) for inst in block.instructions]
        self.assertFalse(any('reg0#2' in line for line in lines), 'the dead pseudo-def must have been dropped')
        self.assertIn('consume(t#1)', lines, 'reg0#1 must not be read after the syscall')

    def test_non_clobbering_call_does_not_block_forward(self):
        func, reg0, t1 = self.reg0_func('non_clobbering')
        reg0_1 = MLILVariableSSA(reg0, 1)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILCall('produce', [], output = reg0_1),
            MLILSetVarSSA(t1, MLILVarSSA(reg0_1)),
            MLILCall('debug_print', [], clobbers_registers = False),
            MLILCall('consume', [MLILVarSSA(t1)]),
            MLILRet(MLILConst(0)),
        ]
        func.basic_blocks = [block]

        self.optimize_rounds(func)

        self.assertIn('consume(reg0#1)', [str(inst) for inst in block.instructions])

    def test_read_as_argument_of_the_clobbering_call_still_forwards(self):
        '''Arguments are read before the call runs, so its own clobber does not apply to them'''
        func, reg0, t1 = self.reg0_func('argument_of_clobbering_call')
        reg0_1 = MLILVariableSSA(reg0, 1)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILCall('produce', [], output = reg0_1),
            MLILSetVarSSA(t1, MLILVarSSA(reg0_1)),
            MLILCall('consume', [MLILVarSSA(t1)]),
            MLILRet(MLILConst(0)),
        ]
        func.basic_blocks = [block]

        self.optimize_rounds(func)

        self.assertIn('consume(reg0#1)', [str(inst) for inst in block.instructions])

    def test_bare_call_is_a_redefinition_of_registers_and_globals(self):
        func, reg0, _ = self.reg0_func('bare_call')
        global5 = func.get_or_create_global_var(5)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [MLILConst(0), MLILSyscall(6, 35, []), MLILConst(0)]

        self.assertFalse(reaches_without_redefinition(func, reg0, block, 0, block, 2))
        self.assertFalse(reaches_without_redefinition(func, global5, block, 0, block, 2))

        block.instructions[1] = MLILCall('debug_print', [], clobbers_registers = False)
        self.assertTrue(reaches_without_redefinition(func, reg0, block, 0, block, 2))


class TestDeadCodeGlobalCallOutput(unittest.TestCase):
    '''Call results only land in the result register - a global call output would be a global
    write that dropping an unread output silently loses, so it must fail loudly instead.'''

    def test_unread_global_call_output_raises(self):
        func = make_func('global_call_output')
        global5 = func.get_or_create_global_var(5)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [MLILCall('produce', [], output = MLILVariableSSA(global5, 1)), MLILRet(MLILConst(0))]
        func.basic_blocks = [block]

        with self.assertRaises(ValueError):
            SSADeadCodeEliminationPass().run(func)


def optimized_corpus_mlil(dat_name: str, func_name: str) -> MediumLevelILFunction:
    path = SORA2_ANI_DIR / dat_name
    if not path.exists():
        raise unittest.SkipTest(f'Test file not found: {path}')

    parser, functions = ScpParser.load(path, round_trip = False, keep_unreachable_code = False)
    func = next(f for f in functions if f.name == func_name)
    llil = ED9VMLifter(parser = parser).lift_function(func)
    return convert_falcom_llil_to_mlil(llil, parser, optimize = True, infer_types = True)


class TestCorpusRegisterReadAfterClobberingCall(unittest.TestCase):
    '''Real functions whose bytecode saves reg0 to a stack slot before a call and later reads the
    saved slot - the decompiled call after the clobber must read the saved copy, not reg0.'''

    def call_text(self, mlil: MediumLevelILFunction, target: str) -> str:
        return next(str(inst) for block in mlil.basic_blocks for inst in block.instructions
                    if str(inst).startswith(f'{target}('))

    def test_set_rotate_ani_param(self):
        mlil = optimized_corpus_mlil('common.dat', 'SetRotateAniParam')
        self.assertNotIn('reg0', self.call_text(mlil, 'chr_set_joint_rot'))

    def test_ani_fall(self):
        mlil = optimized_corpus_mlil('chr0003.dat', 'AniFall')
        self.assertNotIn('reg0', self.call_text(mlil, 'chr_play_animeclip'))


if __name__ == '__main__':
    unittest.main()
