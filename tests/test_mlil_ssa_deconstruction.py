#!/usr/bin/env python3
'''Unit tests for SSADeconstructor._allocate_variables: SSA deconstruction must reuse
already-minted suffix classes instead of minting a fresh one on every conflict, must never let a
defined-but-unused version fall back to an interference-unaware raw base name, must never let a
minted suffix collide with an unrelated real variable, and must track every phi-elimination copy
partner for a destination, not just the last one seen.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILAdd,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, SSADeconstructor


def make_func(name: str) -> MediumLevelILFunction:
    return MediumLevelILFunction(name, 0)


class TestAllocateVariablesReusesSuffixClasses(unittest.TestCase):
    '''Loop-counter shape from the plan: one long-lived version (i0) interferes with three later
    versions that do NOT interfere with each other. All three should share a single suffix class -
    the pre-fix allocator only ever checked the base-name class, so each conflicting version minted
    its own new suffix instead of reusing one already created for an earlier version.'''

    def test_three_non_interfering_versions_share_one_suffix_class(self):
        func = make_func('loop_counter')
        i = MLILVariable('i')
        func.locals['i'] = i
        for n in ('x', 'y', 'z', 'w'):
            func.locals[n] = MLILVariable(n)

        i0 = MLILVariableSSA(i, 0)
        i1 = MLILVariableSSA(i, 1)
        i2 = MLILVariableSSA(i, 2)
        i3 = MLILVariableSSA(i, 3)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(i0, MLILConst(100)),
            MLILSetVarSSA(i1, MLILAdd(MLILVarSSA(i0), MLILConst(1))),
            MLILSetVarSSA(MLILVariableSSA(func.locals['x'], 1), MLILVarSSA(i1)),
            MLILSetVarSSA(i2, MLILAdd(MLILVarSSA(i0), MLILConst(2))),
            MLILSetVarSSA(MLILVariableSSA(func.locals['y'], 1), MLILVarSSA(i2)),
            MLILSetVarSSA(i3, MLILAdd(MLILVarSSA(i0), MLILConst(3))),
            MLILSetVarSSA(MLILVariableSSA(func.locals['z'], 1), MLILVarSSA(i3)),
            MLILSetVarSSA(MLILVariableSSA(func.locals['w'], 1), MLILVarSSA(i0)),
        ]
        func.basic_blocks = [block]

        SSADeconstructor(func).deconstruct()

        lines = [str(inst) for inst in block.instructions]
        self.assertEqual(lines[0], 'i = 100')
        self.assertEqual(lines[-1], 'w = i')

        suffix_names = {lines[idx].split(' = ')[0] for idx in (1, 3, 5)}
        self.assertEqual(len(suffix_names), 1,
                         f'all three non-interfering versions should share one suffix class, got {suffix_names}')
        self.assertNotIn('i', suffix_names)


class TestAllocateVariablesKeepsSwapSafe(unittest.TestCase):
    '''Two-variable swap shape from the plan (the sequentialised back-edge copies for i and j): each
    variable's own pre-swap and post-swap versions genuinely interfere (the pre-swap value is read
    by the OTHER variable's update, after its own update has already run), so they must keep separate
    names - confirms the new class-reuse logic still respects interference and never lets copy-affinity
    preference override it.'''

    def test_swap_halves_keep_distinct_names(self):
        func = make_func('swap')
        i = MLILVariable('i')
        j = MLILVariable('j')
        func.locals['i'] = i
        func.locals['j'] = j
        for n in ('log_j', 'result_i', 'result_j'):
            func.locals[n] = MLILVariable(n)

        i1 = MLILVariableSSA(i, 1)
        j1 = MLILVariableSSA(j, 1)
        i2 = MLILVariableSSA(i, 2)
        j2 = MLILVariableSSA(j, 2)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(i1, MLILConst(10)),
            MLILSetVarSSA(j1, MLILConst(20)),
            MLILSetVarSSA(i2, MLILVarSSA(j1)),     # new i = old j
            MLILSetVarSSA(j2, MLILVarSSA(i1)),     # new j = old i - must read the ORIGINAL i, not i2
            MLILSetVarSSA(MLILVariableSSA(func.locals['log_j'], 1), MLILVarSSA(j1)),
            MLILSetVarSSA(MLILVariableSSA(func.locals['result_i'], 1), MLILVarSSA(i2)),
            MLILSetVarSSA(MLILVariableSSA(func.locals['result_j'], 1), MLILVarSSA(j2)),
        ]
        func.basic_blocks = [block]

        SSADeconstructor(func).deconstruct()

        lines = [str(inst) for inst in block.instructions]
        self.assertEqual(lines[2], 'i_v0 = j', "i's new value must read j's old value under a name distinct from i")
        self.assertEqual(lines[3], 'j_v0 = i', "j's new value must read i's old value, not the just-updated i")


class TestAllocateVariablesProtectsDeadDefinitions(unittest.TestCase):
    '''A defined-but-never-read SSA version must still get an interference-checked name. Excluding it
    from allocation (the pre-fix behavior) left _apply_mapping_to_inst falling back to the raw,
    unversioned base variable with zero interference checking - silently clobbering a coalesced
    version that is genuinely live under that same name at that point.'''

    def test_dead_store_does_not_clobber_a_live_value_under_the_base_name(self):
        func = make_func('dead_store')
        x = MLILVariable('x')
        func.locals['x'] = x
        func.locals['result'] = MLILVariable('result')

        x1 = MLILVariableSSA(x, 1)
        x2 = MLILVariableSSA(x, 2)  # defined, never read

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILConst(10)),
            MLILSetVarSSA(x2, MLILConst(99)),  # dead - x1 must still be readable after this
            MLILSetVarSSA(MLILVariableSSA(func.locals['result'], 1), MLILVarSSA(x1)),
        ]
        func.basic_blocks = [block]

        SSADeconstructor(func).deconstruct()

        lines = [str(inst) for inst in block.instructions]
        self.assertNotEqual(lines[1], 'x = 99', 'the dead store must not target the live base name "x"')
        self.assertEqual(lines[-1], 'result = x', "x1's real value must survive, unclobbered by the dead store")


class TestAllocateVariablesAvoidsNameCollisions(unittest.TestCase):
    '''A minted suffix must never reuse a name already bound to a different real variable -
    MLILVariable equality is name-only, so a collision would silently merge the two.'''

    def test_minted_suffix_skips_a_name_already_used_by_an_unrelated_parameter(self):
        func = make_func('collision')
        counter = MLILVariable('counter')
        func.locals['counter'] = counter
        func.locals['a'] = MLILVariable('a')
        func.locals['b'] = MLILVariable('b')
        # An unrelated parameter already named exactly what the naive first suffix mint would try -
        # function.locals alone would not catch this collision (parameters are a separate collection).
        func.parameters.append(MLILVariable('counter_v0'))

        c0 = MLILVariableSSA(counter, 0)
        c1 = MLILVariableSSA(counter, 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(c0, MLILConst(0)),
            MLILSetVarSSA(c1, MLILConst(1)),  # interferes with c0 (both read below)
            MLILSetVarSSA(MLILVariableSSA(func.locals['a'], 1), MLILVarSSA(c0)),
            MLILSetVarSSA(MLILVariableSSA(func.locals['b'], 1), MLILVarSSA(c1)),
        ]
        func.basic_blocks = [block]

        SSADeconstructor(func).deconstruct()

        minted_name = str(block.instructions[1]).split(' = ')[0]
        self.assertNotEqual(minted_name, 'counter_v0', 'must not silently merge with the unrelated parameter counter_v0')
        self.assertEqual(minted_name, 'counter_v1')


class TestCopyAffinityIsManyToMany(unittest.TestCase):
    '''Phi elimination inserts one copy per predecessor edge, all targeting the same phi.dest - so a
    single destination can have several distinct copy-source partners. copy_affinity must record all
    of them (a set), not silently retain only the last one seen (a plain dict would).'''

    def test_dest_written_by_two_predecessor_copies_keeps_both_partners(self):
        func = make_func('multi_partner')
        v = MLILVariable('v')
        func.locals['v'] = v

        v0 = MLILVariableSSA(v, 0)
        v1 = MLILVariableSSA(v, 1)  # the merge/phi-elimination target
        v3 = MLILVariableSSA(v, 3)

        block_a = MediumLevelILBasicBlock(0)
        block_a.instructions = [
            MLILSetVarSSA(v0, MLILConst(1)),
            MLILSetVarSSA(v1, MLILVarSSA(v0)),  # predecessor A's phi-elimination copy
        ]
        block_b = MediumLevelILBasicBlock(1)
        block_b.instructions = [
            MLILSetVarSSA(v3, MLILConst(2)),
            MLILSetVarSSA(v1, MLILVarSSA(v3)),  # predecessor B's phi-elimination copy
        ]
        func.basic_blocks = [block_a, block_b]

        deconstructor = SSADeconstructor(func)
        deconstructor._collect_ssa_vars()

        self.assertEqual(deconstructor.copy_affinity[v1], {v0, v3},
                         'v1 was copy-assigned from both v0 and v3 - both must be tracked as affinity partners')


if __name__ == '__main__':
    unittest.main()
