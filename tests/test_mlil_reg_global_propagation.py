#!/usr/bin/env python3
'''Unit tests for RegGlobalValuePropagator - Step 9 of the LLIL/MLIL hardening plan. Covers all
six confirmed bugs: 2 (worklist fixpoint) and 6 (constant equality) fixed directly; 1/3/4/5 (a
live/stale cached reference surviving a write to whatever it depends on) closed by Candidate B -
only a fully closed-form (constant) expression is ever cached under a REG/GLOBAL slot, so nothing
cached can ever go stale, chosen over Candidate A (generalized dependency invalidation) after a
full-corpus, cross-game measurement showed zero real difference between them.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MLILConst, MLILGoto, MLILIf, MLILCall, MLILLoadGlobal, MLILLoadReg,
    MLILStoreGlobal, MLILStoreReg, MLILStoreDeref, MLILRet, MLILSetVar, MLILVar, MLILAdd,
    MLILAddressOf,
)
from ir.mlil.passes.pass_reg_global_propagation import (
    RegGlobalValuePropagator, RegGlobalState,
)
from ir.mlil.passes import RegGlobalValuePropagationPass


FUNC_START = 0x1000


class TestWorklistFixpointRecordsInStateOnEveryVisit(unittest.TestCase):
    '''Bug 2: _analyze only recorded block_in when out_state changed, so a loop block whose
    out_state stabilizes early (a call clobbers state to unknown on every visit regardless of
    what flows in) kept a stale, over-optimistic first-visit in_state forever.'''

    def test_loop_global_is_not_folded_past_a_clobbering_call_on_the_back_edge(self):
        func = MediumLevelILFunction('worklist_test')
        entry = func.create_block(start = FUNC_START, label = 'entry')
        loop = func.create_block(start = FUNC_START + 4, label = 'loop')
        exit_block = func.create_block(start = FUNC_START + 8, label = 'exit')

        entry.add_instruction(MLILStoreGlobal(7, MLILConst(0)))
        entry.add_instruction(MLILGoto(loop))
        entry.add_outgoing_edge(loop)

        loop.add_instruction(MLILCall('foo', [MLILLoadGlobal(7)]))
        loop.add_instruction(MLILIf(MLILConst(1), loop, exit_block))
        loop.add_outgoing_edge(loop)
        loop.add_outgoing_edge(exit_block)

        exit_block.add_instruction(MLILRet(None))

        RegGlobalValuePropagationPass().run(func)

        # If block_in[loop] wrongly stayed at the first-visit {7: 0}, this call's argument
        # would be folded to the constant 0 on every iteration, not just the first.
        call_inst = loop.instructions[0]
        self.assertIsInstance(call_inst.args[0], MLILLoadGlobal)


class TestConstantEqualityIsRepresentationSafe(unittest.TestCase):
    '''Bug 6: _expr_equal compared MLILConst values with bare `==`, which conflates int/float
    representations (1 == 1.0) and considers NaN unequal to itself (nan == nan is False in
    Python), the latter of which means _analyze's fixpoint loop never converges for a function
    whose tracked state includes a NaN constant - ED9 floats decode straight from binary data,
    so NaN is reachable.'''

    def setUp(self):
        self.propagator = RegGlobalValuePropagator(MediumLevelILFunction('equality_test'))

    def test_int_and_float_constants_are_not_equal_even_with_the_same_numeric_value(self):
        self.assertFalse(self.propagator._expr_equal(MLILConst(1), MLILConst(1.0)))

    def test_nan_constants_are_equal_to_each_other(self):
        self.assertTrue(self.propagator._expr_equal(MLILConst(float('nan')), MLILConst(float('nan'))))

    def test_merge_states_widens_to_unknown_when_predecessors_disagree_on_representation(self):
        merged = self.propagator._merge_states([
            RegGlobalState(global_ = {0: MLILConst(1)}),
            RegGlobalState(global_ = {0: MLILConst(1.0)}),
        ])

        # Predecessors disagree on representation - must widen to unknown, not silently pick
        # one predecessor's int constant for a path that actually produced a float.
        self.assertIsNone(merged.global_[0])

    def test_state_equal_reaches_a_fixpoint_on_a_nan_valued_state(self):
        left = RegGlobalState(global_ = {0: MLILConst(float('nan'))})
        right = RegGlobalState(global_ = {0: MLILConst(float('nan'))})

        self.assertTrue(self.propagator._state_equal(left, right))


class TestClosedFormCachingClosesLiveReferenceBugs(unittest.TestCase):
    '''Bugs 1/3/4/5: only a fully closed-form (constant) expression is ever cached under a
    REG/GLOBAL slot - a live reference to another slot, a local, or a pointer dereference is
    never cached, so none of these can go stale.'''

    def test_bug1_copy_of_an_unresolved_slot_is_not_cached_as_a_live_reference(self):
        func = MediumLevelILFunction('bug1')
        block = func.create_block()
        block.add_instruction(MLILStoreReg(0, MLILLoadReg(1)))
        block.add_instruction(MLILStoreReg(1, MLILConst(7)))
        block.add_instruction(MLILRet(MLILLoadReg(0)))

        RegGlobalValuePropagationPass().run(func)

        # If REG[0] wrongly cached "whatever REG[1] turns out to be," this would fold to 7.
        final_ret = block.instructions[-1]
        self.assertIsInstance(final_ret.value, MLILLoadReg)
        self.assertEqual(final_ret.value.index, 0)

    def test_bug3_reassigning_a_local_does_not_leak_into_an_earlier_global_read(self):
        func = MediumLevelILFunction('bug3')
        block = func.create_block()
        x = func.get_or_create_local('var_s0', 0)
        block.add_instruction(MLILStoreGlobal(5, MLILVar(x)))
        block.add_instruction(MLILSetVar(x, MLILConst(99)))
        block.add_instruction(MLILCall('h', [MLILLoadGlobal(5)]))

        RegGlobalValuePropagationPass().run(func)

        # If GLOBAL[5] wrongly cached "whatever var_s0 turns out to be," this would fold to 99.
        call_inst = block.instructions[-1]
        self.assertIsInstance(call_inst.args[0], MLILLoadGlobal)

    def test_bug4_a_self_referential_store_does_not_double_apply(self):
        func = MediumLevelILFunction('bug4')
        block = func.create_block()
        block.add_instruction(MLILStoreReg(0, MLILAdd(MLILLoadReg(0), MLILConst(1))))
        block.add_instruction(MLILRet(MLILLoadReg(0)))

        RegGlobalValuePropagationPass().run(func)

        # "REG[0] + 1" still contains a LoadReg - not closed-form - so it must not be cached as
        # REG[0]'s own new value, or the return would double-apply the +1.
        final_ret = block.instructions[-1]
        self.assertIsInstance(final_ret.value, MLILLoadReg)

    def test_bug5_a_pointer_write_does_not_retroactively_change_an_earlier_global_snapshot(self):
        func = MediumLevelILFunction('bug5')
        block = func.create_block()
        x = func.get_or_create_local('x', 0)
        block.add_instruction(MLILSetVar(x, MLILConst(1)))
        block.add_instruction(MLILStoreGlobal(5, MLILVar(x)))
        block.add_instruction(MLILStoreDeref(MLILAddressOf(MLILVar(x)), MLILConst(2)))
        block.add_instruction(MLILRet(MLILLoadGlobal(5)))

        RegGlobalValuePropagationPass().run(func)

        # If GLOBAL[5] wrongly cached "whatever x turns out to be," this would fold to 2.
        final_ret = block.instructions[-1]
        self.assertIsInstance(final_ret.value, MLILLoadGlobal)

    def test_positive_control_constant_propagation_still_works(self):
        '''The main case this pass exists for must still fold - closed-form caching should not
        regress plain constant propagation.'''
        func = MediumLevelILFunction('positive_control')
        block = func.create_block()
        block.add_instruction(MLILStoreReg(0, MLILConst(5)))
        block.add_instruction(MLILRet(MLILLoadReg(0)))

        RegGlobalValuePropagationPass().run(func)

        final_ret = block.instructions[-1]
        self.assertIsInstance(final_ret.value, MLILConst)
        self.assertEqual(final_ret.value.value, 5)


if __name__ == '__main__':
    unittest.main()
