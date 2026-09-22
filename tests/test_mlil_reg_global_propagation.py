#!/usr/bin/env python3
'''Unit tests for RegGlobalValuePropagator's worklist-fixpoint and constant-equality bugs -
Step 9 of the LLIL/MLIL hardening plan (bugs 2 and 6; bugs 1/3/4/5 need a design decision
between candidate fixes and are not covered here).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MLILConst, MLILGoto, MLILIf, MLILCall, MLILLoadGlobal,
    MLILStoreGlobal, MLILRet,
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


if __name__ == '__main__':
    unittest.main()
