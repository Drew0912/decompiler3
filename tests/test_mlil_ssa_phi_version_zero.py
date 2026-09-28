#!/usr/bin/env python3
'''Unit tests for SSADeconstructor._eliminate_phi_nodes's version-0 skip: a parameter/register/
global's SSA version 0 is a real value already live at function entry, not an undefined initial
value like a plain local's version 0 - skipping the phi-source copy for it can drop that value on
the path where the variable was never reassigned.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILGoto
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILPhi, SSADeconstructor


def make_func(name: str) -> MediumLevelILFunction:
    return MediumLevelILFunction(name, 0)


def build_if_no_else_merge(dest_var: MLILVariableSSA, then_source: MLILVariableSSA,
                           else_source: MLILVariableSSA):
    '''then_block sets the variable and falls to merge_block; else_block leaves it untouched
    and falls to merge_block too - both predecessors have a single outgoing edge each, so
    _phi_copy_block inserts directly into them (no critical-edge split needed).'''
    then_block = MediumLevelILBasicBlock(0, label = 'then_block')
    else_block = MediumLevelILBasicBlock(1, label = 'else_block')
    merge_block = MediumLevelILBasicBlock(2, label = 'merge_block')

    then_block.instructions = [
        MLILSetVarSSA(then_source, MLILConst(42)),
        MLILGoto(merge_block),
    ]
    then_block.add_outgoing_edge(merge_block)

    else_block.instructions = [
        MLILGoto(merge_block),  # the variable is untouched here - stays at its entry version
    ]
    else_block.add_outgoing_edge(merge_block)

    merge_block.instructions = [
        MLILPhi(dest = dest_var, sources = [(then_source, then_block), (else_source, else_block)]),
    ]

    return then_block, else_block, merge_block


class TestEliminatePhiNodesRegisterVersionZero(unittest.TestCase):
    '''A register's version 0 is the caller's real incoming value - the phi-source copy must
    not be skipped just because the register was never reassigned on that path.'''

    def test_register_phi_source_at_version_zero_gets_a_copy(self):
        func = make_func('reg_phi_test')
        reg0 = func.get_or_create_register_var(0)

        reg0_v0 = MLILVariableSSA(reg0, 0)
        reg0_v1 = MLILVariableSSA(reg0, 1)
        reg0_v2 = MLILVariableSSA(reg0, 2)  # phi destination

        then_block, else_block, merge_block = build_if_no_else_merge(reg0_v2, reg0_v1, reg0_v0)
        func.basic_blocks = [then_block, else_block, merge_block]

        SSADeconstructor(func)._eliminate_phi_nodes()

        self.assertEqual(len(else_block.instructions), 2,
                         'else_block must gain a copy carrying reg0 forward into the phi destination')
        copy_inst = else_block.instructions[0]
        self.assertIsInstance(copy_inst, MLILSetVarSSA)
        self.assertEqual(copy_inst.var, reg0_v2)
        self.assertIsInstance(copy_inst.value, MLILVarSSA)
        self.assertEqual(copy_inst.value.var, reg0_v0)


class TestEliminatePhiNodesGlobalVersionZero(unittest.TestCase):
    '''Same defect, same fix, for a global - its version 0 is the persisted store's live value,
    not undefined (the SSA construction side already treats parameters and globals as
    "defined at function entry" identically - see _rename_variables_iterative).'''

    def test_global_phi_source_at_version_zero_gets_a_copy(self):
        func = make_func('global_phi_test')
        global0 = func.get_or_create_global_var(0)

        global0_v0 = MLILVariableSSA(global0, 0)
        global0_v1 = MLILVariableSSA(global0, 1)
        global0_v2 = MLILVariableSSA(global0, 2)

        then_block, else_block, merge_block = build_if_no_else_merge(global0_v2, global0_v1, global0_v0)
        func.basic_blocks = [then_block, else_block, merge_block]

        SSADeconstructor(func)._eliminate_phi_nodes()

        self.assertEqual(len(else_block.instructions), 2,
                         'else_block must gain a copy carrying the global forward into the phi destination')
        copy_inst = else_block.instructions[0]
        self.assertEqual(copy_inst.var, global0_v2)
        self.assertEqual(copy_inst.value.var, global0_v0)


class TestEliminatePhiNodesLocalVersionZeroStillSkipped(unittest.TestCase):
    '''A plain local's version 0 is genuinely undefined (unlike a parameter/register/global) -
    this case must keep being skipped, unaffected by widening the exemption.'''

    def test_local_phi_source_at_version_zero_still_skipped(self):
        func = make_func('local_phi_test')
        local = MLILVariable('temp')
        func.locals['temp'] = local

        local_v0 = MLILVariableSSA(local, 0)
        local_v1 = MLILVariableSSA(local, 1)
        local_v2 = MLILVariableSSA(local, 2)

        then_block, else_block, merge_block = build_if_no_else_merge(local_v2, local_v1, local_v0)
        func.basic_blocks = [then_block, else_block, merge_block]

        SSADeconstructor(func)._eliminate_phi_nodes()

        self.assertEqual(len(else_block.instructions), 1,
                         'a plain local version-0 source must still be skipped, unlike a register/global')
        self.assertIsInstance(else_block.instructions[0], MLILGoto)


if __name__ == '__main__':
    unittest.main()
