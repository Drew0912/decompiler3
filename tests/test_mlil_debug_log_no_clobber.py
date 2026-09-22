#!/usr/bin/env python3
'''Unit tests for MediumLevelILCall.clobbers_registers - Step 11 (bug 4) of the LLIL/MLIL
hardening plan: a call proven to have no VM register/global side effects at all (the Falcom
debug.log translation) must not make generic SSA construction give every register, including
reg0, a fresh undefined pseudo-definition - that contradicts the translator's own documented
invariant that DEBUG_LOG leaves the result register alone.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MediumLevelILCall, MLILSetVar, MLILVar, MLILCall, MLILRet
from ir.mlil.mlil_ssa import SSAConstructor, MLILSetVarSSA


FUNC_START = 0x1000


def build_read_call_read(*, clobbers_registers: bool) -> MediumLevelILFunction:
    '''x = REG[0]; debug.log(REG[0]) [clobbers_registers flag under test]; y = REG[0]; return y'''
    func = MediumLevelILFunction('debug_log_clobber_test')
    block = func.create_block(start = FUNC_START)
    reg0 = func.get_or_create_register_var(0)
    x = func.get_or_create_local('x')
    y = func.get_or_create_local('y')

    block.add_instruction(MLILSetVar(x, MLILVar(reg0)))
    block.add_instruction(MLILCall('debug.log', [MLILVar(reg0)], clobbers_registers = clobbers_registers))
    block.add_instruction(MLILSetVar(y, MLILVar(reg0)))
    block.add_instruction(MLILRet(MLILVar(y)))

    return func


def find_def(block, var) -> MLILSetVarSSA:
    for inst in block.instructions:
        if isinstance(inst, MLILSetVarSSA) and inst.var.base_var == var:
            return inst

    raise AssertionError(f'no SSA definition found for {var.name!r}')


class TestDebugLogDoesNotClobberRegisters(unittest.TestCase):
    def test_register_read_after_a_non_clobbering_call_keeps_the_same_ssa_version(self):
        func = build_read_call_read(clobbers_registers = False)
        SSAConstructor(func).construct()

        block = func.basic_blocks[0]
        x_def = find_def(block, func.locals['x'])
        y_def = find_def(block, func.locals['y'])

        self.assertEqual(x_def.value.var.version, y_def.value.var.version,
                         'a call marked clobbers_registers=False must not create a new reg0 '
                         'version - both reads should see the exact same incoming value')

    def test_ordinary_call_still_clobbers_the_register(self):
        # Regression guard: the default (clobbers_registers=True) must keep today's
        # conservative behavior for every other call.
        func = build_read_call_read(clobbers_registers = True)
        SSAConstructor(func).construct()

        block = func.basic_blocks[0]
        x_def = find_def(block, func.locals['x'])
        y_def = find_def(block, func.locals['y'])

        self.assertNotEqual(x_def.value.var.version, y_def.value.var.version,
                            'an ordinary call must still clobber reg0 with an unknown value')

    def test_calls_own_output_register_is_not_also_given_a_pseudo_def(self):
        # Regression guard for _clobbered_reg_global_vars needing the still-plain output
        # variable: reg0 = f() must define reg0 exactly once (its own output), never a
        # second time via the generic "every other register/global" clobber list.
        func = MediumLevelILFunction('call_output_test')
        block = func.create_block(start = FUNC_START)
        reg0 = func.get_or_create_register_var(0)

        block.add_instruction(MLILCall('f', [], reg0))
        block.add_instruction(MLILRet(MLILVar(reg0)))

        SSAConstructor(func).construct()

        block = func.basic_blocks[0]
        call_inst = block.instructions[0]
        self.assertIsInstance(call_inst, MediumLevelILCall)
        self.assertEqual(call_inst.output.base_var, reg0, "the call's own output must be reg0, SSA-versioned")

        pseudo_defs = [inst for inst in block.instructions
                      if isinstance(inst, MLILSetVarSSA) and inst.var.base_var == reg0]
        self.assertEqual(len(pseudo_defs), 0,
                         'reg0 must not ALSO get a separate pseudo-def alongside being the '
                         "call's own output")


if __name__ == '__main__':
    unittest.main()
