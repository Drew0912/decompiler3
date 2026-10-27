#!/usr/bin/env python3
"""A register a function writes and its return leaves is the caller's to read after the call (registers outlive a
function, as globals do): SSA construction stores it before the return, so the .ts writes the register itself
(`REGS[n] = v`), not a local, on every arm that writes it. The result register's write is the return's value, not
stored beside it; a call between the write and the return leaves the callee's value, and a loop of calls merges only
callees' values, so nothing of the function's to store"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen import generate_typescript
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import RESULT_REG_INDEX
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee

REG_INDEX = 5
LEFT_VALUE = 7
ARM_VALUES = (1, 2)
GLOBAL_READ, GLOBAL_WRITTEN = 1, 0
TAIL_CALL_ARGC = 1
REGISTER = f'REGS[{REG_INDEX}]'
LOCAL = f'reg{REG_INDEX}'


def return_nothing(asm: Asm):
    asm.push_raw(0); asm.set_reg(RESULT_REG_INDEX); asm.ret()


def typescript_of(asm: Asm) -> str:
    _, llil = lift_asm(asm, others=(returning_callee(),))
    mlil = convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=False)
    return generate_typescript(convert_falcom_mlil_to_hlil(mlil))


def call_callee(asm: Asm):
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.call(CALLEE_ID); asm.label('back')


class TestRegisterLeftForTheCaller(unittest.TestCase):

    def test_write_before_the_return(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        return_nothing(asm)
        ts = typescript_of(asm)
        self.assertIn(f'{REGISTER} = {LEFT_VALUE};', ts)
        self.assertNotIn(LOCAL, ts)

    def test_each_arm_of_a_join_writes_the_register(self):
        asm = Asm()
        asm.load_global(GLOBAL_READ); asm.jz('else')
        asm.push_int(ARM_VALUES[0]); asm.set_reg(REG_INDEX); asm.jmp('end')
        asm.label('else'); asm.push_int(ARM_VALUES[1]); asm.set_reg(REG_INDEX)
        asm.label('end'); return_nothing(asm)
        ts = typescript_of(asm)
        for value in ARM_VALUES:
            self.assertIn(f'{LOCAL} = {value};', ts)
        self.assertIn(f'{REGISTER} = {LOCAL};', ts)

    def test_arm_that_does_not_write_keeps_the_incoming_value(self):
        asm = Asm()
        asm.load_global(GLOBAL_READ); asm.jz('end')
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        asm.label('end'); return_nothing(asm)
        ts = typescript_of(asm)
        self.assertIn(f'{LOCAL} = {LEFT_VALUE};', ts)
        self.assertIn(f'{LOCAL} = {REGISTER};', ts)
        self.assertIn(f'{REGISTER} = {LOCAL};', ts)

    def test_result_register_is_the_return_value_only(self):
        asm = Asm()
        return_nothing(asm)
        ts = typescript_of(asm)
        self.assertIn('return 0;', ts)
        self.assertNotIn(f'REGS[{RESULT_REG_INDEX}]', ts)
        self.assertNotIn(f'reg{RESULT_REG_INDEX}', ts)

    def test_call_between_write_and_return_leaves_the_callee_value(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        call_callee(asm)
        return_nothing(asm)
        ts = typescript_of(asm)
        self.assertNotIn(REGISTER, ts)
        self.assertNotIn(LOCAL, ts)

    def test_loop_of_calls_before_the_return_writes_nothing(self):
        """GLOBAL = reg; while GLOBAL': callee(); return: at the return the register holds the incoming value or a
        callee's, merged at the loop header, never a value of the function's"""
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_WRITTEN)
        asm.label('head'); asm.load_global(GLOBAL_READ); asm.jz('done')
        call_callee(asm); asm.jmp('head')
        asm.label('done'); return_nothing(asm)
        ts = typescript_of(asm)
        self.assertNotIn(f'{REGISTER} =', ts)
        self.assertNotIn(LOCAL, ts)

    def test_tail_call_argument_passed_through_a_register(self):
        """reg = x; GET_REG; CALL_SCRIPT_NO_RETURN, the shape a tail call passes its argument copy in: the call's own
        clobber is what the return leaves, so the register is only the call's argument"""
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        asm.get_reg(REG_INDEX); asm.call_script_no_return(TAIL_CALL_ARGC)
        ts = typescript_of(asm)
        self.assertNotIn(REGISTER, ts)
        self.assertNotIn(LOCAL, ts)


if __name__ == '__main__':
    unittest.main()
