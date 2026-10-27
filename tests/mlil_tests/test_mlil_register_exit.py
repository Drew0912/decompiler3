#!/usr/bin/env python3
"""A register a function writes and its return leaves is the caller's to read after the call (registers outlive a
function, as globals do): MLIL keeps the write although nothing in the function reads it, on every arm that writes
it. The result register's write is the return's value, not kept beside it; a call between the write and the return
leaves the callee's value, and a loop of calls merges only callees' values, so nothing of the function's to keep"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import RESULT_REG_INDEX
from ir.mlil.mlil import MLILRet, MLILSetVar
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee

REG_INDEX = 5
LEFT_VALUE = 7
ARM_VALUES = (1, 2)
GLOBAL_READ, GLOBAL_WRITTEN = 1, 0
TAIL_CALL_ARGC = 1


def return_nothing(asm: Asm):
    asm.push_raw(0); asm.set_reg(RESULT_REG_INDEX); asm.ret()


def mlil_of(asm: Asm):
    _, llil = lift_asm(asm, others=(returning_callee(),))
    return convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=False)


def writes_of(mlil, index: int) -> list[str]:
    """The values MLIL assigns to register index, in block order"""
    register = mlil.register_vars.get(index)
    return [str(inst.value) for block in mlil.basic_blocks for inst in block.instructions
            if isinstance(inst, MLILSetVar) and register is not None and inst.var is register]


class TestRegisterLeftForTheCaller(unittest.TestCase):

    def test_write_before_the_return(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        return_nothing(asm)
        self.assertEqual(writes_of(mlil_of(asm), REG_INDEX), [str(LEFT_VALUE)])

    def test_each_arm_of_a_join_keeps_its_write(self):
        asm = Asm()
        asm.load_global(GLOBAL_READ); asm.jz('else')
        asm.push_int(ARM_VALUES[0]); asm.set_reg(REG_INDEX); asm.jmp('end')
        asm.label('else'); asm.push_int(ARM_VALUES[1]); asm.set_reg(REG_INDEX)
        asm.label('end'); return_nothing(asm)
        self.assertEqual(sorted(writes_of(mlil_of(asm), REG_INDEX)), [str(value) for value in ARM_VALUES])

    def test_result_register_is_the_return_value_only(self):
        asm = Asm()
        return_nothing(asm)
        mlil = mlil_of(asm)
        self.assertEqual(writes_of(mlil, RESULT_REG_INDEX), [])
        self.assertTrue(any(isinstance(inst, MLILRet) for block in mlil.basic_blocks for inst in block.instructions))

    def test_call_between_write_and_return_leaves_the_callee_value(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.call(CALLEE_ID); asm.label('back')
        return_nothing(asm)
        self.assertEqual(writes_of(mlil_of(asm), REG_INDEX), [])

    def test_loop_of_calls_before_the_return_writes_nothing(self):
        """GLOBAL = reg; while GLOBAL': callee(); return: at the return the register holds the incoming value or a
        callee's, merged at the loop header, never a value of the function's: nothing to keep, no copy"""
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_WRITTEN)
        asm.label('head'); asm.load_global(GLOBAL_READ); asm.jz('done')
        asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.call(CALLEE_ID); asm.label('back')
        asm.jmp('head')
        asm.label('done'); return_nothing(asm)
        self.assertEqual(writes_of(mlil_of(asm), REG_INDEX), [])

    def test_tail_call_argument_passed_through_a_register(self):
        """reg = x; GET_REG; CALL_SCRIPT_NO_RETURN, the shape a tail call passes its argument copy in: the register
        is read once, by the call, and the call's own clobber is what the return leaves. Dead-code elimination drops
        the unread clobber pseudo-definition, so the call itself must stop the walk back to the write"""
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
        asm.get_reg(REG_INDEX); asm.call_script_no_return(TAIL_CALL_ARGC)
        self.assertEqual(writes_of(mlil_of(asm), REG_INDEX), [])


if __name__ == '__main__':
    unittest.main()
