#!/usr/bin/env python3
"""A POPN statement around a call's result (the Codex plan review's five cases): the call-result passes and the folder
never step over it, as they never stepped over a call. A call read only by the POPN folds into it; one read again
later stays a statement; a POPN between a call and its reader keeps the call apart; a POPN reading the result register
keeps the store before it; an if arm holding only a POPN stays."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from ir.hlil.hlil_formatter import HLILFormatter
from tests.shared.llil_utils import lift_asm
from tests.shared.logic_check_functions import GLOBAL_A, GLOBAL_B, MESSAGE, call, return_nothing
from tests.shared.scp_asm import Asm, returning_callee

STORED = 5


def hlil_lines(asm: Asm) -> list[str]:
    """asm's HLIL text, beside a callee of no parameters"""
    _, llil = lift_asm(asm, others=(returning_callee(0),))
    hlil = convert_falcom_mlil_to_hlil(convert_falcom_llil_to_mlil_stack(llil))
    return [line.strip() for line in HLILFormatter.format_function(hlil) if line.strip()]


class TestPopnAroundACallResult(unittest.TestCase):
    def test_unrelated_popn_between_the_call_and_its_reader(self):
        asm = Asm()
        call(asm, 'after'); asm.push_str(MESSAGE); asm.popn(1); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)

        self.assertEqual(hlil_lines(asm)[1:5], [
            'var t1', 't1 = callee();', f'POPN("{MESSAGE}");', f'GLOBALS[{GLOBAL_A}] = t1;',
        ])

    def test_result_popped_by_the_popn_folds_into_it(self):
        asm = Asm()
        call(asm, 'after'); asm.get_reg(0); asm.push_str(MESSAGE); asm.popn(2)
        return_nothing(asm)

        self.assertEqual(hlil_lines(asm)[1:2], [f'POPN("{MESSAGE}", callee());'])

    def test_result_popped_and_read_again_stays_a_statement(self):
        asm = Asm()
        call(asm, 'after'); asm.get_reg(0); asm.push_str(MESSAGE); asm.popn(2)
        asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)

        self.assertEqual(hlil_lines(asm)[1:5], [
            'var t1', 't1 = callee();', f'POPN("{MESSAGE}", t1);', f'GLOBALS[{GLOBAL_A}] = t1;',
        ])

    def test_popn_reading_the_result_register_keeps_the_store_before_the_return(self):
        asm = Asm()
        asm.push_int(STORED); asm.set_reg(0); asm.get_reg(0); asm.popn(1); asm.ret()

        self.assertEqual(hlil_lines(asm)[1:4], [f'REGS[0] = {STORED};', 'POPN(REGS[0]);', 'return REGS[0];'])

    def test_if_arm_holding_only_a_popn_stays(self):
        asm = Asm()
        asm.load_global(GLOBAL_B); asm.jz('else'); asm.push_str(MESSAGE); asm.popn(1); asm.label('else')
        return_nothing(asm)

        self.assertEqual(hlil_lines(asm)[1:4], [f'if (GLOBALS[{GLOBAL_B}] != 0) {{', f'POPN("{MESSAGE}");', '}'])


if __name__ == '__main__':
    unittest.main()
