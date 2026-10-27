#!/usr/bin/env python3
"""A loop at the very start of a function: its header is the entry block, which the back edge enters too. SSA
construction puts an empty block in front of it, so the header's phi exists and the values the loop carries survive
(without it the body's writes to a parameter were dropped: `while (arg1 != 0) {}`, an endless loop)"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen import generate_typescript
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import RESULT_REG_INDEX
from ir.llil.llil import WORD_SIZE
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import Asm

PARAMETERS = 1
NEW_VALUE = 5
GLOBAL_WRITTEN = 0


def return_nothing(asm: Asm):
    asm.pop(PARAMETERS * WORD_SIZE); asm.push_raw(0); asm.set_reg(RESULT_REG_INDEX); asm.ret()


def typescript_of(asm: Asm) -> str:
    _, llil = lift_asm(asm, argc=PARAMETERS)
    mlil = convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=False)
    return generate_typescript(convert_falcom_mlil_to_hlil(mlil))


def loop_on_the_parameter(body) -> Asm:
    """f(a): while a: <body>; ...: the loop test is the function's first instruction"""
    asm = Asm()
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.jz('done')
    body(asm); asm.jmp('head')
    asm.label('done')
    return asm


class TestLoopAtTheFunctionStart(unittest.TestCase):

    def test_parameter_decremented_in_the_loop(self):
        def decrement(asm: Asm):
            asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.sub(); asm.pop_to(-WORD_SIZE)
        asm = loop_on_the_parameter(decrement)
        return_nothing(asm)
        self.assertIn('arg1 = arg1 - 1;', typescript_of(asm))

    def test_parameter_written_in_the_loop_read_after_it(self):
        def overwrite(asm: Asm):
            asm.push_int(NEW_VALUE); asm.pop_to(-WORD_SIZE)
        asm = loop_on_the_parameter(overwrite)
        asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_WRITTEN)
        return_nothing(asm)
        ts = typescript_of(asm)
        self.assertIn(f'arg1 = {NEW_VALUE};', ts)
        self.assertIn(f'GLOBALS[{GLOBAL_WRITTEN}] = arg1;', ts)


if __name__ == '__main__':
    unittest.main()
