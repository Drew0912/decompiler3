#!/usr/bin/env python3
"""Unit tests for BitwiseHexPass: a bitwise operation on a value prints its constant operand in hex, under a ~ too,
and a union of single-bit flags there; any other expression made only of constants prints as written. .mlil.asm,
.hlil.ts and .ts agree."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen import generate_typescript
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.assembler.stack_effects import RESULT_REGISTER
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from ir.hlil.hlil_formatter import HLILFormatter
from ir.mlil.mlil_formatter import MLILFormatter
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import REG_INDEX, Asm


FLAG = 0x800
BIT = 0x10
LOW_FLAG = 1
HIGH_FLAG = 0x8000
MIXED_VALUE = 119       # several bits: no flag


def outputs(push_value) -> dict[str, str]:
    """The three outputs of a function returning the value push_value(asm) pushes"""
    asm = Asm()
    push_value(asm)
    asm.set_reg(RESULT_REGISTER); asm.ret()
    _, llil_func = lift_asm(asm)
    mlil_func = convert_falcom_llil_to_mlil_stack(llil_func)
    hlil_func = convert_falcom_mlil_to_hlil(mlil_func)
    return {'.mlil.asm': '\n'.join(MLILFormatter.format_function(mlil_func)),
            '.hlil.ts': '\n'.join(HLILFormatter.format_function(hlil_func)),
            '.ts': generate_typescript(hlil_func)}


class TestBitwiseHex(unittest.TestCase):
    def assert_every_output_has(self, push_value, expected: str):
        for output, text in outputs(push_value).items():
            with self.subTest(output):
                self.assertIn(expected, text)

    def test_mask_on_a_value(self):
        def value_and_mask(asm: Asm):
            asm.get_reg(REG_INDEX); asm.push_int(FLAG); asm.bitwise_and()

        def mask_and_value(asm: Asm):
            asm.push_int(FLAG); asm.get_reg(REG_INDEX); asm.bitwise_and()

        for push_value, expected in ((value_and_mask, '& 0x00000800'), (mask_and_value, '0x00000800 &')):
            with self.subTest(push_value.__name__):
                self.assert_every_output_has(push_value, expected)

    def test_inverted_mask(self):
        def push_value(asm: Asm):
            asm.get_reg(REG_INDEX); asm.push_int(BIT); asm.not_(); asm.bitwise_and()

        self.assert_every_output_has(push_value, '& ~0x00000010')

    def test_constants_alone_print_as_written(self):
        def push_value(asm: Asm):
            asm.push_int(LOW_FLAG); asm.push_int(HIGH_FLAG); asm.bitwise_or()

        self.assert_every_output_has(push_value, f'{LOW_FLAG} | {HIGH_FLAG}')

    def test_flag_union_on_a_value(self):
        """Single bits only print in hex: a union with any other value prints as written"""
        def push_value(flags: tuple[int, int]):
            def push(asm: Asm):
                asm.get_reg(REG_INDEX); asm.push_int(flags[0]); asm.push_int(flags[1]); asm.bitwise_or()
                asm.bitwise_and()
            return push

        for flags, expected in (((LOW_FLAG, HIGH_FLAG), '& (0x00000001 | 0x00008000)'),
                                ((MIXED_VALUE, HIGH_FLAG), f'& ({MIXED_VALUE} | {HIGH_FLAG})')):
            with self.subTest(flags=flags):
                self.assert_every_output_has(push_value(flags), expected)


if __name__ == '__main__':
    unittest.main()
