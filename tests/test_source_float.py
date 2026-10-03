#!/usr/bin/env python3
'''Floats in the IR outputs (.llil.asm, .mlil.asm, .hlil.ts, .ts) print the .py's spelling: the lifter keeps the
exact decoded value as a SourceFloat carrying the text. A plain float prints its exact repr.'''

import copy
import math
from pathlib import Path
import pickle
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from codegen.typescript import TypeScriptGenerator
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter
from falcom.ed9.parser.types_scp import ScpValue
from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_writer_helper import *
from ir.core import SourceFloat, constant_values_equal
from ir.hlil import HLILConst
from ir.hlil.hlil_formatter import HLILFormatter
from ir.llil.llil import WORD_SIZE, LowLevelILConst, LowLevelILStackStore
from ir.mlil.mlil import MLILConst
from ir.mlil.mlil_ssa_optimizer import SSAOptimizer
from scp_writer_test_utils import fresh_writer

STORED_0_3 = 0.2999999523162842     # what 0.3 decodes to
WORD_0_3   = 0x8FA66666


class TestSourceFloat(unittest.TestCase):
    def test_prints_its_text_and_keeps_the_exact_value(self):
        value = SourceFloat(STORED_0_3, '0.3')

        self.assertEqual(str(value), '0.3')
        self.assertEqual(f'{value}', '0.3')
        self.assertEqual(repr(value), repr(STORED_0_3))

    def test_without_text_prints_the_exact_value(self):
        self.assertEqual(str(SourceFloat(STORED_0_3)), repr(STORED_0_3))

    def test_arithmetic_gives_a_plain_float(self):
        value = SourceFloat(STORED_0_3, '0.3')
        for result in (value * 2, -value, value + 0):
            with self.subTest(result = result):
                self.assertIs(type(result), float)

    def test_copies_keep_the_text(self):
        value = SourceFloat(STORED_0_3, '0.3')
        for result in (copy.copy(value), copy.deepcopy(value), pickle.loads(pickle.dumps(value))):
            with self.subTest(result = result):
                self.assertIs(type(result), SourceFloat)
                self.assertEqual(str(result), '0.3')


class TestLiftedFloat(unittest.TestCase):
    def test_decoded_float_keeps_its_value_and_gets_the_py_text(self):
        value = ED9VMLifter._source_value(ScpValue().from_value(WORD_0_3).value)

        self.assertIs(type(value), SourceFloat)
        self.assertEqual(value.hex(), STORED_0_3.hex())
        self.assertEqual(str(value), '0.3')

    def test_other_values_stay_as_they_are(self):
        for value in (1, math.inf):
            with self.subTest(value = value):
                self.assertIs(ED9VMLifter._source_value(value), value)


class TestPlainFloatPrintsExactly(unittest.TestCase):
    '''A float without source text prints its exact repr: no rounding, never int-looking'''

    def test_llil_mlil_hlil_ts(self):
        for value, text in ((STORED_0_3, '0.2999999523162842'), (1.0, '1.0'), (1e-07, '1e-07')):
            with self.subTest(value = value):
                self.assertEqual(str(LowLevelILConst(value)), text)
                self.assertEqual(str(MLILConst(value)), text)
                self.assertEqual(HLILFormatter._format_expr(HLILConst(value)), text)
                self.assertEqual(TypeScriptGenerator._format_expr(HLILConst(value)), text)

    def test_non_finite_values(self):
        # TS has no literal for them; .hlil.ts is a listing and keeps Python's spelling
        for value, ts, hlil in ((math.inf, 'Infinity', 'inf'), (-math.inf, '-Infinity', '-inf'),
                                (math.nan, 'NaN', 'nan')):
            with self.subTest(value = value):
                self.assertEqual(TypeScriptGenerator._format_expr(HLILConst(value)), ts)
                self.assertEqual(TypeScriptGenerator._format_default_value(value), ts)
                self.assertEqual(HLILFormatter._format_expr(HLILConst(value)), hlil)


class TestConstantIdentity(unittest.TestCase):
    def test_signed_zeros_are_different_constants(self):
        # Different stored words: merging them would print one spelling for both
        self.assertFalse(constant_values_equal(0.0, -0.0))
        self.assertTrue(constant_values_equal(math.nan, math.nan))

    def test_source_float_merges_only_with_the_same_text(self):
        value = SourceFloat(1.0, '1.0')

        self.assertTrue(constant_values_equal(value, SourceFloat(1.0, '1.0')))
        self.assertFalse(constant_values_equal(value, SourceFloat(1.0, '1e0')))
        self.assertFalse(constant_values_equal(value, 1.0))

    def test_optimizer_sees_a_changed_text_as_a_change(self):
        key = SSAOptimizer._structural_key(SourceFloat(STORED_0_3, '0.3'))
        for other in (STORED_0_3, SourceFloat(STORED_0_3), SourceFloat(STORED_0_3, '0.30')):
            with self.subTest(other = repr(other)):
                self.assertNotEqual(key, SSAOptimizer._structural_key(other))


class TestLLILBitsComment(unittest.TestCase):
    def test_only_a_source_float_shows_bits(self):
        source = LowLevelILStackStore(LowLevelILConst(SourceFloat(27.199996948242188, '27.2')), slot_index = 5)
        plain = LowLevelILStackStore(LowLevelILConst(27.199996948242188), slot_index = 5)

        self.assertEqual(FalcomLLILFormatter._format_simplified(source),
                         ['STACK[sp] = 27.2 ; [5] f32 0x41D99998, raw 0x90766666'])
        self.assertEqual(FalcomLLILFormatter._format_simplified(plain), ['STACK[sp] = 27.199996948242188 ; [5]'])


class TestDecompiledFloats(unittest.TestCase):
    '''End to end: compiled floats come back in every IR output spelled as in the .py'''

    @classmethod
    def setUpClass(cls):
        fresh_writer()
        with tempfile.TemporaryDirectory() as tmp:
            dat = Path(tmp) / 'floats.dat'
            writer = create_scp_writer(str(dat))

            @writer.LLILCode()
            def Short(arg1: Nullable32 = 0.2):
                PUSH_FLOAT(0.033299997448921204)
                SET_REG(0)
                POP(WORD_SIZE)
                RETURN()

            @writer.LLILCode()
            def Exact():
                # Rounded to 3 decimals this printed 60.0, a different word
                PUSH_FLOAT(60.000030517578125)
                SET_REG(0)
                RETURN()

            @writer.LLILCode()
            def Negative():
                PUSH_FLOAT(-2738.1494140625)
                SET_REG(0)
                RETURN()

            writer.run({'Short': Short, 'Exact': Exact, 'Negative': Negative})

            config = ScenaDecompileConfig()
            config.output_dir = Path(tmp) / 'out'
            config.write_llil_asm = True
            config.write_hlil_ts = True
            process_file(dat, config)
            out = config.output_dir / dat.stem
            cls.outputs = {suffix: (out / f'{dat.stem}{suffix}').read_text(encoding = 'utf-8')
                           for suffix in ('.llil.asm', '.mlil.asm', '.hlil.ts', '.ts')}

    def test_every_output_prints_the_py_text(self):
        for suffix, text in self.outputs.items():
            for literal in ('0.0333', '60.00003', '-2738.15'):
                with self.subTest(output = suffix, literal = literal):
                    self.assertRegex(text, rf'(?<![\d.]){re.escape(literal)}(?![\d])')

    def test_default_prints_its_text(self):
        self.assertIn('arg1: number = 0.2)', self.outputs['.ts'])

    def test_llil_push_shows_the_bits(self):
        self.assertIn(ScpValue.float_bits_text(0.033299997448921204), self.outputs['.llil.asm'])


if __name__ == '__main__':
    unittest.main()
