#!/usr/bin/env python3
'''Unit tests for SCP parser'''

from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from io import BytesIO
from common import *
from falcom.ed9 import *
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.llil.llil import LowLevelILFunction
from ir.mlil import *
from ir.hlil import *
from codegen import *
import ast
import tempfile
import unittest
import struct


class TestScpValue(unittest.TestCase):
    '''Test ScpValue serialization and deserialization'''

    def test_raw_value(self):
        '''Test Raw type value'''
        # Raw value is stored as-is
        raw_val = 0x12345678
        val = ScpValue(RawInt(raw_val))

        # Serialize
        data = val.to_bytes()
        self.assertEqual(len(data), 4)

        # Deserialize
        fs = fileio.FileStream()
        fs.OpenMemory(data)
        val2 = ScpValue(fs = fs)
        self.assertEqual(val2.value, raw_val)
        self.assertEqual(val2.type, ScpValue.Type.Raw)

    def test_integer_value(self):
        '''Test Integer type value'''
        test_values = [0, 1, -1, 100, -100, 0x1FFFFFFF]  # 0x1FFFFFFF is safe max for 30-bit signed

        for test_val in test_values:
            with self.subTest(value = test_val):
                val = ScpValue(test_val)
                self.assertEqual(val.type, ScpValue.Type.Integer)

                # Serialize
                data = val.to_bytes()
                self.assertEqual(len(data), 4)

                # Check type bits (top 2 bits should be 01)
                endian = '<' if default_endian() == 'little' else '>'
                raw = struct.unpack(f'{endian}I', data)[0]
                type_bits = raw >> 30
                self.assertEqual(type_bits, ScpValue.Type.Integer)

                # Deserialize
                fs = fileio.FileStream()
                fs.OpenMemory(data)
                val2 = ScpValue(fs = fs)
                self.assertEqual(val2.value, test_val)
                self.assertEqual(val2.type, ScpValue.Type.Integer)

    def test_float_value(self):
        '''Test Float type value'''
        test_values = [0.0, 1.0, -1.0, 3.14159, -2.71828, 100.5]

        for test_val in test_values:
            with self.subTest(value = test_val):
                val = ScpValue(test_val)
                self.assertEqual(val.type, ScpValue.Type.Float)

                # Serialize
                data = val.to_bytes()
                self.assertEqual(len(data), 4)

                # Deserialize
                fs = fileio.FileStream()
                fs.OpenMemory(data)
                val2 = ScpValue(fs = fs)
                self.assertAlmostEqual(val2.value, test_val, places = 5)
                self.assertEqual(val2.type, ScpValue.Type.Float)

    def test_roundtrip(self):
        '''Test value roundtrip (serialize then deserialize)'''
        test_cases = [
            RawInt(0x12345678),  # Must have top 2 bits as 00 for Raw type
            42,
            -123,
            3.14159,
            -2.71828,
        ]

        for original_value in test_cases:
            with self.subTest(value = original_value):
                val1 = ScpValue(original_value)
                data = val1.to_bytes()

                fs = fileio.FileStream()
                fs.OpenMemory(data)
                val2 = ScpValue(fs = fs)

                self.assertEqual(val1.type, val2.type)
                if isinstance(original_value, float):
                    self.assertAlmostEqual(val1.value, val2.value, places = 5)
                else:
                    self.assertEqual(val1.value, val2.value)

    def test_string_value_serialize(self):
        '''Test String type cannot be serialized with to_bytes (not implemented)'''
        val = ScpValue("test string")
        self.assertEqual(val.type, ScpValue.Type.String)

        # String serialization is not implemented
        with self.assertRaises(NotImplementedError):
            val.to_bytes()

    def test_string_value_deserialize(self):
        '''Test String type deserialization'''
        endian = '<' if default_endian() == 'little' else '>'

        # Create a buffer with string data at offset 0x100
        buffer = BytesIO()
        buffer.write(b'\x00' * 0x100)  # Padding
        string_offset = buffer.tell()
        test_string = "TestFunction"
        buffer.write(test_string.encode('utf-8') + b'\x00')  # Null-terminated

        # Write ScpValue at beginning pointing to string
        buffer.seek(0)
        string_value = string_offset | (ScpValue.Type.String << 30)
        buffer.write(struct.pack(f'{endian}I', string_value))

        # Parse it
        buffer.seek(0)
        fs = fileio.FileStream()
        fs.OpenMemory(buffer.getvalue())
        # Set encoding to utf-8 to avoid mbcs encoding error on Linux
        fs._encoding = 'utf-8'
        val = ScpValue(fs = fs)

        self.assertEqual(val.type, ScpValue.Type.String)
        self.assertEqual(val.value, test_string)


class TestQuoteString(unittest.TestCase):
    '''Test quote_string escaping (falcom/ed9/disasm/ed9_optable.py PUSH_STR formatting)'''

    def test_round_trip(self):
        '''quote_string output must parse back to the original text via ast.literal_eval'''
        test_strings = [
            '\\n',              # literal backslash + n - the real corpus case (ai_chr0313_c10_e00.dat)
            '"',
            "'",
            '\n',
            '\r\n',
            '\t',
            '\x00',
            '\x1b[0m',
            '◆敵から距離を取る',  # real corpus text (ai1.0/ai_chr5004p.dat)
            'a\\',
            '',
        ]

        for text in test_strings:
            with self.subTest(text = text):
                self.assertEqual(ast.literal_eval(quote_string(text)), text)

    def test_backslash_n_escaped_not_interpreted(self):
        '''A literal backslash + n must not become a real newline'''
        self.assertEqual(quote_string('\\n'), '"\\\\n"')

    def test_non_ascii_kept_verbatim(self):
        '''Printable non-ASCII (Japanese game text) is never \\u-escaped'''
        text = '◆敵から距離を取る'  # real corpus text (ai1.0/ai_chr5004p.dat)
        self.assertIn('◆', quote_string(text))
        self.assertNotIn('\\u', quote_string(text))


class TestScpParser(unittest.TestCase):
    '''Test SCP parser against a real corpus file, through the full LLIL/MLIL/HLIL/TS pipeline.

    All outputs are written under a TemporaryDirectory, never beside the real corpus file - a
    previous version of this test wrote '.py'/'.llil.asm'/'.mlil.asm'/'.hlil.ts'/'.ts' next to
    the real .dat and appended to '.llil.dot' on every run, silently growing a 24MB+ file in the
    game data directory (gitignored, so `git status` never showed it).
    '''

    TEST_FILE = Path(__file__).parent.parent / 'script_en' / 'battle' / 'btlsys.dat'

    @classmethod
    def setUpClass(cls):
        if not cls.TEST_FILE.exists():
            raise unittest.SkipTest(f'Test file not found: {cls.TEST_FILE}')

        cls.llil_functions = {}
        cls.mlil_functions = {}
        cls.hlil_functions = {}

        with fileio.FileStream(str(cls.TEST_FILE), encoding = default_encoding()) as fs:
            cls.parser = ScpParser(fs, cls.TEST_FILE.name)
            cls.parser.parse()

            # disasm_all_functions seeks/reads from fs directly, so it must run before the stream closes
            cls.functions = cls.parser.disasm_all_functions()

            for func in cls.functions:
                llil_func = ED9VMLifter(parser = cls.parser).lift_function(func)
                cls.llil_functions[func.name] = llil_func

                mlil_func = convert_falcom_llil_to_mlil(llil_func, cls.parser, optimize = True)
                cls.mlil_functions[func.name] = mlil_func

                cls.hlil_functions[func.name] = convert_falcom_mlil_to_hlil(mlil_func, func)

    def test_header(self):
        self.assertIsNotNone(self.parser.header)
        self.assertGreater(self.parser.header.function_count, 0)

    def test_lift_to_llil(self):
        for func in self.functions:
            with self.subTest(function = func.name):
                self.assertIsInstance(self.llil_functions[func.name], LowLevelILFunction)

    def test_convert_to_mlil(self):
        for func in self.functions:
            with self.subTest(function = func.name):
                self.assertIsNotNone(self.mlil_functions[func.name])

    def test_convert_to_hlil(self):
        for func in self.functions:
            with self.subTest(function = func.name):
                self.assertIsNotNone(self.hlil_functions[func.name])

    def test_generate_typescript(self):
        for func in self.functions:
            with self.subTest(function = func.name):
                self.assertIsInstance(generate_typescript(self.hlil_functions[func.name]), str)

    def test_debug_output_writes_under_temp_dir_only(self):
        '''Regression guard: formatting/writing debug dumps must never touch the real corpus'''
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / self.TEST_FILE.name

            formatted_lines = list(self.parser.gen_python_header())
            llil_lines = []
            mlil_lines = []
            hlil_lines = []
            typescript_lines = []

            for func in self.functions:
                with self.subTest(function = func.name):
                    formatted_lines.extend(self.parser.format_function(func))
                    formatted_lines.append('')

                    llil_lines.extend(FalcomLLILFormatter.format_llil_function(self.llil_functions[func.name]))
                    llil_lines.append('')

                    mlil_lines.extend(MLILFormatter.format_function(self.mlil_functions[func.name]))
                    mlil_lines.append('')

                    hlil_lines.extend(HLILFormatter.format_function(self.hlil_functions[func.name]))
                    hlil_lines.append('')

                    typescript_lines.append(generate_typescript(self.hlil_functions[func.name]))
                    typescript_lines.append('')

            formatted_lines.extend(self.parser.gen_python_footer())

            out_file.with_suffix('.py').write_text('\n'.join(formatted_lines) + '\n', encoding = 'utf-8')
            out_file.with_suffix('.llil.asm').write_text('\n'.join(llil_lines) + '\n', encoding = 'utf-8')
            out_file.with_suffix('.mlil.asm').write_text('\n'.join(mlil_lines) + '\n', encoding = 'utf-8')
            out_file.with_suffix('.hlil.ts').write_text('\n'.join(hlil_lines) + '\n', encoding = 'utf-8')

            typescript_content = generate_typescript_header() + '\n'.join(typescript_lines) + '\n'
            out_file.with_suffix('.ts').write_text(typescript_content, encoding = 'utf-8')

            for suffix in ('.py', '.llil.asm', '.mlil.asm', '.hlil.ts', '.ts'):
                self.assertTrue(out_file.with_suffix(suffix).exists())


if __name__ == '__main__':
    unittest.main(buffer = False, defaultTest = 'TestScpParser')
