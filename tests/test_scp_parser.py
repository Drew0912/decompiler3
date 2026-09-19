#!/usr/bin/env python3
'''Unit tests for SCP parser'''

from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml import *
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
    '''Test SCP parser'''

    def test_parser_with_real_file(self):
        '''Test parser with real SCP file if available'''

        # ED9_DATA_DIR = Path(r'D:\Dev\decompiler3\script_en\scena')
        # ED9_DATA_DIR = Path(r'D:\Dev\decompiler3\script_en\ai')
        ED9_DATA_DIR = Path(r'D:\Dev\decompiler3\script_en\battle')

        # test_file = Path(__file__).parent / 'mp2000_ev.dat'
        test_file = Path(__file__).parent / 'debug.dat'
        # test_file = Path(__file__).parent / 'mp3010_01.dat'
        # test_file = ED9_DATA_DIR / 'c0600.dat'

        # test_file = ED9_DATA_DIR / 'e2000.dat'
        # test_file = ED9_DATA_DIR / 'ai_chr0100_e00.dat'
        test_file = ED9_DATA_DIR / 'btlsys.dat'
        # test_file = ED9_DATA_DIR / 'ai_chr0118_e00.dat'
        # test_file = ED9_DATA_DIR / 'btl_EV_01_07_00.dat'

        if not test_file.exists():
            self.skipTest(f'Test file not found: {test_file}')

        with fileio.FileStream(str(test_file), encoding = default_encoding()) as fs:
            parser = ScpParser(fs, test_file.name)
            parser.parse()

            print(parser.header)

            # Check header was parsed
            self.assertIsNotNone(parser.header)
            self.assertGreater(parser.header.function_count, 0)

            # Test disassembly and formatting
            disassembled_functions = parser.disasm_all_functions(
                # filter_func = lambda f: f.name == 'TestCitySet'
            )

            formatted_lines = []
            llil_lines = []
            mlil_lines = []
            hlil_lines = []
            typescript_lines = []

            formatted_lines.extend(parser.gen_python_header())

            # Generate LLIL CFG
            llil_cfg_path = test_file.with_suffix('.llil.dot')

            # Generate MLIL CFG
            mlil_cfg_path = test_file.with_suffix('.mlil.dot')

            # Print formatted functions
            print('\n=== Disassembly ===\n')
            for func in disassembled_functions:
                print(f'{func} @ 0x{func.offset:08X}')

                formatted_lines.extend(parser.format_function(func))
                formatted_lines.append('')

                # Generate LLIL
                lifter = ED9VMLifter(parser = parser)
                llil_func = lifter.lift_function(func)
                self.assertIsInstance(llil_func, LowLevelILFunction)

                llil_lines.extend(FalcomLLILFormatter.format_llil_function(llil_func))
                llil_lines.append('')

                with llil_cfg_path.open("a", encoding = 'utf-8') as f:
                    f.write(FalcomLLILFormatter.to_dot(llil_func))


                # llil_cfg_path.write_text(FalcomLLILFormatter.to_dot(llil_func), encoding = 'utf-8')

                # Generate MLIL from LLIL (with parser for type signatures)
                mlil_func = convert_falcom_llil_to_mlil(llil_func, parser, optimize=True)
                mlil_lines.extend(MLILFormatter.format_function(mlil_func))
                mlil_lines.append('')

                # mlil_cfg_path.write_text(MLILFormatter.to_dot(mlil_func), encoding = 'utf-8')

                # Generate HLIL from MLIL with Falcom-specific type information
                hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

                # Debug output: HLIL text
                hlil_lines.extend(HLILFormatter.format_function(hlil_func))
                hlil_lines.append('')

                # Final output: TypeScript code
                typescript_code = generate_typescript(hlil_func)
                typescript_lines.append(typescript_code)
                typescript_lines.append('')

            formatted_lines.extend(parser.gen_python_footer())
            vmpy_path = test_file.with_suffix('.py')
            vmpy_path.write_text('\n'.join(formatted_lines) + '\n', encoding = 'utf-8')

            llil_path = test_file.with_suffix('.llil.asm')
            llil_path.write_text('\n'.join(llil_lines) + '\n', encoding = 'utf-8')

            # # Generate LLIL CFG
            # llil_cfg_path = test_file.with_suffix('.llil.dot')
            # llil_cfg_path.write_text(FalcomLLILFormatter.to_dot(llil_func), encoding = 'utf-8')

            mlil_path = test_file.with_suffix('.mlil.asm')
            mlil_path.write_text('\n'.join(mlil_lines) + '\n', encoding = 'utf-8')

            # # Generate MLIL CFG
            # mlil_cfg_path = test_file.with_suffix('.mlil.dot')
            # mlil_cfg_path.write_text(MLILFormatter.to_dot(mlil_func), encoding = 'utf-8')

            # HLIL debug output (IR text)
            hlil_path = test_file.with_suffix('.hlil.ts')
            hlil_path.write_text('\n'.join(hlil_lines) + '\n', encoding = 'utf-8')

            # TypeScript final output
            typescript_path = test_file.with_suffix('.ts')
            typescript_content = generate_typescript_header() + '\n'.join(typescript_lines) + '\n'
            typescript_path.write_text(typescript_content, encoding = 'utf-8')


if __name__ == '__main__':
    unittest.main(buffer = False, defaultTest = 'TestScpParser')
