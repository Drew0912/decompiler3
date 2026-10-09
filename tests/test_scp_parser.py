#!/usr/bin/env python3
'''Unit tests for SCP parser'''

from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from io import BytesIO
from common import *
from falcom.ed9 import *
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


if __name__ == '__main__':
    unittest.main(buffer = False)
