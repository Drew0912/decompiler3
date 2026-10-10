#!/usr/bin/env python3
'''Unit tests for ScpValue encoding, quote_string and the function-name hash (CRC-32 table)'''

import ast
import binascii
from pathlib import Path
import struct
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from common import *
from falcom.ed9 import *
from falcom.ed9.parser.crc32 import crc32_table, hash_func_Name


ENDIAN = '<' if default_endian() == 'little' else '>'
STRING_OFFSET = 0x100
CRC32_POLYNOMIAL = 0xEDB88320
BYTE_VALUES = 256
BITS_PER_BYTE = 8
NAME_HASH_SEED_MASK = 0x00FFFFFF    # the game's own seed for the rest of the name
CRC32_FINAL_XOR = 0xFFFFFFFF


def decode(data: bytes, **kwargs) -> ScpValue:
    '''The ScpValue read from the start of data (kwargs go to the FileStream)'''
    return ScpValue(fs = fileio.FileStream(**kwargs).OpenMemory(data))


class TestScpValue(unittest.TestCase):
    '''Each ScpValue type is one 4-byte word and decodes back to its value'''

    def test_raw_value(self):
        raw_val = 0x12345678
        data = ScpValue(RawInt(raw_val)).to_bytes()
        self.assertEqual(len(data), 4)

        val2 = decode(data)
        self.assertEqual(val2.value, raw_val)
        self.assertEqual(val2.type, ScpValue.Type.Raw)

    def test_integer_value(self):
        test_values = [0, 1, -1, 100, -100, 0x1FFFFFFF]  # 0x1FFFFFFF is safe max for 30-bit signed

        for test_val in test_values:
            with self.subTest(value = test_val):
                val = ScpValue(test_val)
                self.assertEqual(val.type, ScpValue.Type.Integer)
                data = val.to_bytes()
                self.assertEqual(len(data), 4)
                self.assertEqual(struct.unpack(f'{ENDIAN}I', data)[0] >> ScpValue.TYPE_SHIFT, ScpValue.Type.Integer)

                val2 = decode(data)
                self.assertEqual(val2.value, test_val)
                self.assertEqual(val2.type, ScpValue.Type.Integer)

    def test_float_value(self):
        test_values = [0.0, 1.0, -1.0, 3.14159, -2.71828, 100.5]

        for test_val in test_values:
            with self.subTest(value = test_val):
                val = ScpValue(test_val)
                self.assertEqual(val.type, ScpValue.Type.Float)
                data = val.to_bytes()
                self.assertEqual(len(data), 4)

                val2 = decode(data)
                self.assertAlmostEqual(val2.value, test_val, places = 5)
                self.assertEqual(val2.type, ScpValue.Type.Float)

    def test_roundtrip(self):
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
                val2 = decode(val1.to_bytes())

                self.assertEqual(val1.type, val2.type)
                if isinstance(original_value, float):
                    self.assertAlmostEqual(val1.value, val2.value, places = 5)
                else:
                    self.assertEqual(val1.value, val2.value)

    def test_string_value_deserialize(self):
        '''A String value is the offset of a NUL-terminated string; utf-8, not the platform's default encoding'''
        text = 'TestFunction'
        word = struct.pack(f'{ENDIAN}I', ScpValue.Type.String << ScpValue.TYPE_SHIFT | STRING_OFFSET)
        val = decode(word.ljust(STRING_OFFSET, b'\0') + text.encode('utf-8') + b'\0', encoding = 'utf-8')

        self.assertEqual(val.type, ScpValue.Type.String)
        self.assertEqual(val.value, text)


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


class TestFunctionNameHash(unittest.TestCase):
    @classmethod
    def polynomial_table(cls) -> list[int]:
        table = []
        for value in range(BYTE_VALUES):
            for _ in range(BITS_PER_BYTE):
                value = value >> 1 ^ CRC32_POLYNOMIAL if value & 1 else value >> 1

            table.append(value)

        return table

    def test_table_is_the_standard_crc32_table(self):
        self.assertEqual(crc32_table, self.polynomial_table())

    def test_name_hash_by_first_character(self):
        '''The first byte picks a table entry: one name per UTF-8 lead byte a function name can start with'''
        table = self.polynomial_table()
        for first in ('a', 'Z', '_', '\u00e9', '\u3042', '\u6f22', '\ud55c', '\uac00'):
            with self.subTest(first = first):
                data = (first + 'Func').encode(default_encoding())
                expected = binascii.crc32(data[1:], ~(table[~data[0]] ^ NAME_HASH_SEED_MASK)) ^ CRC32_FINAL_XOR
                self.assertEqual(hash_func_Name(first + 'Func'), expected)


if __name__ == '__main__':
    unittest.main(buffer = False)
