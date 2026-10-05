#!/usr/bin/env python3
'''Unit tests for common/fileio.py - the deliberate quirks of the ported ml FileStream that round trips rely on.'''

from pathlib import Path
import math
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from common import fileio


class TestFileStreamQuirks(unittest.TestCase):

    @classmethod
    def memory(cls, data: bytes = b'', **kwargs) -> fileio.FileStream:
        return fileio.FileStream(**kwargs).OpenMemory(data)

    def test_write_stops_at_first_empty_buffer(self):
        fs = self.memory()
        self.assertIsNone(fs.Write(b'ab', b'', b'zz'))
        self.assertEqual(fs.ReadAll(), b'ab')

    def test_write_filestream_buffer_writes_whole_content_and_keeps_its_position(self):
        src = self.memory(b'xyz')
        src.Position = 1
        fs = self.memory()
        self.assertEqual(fs.Write(src), 3)
        self.assertEqual(fs.ReadAll(), b'xyz')
        self.assertEqual(src.Position, 1)

    def test_integer_writers_truncate_like_a_c_cast(self):
        cases = [
            ('WriteChar',   -1,             b'\xff'),
            ('WriteByte',   0x100,          b'\x00'),
            ('WriteShort',  -1,             b'\xff\xff'),
            ('WriteUShort', 0x12345,        b'\x45\x23'),
            ('WriteLong',   -2,             b'\xfe\xff\xff\xff'),
            ('WriteULong',  (1 << 32) + 5,  b'\x05\x00\x00\x00'),
        ]
        for method, value, expected in cases:
            with self.subTest(method = method, value = value):
                fs = self.memory()
                self.assertEqual(getattr(fs, method)(value), len(expected))
                self.assertEqual(fs.ReadAll(), expected)

    def test_signed_writers_are_their_unsigned_twins(self):
        self.assertIs(fileio.FileStream.WriteChar, fileio.FileStream.WriteByte)
        self.assertIs(fileio.FileStream.WriteShort, fileio.FileStream.WriteUShort)
        self.assertIs(fileio.FileStream.WriteLong, fileio.FileStream.WriteULong)

    def test_write_float_out_of_range_becomes_inf(self):
        for value, expected in [(1e40, math.inf), (-1e40, -math.inf), (1.5, 1.5)]:
            with self.subTest(value = value):
                fs = self.memory()
                fs.WriteFloat(value)
                self.assertEqual(fs.ReadAll(), struct.pack('<f', expected))

    def test_read_multibyte_drops_undecodable_bytes(self):
        fs = self.memory(b'a\xffb\x00rest', encoding = 'utf-8')
        self.assertEqual(fs.ReadMultiByte(), 'ab')
        self.assertEqual(fs.Position, 4)

    def test_empty_stream_is_falsy(self):
        self.assertFalse(self.memory())
        self.assertTrue(self.memory(b'x'))

    def test_endian_defaults_to_config_and_accepts_names(self):
        for kwargs, expected in [({}, b'\x01\x00'), ({'endian': 'big'}, b'\x00\x01'), ({'endian': '<'}, b'\x01\x00')]:
            with self.subTest(**kwargs):
                fs = self.memory(**kwargs)
                fs.WriteUShort(1)
                self.assertEqual(fs.ReadAll(), expected)

    def test_read_zero_and_position_saver(self):
        fs = self.memory(b'abcdef')
        fs.Position = 2
        with fs.PositionSaver:
            fs.Position = 4
            self.assertEqual(fs.Read(0), b'')
            self.assertEqual(fs.Read(2), b'ef')

        self.assertEqual(fs.Position, 2)

    def test_close_without_open_is_harmless(self):
        fileio.FileStream().Close()


if __name__ == '__main__':
    unittest.main()
