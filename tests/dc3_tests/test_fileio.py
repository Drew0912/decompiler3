#!/usr/bin/env python3
'''Unit tests for common/fileio.py - the deliberate quirks of the ported ml FileStream that round trips rely on.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from common import fileio
from common.logging import log


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

    def test_read_multibyte_drops_undecodable_bytes_with_a_warning(self):
        fs = self.memory(b'a\xffb\x00rest', encoding = 'utf-8')
        with self.assertLogs(log, 'WARNING') as logs:
            self.assertEqual(fs.ReadMultiByte(), 'ab')

        self.assertIn('string at 0x0', logs.output[0])
        self.assertEqual(fs.Position, 4)

    def test_read_multibyte_stops_after_its_nul_across_chunks(self):
        text = 'x' * (fileio.FileStream.STRING_CHUNK_SIZE * 2 + 3)
        cases = [
            ('longer than a chunk',     text.encode() + b'\x00rest',    text,   len(text) + 1),
            ('empty',                   b'\x00rest',                    '',     1),
            ('no NUL before the end',   b'abc',                         'abc',  3),
        ]
        for name, data, expected, position in cases:
            with self.subTest(name):
                fs = self.memory(data, encoding = 'utf-8')
                self.assertEqual(fs.ReadMultiByte(), expected)
                self.assertEqual(fs.Position, position)

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


if __name__ == '__main__':
    unittest.main()
