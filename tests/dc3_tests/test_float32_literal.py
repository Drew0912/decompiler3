#!/usr/bin/env python3
"""dc3.utils.float32_literal: the shortest text that stores the same float32"""

from pathlib import Path
import struct
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.utils import float32_literal


class TestFloat32Literal(unittest.TestCase):
    def test_a_float_prints_its_shortest_literal(self):
        for stored, text in ((0.3, '0.3'), (4.0, '4.0'), (-0.0, '-0.0'), (1e-05, '1e-05'), (33.988, '33.988')):
            with self.subTest(text):
                value = struct.unpack('<f', struct.pack('<f', stored))[0]
                self.assertEqual(float32_literal(value), text)

    def test_a_float_needing_every_digit_keeps_its_bits(self):
        value = struct.unpack('<f', bytes.fromhex('79e91e40'))[0]
        self.assertEqual(struct.pack('<f', float(float32_literal(value))), struct.pack('<f', value))


if __name__ == '__main__':
    unittest.main()
