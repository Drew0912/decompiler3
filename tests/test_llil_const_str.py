#!/usr/bin/env python3
'''LowLevelILConst string text in the .llil.asm: escaped, so a quote or line break can't end the token or the line.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil import LowLevelILConst


class TestStringConst(unittest.TestCase):
    def test_plain_string_keeps_single_quotes(self):
        self.assertEqual(str(LowLevelILConst('AniBtlAttack')), "'AniBtlAttack'")

    def test_quote_is_escaped(self):
        self.assertEqual(str(LowLevelILConst("Thunder God's Descent")), r"'Thunder God\'s Descent'")

    def test_double_quote_is_kept(self):
        self.assertEqual(str(LowLevelILConst('say "hi"')), '\'say "hi"\'')

    def test_backslash_and_whitespace_escapes(self):
        self.assertEqual(str(LowLevelILConst('a\\b\tc\nd\re')), r"'a\\b\tc\nd\re'")

    def test_control_characters_are_hex_escaped(self):
        self.assertEqual(str(LowLevelILConst('x\x01y\x7fz')), r"'x\x01y\x7fz'")

    def test_non_ascii_text_is_kept(self):
        self.assertEqual(str(LowLevelILConst('◆通常攻撃')), "'◆通常攻撃'")


if __name__ == '__main__':
    unittest.main()
