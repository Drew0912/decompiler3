#!/usr/bin/env python3
'''Unit tests for MLILFormatter's own formatting of a constant instruction.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import MLILConst
from ir.mlil.mlil_formatter import MLILFormatter


# A quote, a backslash and a newline, and its escaped literal
SPECIAL_TEXT = 'a"b\\c\nd'
SPECIAL_TEXT_LITERAL = r'"a\"b\\c\nd"'


class TestConstantFormatting(unittest.TestCase):
    '''A string constant prints as the same escaped literal as MLILConst's own str() (it used to be quoted raw).'''

    def test_string_constant_is_escaped(self):
        self.assertEqual(MLILFormatter.format_instruction(MLILConst(SPECIAL_TEXT)), SPECIAL_TEXT_LITERAL)

    def test_matches_the_constants_own_text(self):
        const = MLILConst(SPECIAL_TEXT)
        self.assertEqual(MLILFormatter.format_instruction(const), str(const))


if __name__ == '__main__':
    unittest.main()
