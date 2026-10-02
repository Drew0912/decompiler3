#!/usr/bin/env python3
'''ScpValue.float_literal: the .py spells a stored float as the shortest float literal that stores the same
word (PUSH_FLOAT(0.3), not PUSH_FLOAT(0.2999999523162842)); non-finite floats, which the game can't use, print
as a float() call and warn when decoded.'''

import ast
import math
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.parser import types_scp
from falcom.ed9.parser.types_scp import ScpValue

FLOAT_TAG       = ScpValue.Type.Float << ScpValue.TYPE_SHIFT
RANDOM_WORDS    = 20000
SEED            = 20261002
F32_SIGN        = 0x80000000
F32_EXP_SHIFT   = 23
F32_EXP_MAX     = 0xFF          # all ones: inf or NaN
F32_MANTISSA    = 0x007FFFFF
F32_INF         = 0x7F800000
F32_NEAR_MAX    = 0x7F7FF9C4    # rounding a candidate up can overflow float32


def float_word(f32_bits: int) -> int:
    return FLOAT_TAG | (f32_bits >> ScpValue.FLOAT_DROPPED_BITS)


def decode(word: int) -> float:
    return ScpValue().from_value(word).value


def stored(text: str) -> float:
    '''The value the game holds for a source literal: encode, then decode'''
    return decode(ScpValue(float(text)).to_word())


def edge_words() -> list[int]:
    '''Every exponent with the smallest and largest kept mantissa, both signs, plus zeros and subnormals'''
    kept_mantissa_max = F32_MANTISSA & ~((1 << ScpValue.FLOAT_DROPPED_BITS) - 1)
    patterns = {0, 1 << ScpValue.FLOAT_DROPPED_BITS, kept_mantissa_max, F32_NEAR_MAX}
    for exponent in range(F32_EXP_MAX):
        patterns.update({exponent << F32_EXP_SHIFT, (exponent << F32_EXP_SHIFT) | kept_mantissa_max})

    return sorted(float_word(bits | sign) for bits in patterns for sign in (0, F32_SIGN))


class TestShortestText(unittest.TestCase):
    def test_stored_value_prints_short(self):
        self.assertEqual(ScpValue.float_literal(0.2999999523162842), '0.3')
        self.assertEqual(ScpValue.float_literal(0.19999998807907104), '0.2')
        self.assertEqual(ScpValue.float_literal(-63.102996826171875), '-63.103')

        for text in ('0.3', '27.2', '0.705', '0.0333'):
            with self.subTest(text = text):
                self.assertNotEqual(repr(stored(text)), text)
                self.assertEqual(ScpValue.float_literal(stored(text)), text)

    def test_always_a_float_literal(self):
        # '1' would encode an Integer and '-0' would lose its sign
        for value, text in ((1.0, '1.0'), (-0.0, '-0.0'), (170.0, '170.0'), (100.0, '100.0')):
            with self.subTest(value = value):
                self.assertEqual(ScpValue.float_literal(value), text)

    def test_zero_is_not_the_midpoint(self):
        self.assertEqual(ScpValue.float_literal(0.0), '0.0')

    def test_near_float32_max_does_not_raise(self):
        near_max = decode(float_word(F32_NEAR_MAX))
        self.assertEqual(ScpValue(float(ScpValue.float_literal(near_max))).to_word(), float_word(F32_NEAR_MAX))

        # A double past float32's range has no word: printed as is
        self.assertEqual(ScpValue.float_literal(3.5e38), '3.5e+38')

    def test_every_word_round_trips(self):
        rng = random.Random(SEED)
        words = edge_words()
        while len(words) < len(edge_words()) + RANDOM_WORDS:
            payload = rng.getrandbits(ScpValue.TYPE_SHIFT)
            # Skip inf/NaN by their bits: decoding one would log a warning
            if ((payload << ScpValue.FLOAT_DROPPED_BITS) >> F32_EXP_SHIFT) & F32_EXP_MAX != F32_EXP_MAX:
                words.append(FLOAT_TAG | payload)

        for word in words:
            text = ScpValue.float_literal(decode(word))
            self.assertIs(type(ast.literal_eval(text)), float, text)
            self.assertEqual(ScpValue(float(text)).to_word(), word, f'0x{word:08X} -> {text}')


class TestNonFinite(unittest.TestCase):
    def test_printed_as_a_float_call(self):
        self.assertEqual(ScpValue.float_literal(math.inf), "float('inf')")
        self.assertEqual(ScpValue.float_literal(-math.inf), "-float('inf')")

        # Any NaN word, not just the canonical one: it can't compile, so its bits don't matter
        self.assertEqual(ScpValue.float_literal(ScpValue.float32_from_bits(F32_INF | (1 << ScpValue.FLOAT_DROPPED_BITS))), "float('nan')")

    def test_decoding_warns(self):
        word = float_word(F32_INF)
        with self.assertLogs(types_scp.log, level = 'WARNING') as logs:
            self.assertEqual(decode(word), math.inf)

        self.assertIn(f"non-finite float inf (word 0x{word:08X}): the game can't use it", logs.output[0])

    def test_still_encodable(self):
        # The writer rejects it (test_scp_writer_dsl.py); ScpValue itself must still represent any word
        self.assertEqual(ScpValue(math.inf).to_word(), float_word(F32_INF))


class TestWord(unittest.TestCase):
    def test_to_word(self):
        self.assertEqual(ScpValue(0.3).to_word(), 0x8FA66666)
        self.assertEqual(ScpValue(1).to_word(), 0x40000001)

    def test_repr_unchanged(self):
        # Library fingerprints and the checked-in common_index.py depend on it
        self.assertEqual(repr(ScpValue(0.19999998807907104)), 'ScpValue(0.19999998807907104)')


if __name__ == '__main__':
    unittest.main()
