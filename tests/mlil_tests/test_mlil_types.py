#!/usr/bin/env python3
"""Unit tests for the MLIL type lattice (ir/mlil/mlil_types.py)."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil_types import MLILType, MLILVariantType, unify_types


def int_float() -> MLILVariantType:
    return MLILVariantType({MLILType.int_type(), MLILType.float_type()})


def int_float_string() -> MLILVariantType:
    return MLILVariantType({MLILType.int_type(), MLILType.float_type(), MLILType.string_type()})


class TestVariantEquality(unittest.TestCase):

    def test_same_members_are_equal_and_hash_equal(self):
        same_members = MLILVariantType({MLILType.float_type(), MLILType.int_type()})
        self.assertEqual(int_float(), same_members)
        self.assertEqual(hash(int_float()), hash(same_members))

    def test_different_members_are_not_equal(self):
        self.assertNotEqual(int_float(), int_float_string())
        self.assertEqual(len({int_float(), int_float_string()}), 2)

    def test_variant_never_equals_a_plain_type(self):
        self.assertNotEqual(int_float(), MLILType.int_type())
        self.assertNotEqual(MLILType.int_type(), int_float())

    def test_unify_adds_the_new_member(self):
        # Compare members, not the types: equality is what is under test here
        self.assertEqual(unify_types(int_float(), MLILType.string_type()).types, int_float_string().types)
        self.assertEqual(unify_types(MLILType.string_type(), int_float()).types, int_float_string().types)
        self.assertEqual(unify_types(int_float(), MLILType.float_type()).types, int_float().types)


if __name__ == '__main__':
    unittest.main()
