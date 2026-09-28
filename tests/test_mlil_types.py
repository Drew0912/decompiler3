#!/usr/bin/env python3
'''Unit tests for the MLIL type lattice (ir/mlil/mlil_types.py).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MLILAddressOf, MLILCall, MLILConst, MLILRet, MLILSetVar, MLILVar
from ir.mlil.mlil_ssa import SSAConstructor
from ir.mlil.mlil_types import MLILType, MLILVariantType, unify_types
from ir.mlil.passes import SSATypeInferencePass


INT_VALUE = 1
FLOAT_VALUE = 1.5
STRING_VALUE = 's'


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


class TestVariantGrowthIsRecorded(unittest.TestCase):
    '''An address-taken local has one SSA identity, so each *(&x) = v store updates the same
    entry: the third store's member must still be recorded once x is already a variant.'''

    def test_address_taken_local_collects_every_stored_type(self):
        # x = 1; x = 1.5; x = "s"; f(&x); return
        func = MediumLevelILFunction('variant_growth')
        block = func.create_block()
        x = func.get_or_create_local('x')

        for value in (INT_VALUE, FLOAT_VALUE, STRING_VALUE):
            block.add_instruction(MLILSetVar(x, MLILConst(value)))

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        block.add_instruction(MLILRet())

        SSAConstructor(func).construct()
        SSATypeInferencePass().run(func)

        self.assertEqual(func.var_types['x'].types, int_float_string().types, str(func.var_types['x']))


if __name__ == '__main__':
    unittest.main()
