#!/usr/bin/env python3
"""Unit tests for the MLIL type lattice (ir/mlil/mlil_types.py)."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.ir.llil.vm_lifter import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.parser.parser_types import FunctionParam
from falcom.ed9.structs.scp_types import Nullable32, NullableStr, Pointer, ScpParamFlags, Value32
from ir.mlil.mlil import MediumLevelILFunction, MLILAddressOf, MLILCall, MLILConst, MLILRet, MLILSetVar, MLILVar
from ir.mlil.mlil_ssa import SSAConstructor
from ir.mlil.mlil_types import MLILType, MLILVariantType, unify_types
from ir.mlil.passes import SSATypeInferencePass
from tests.shared.scp_asm import Asm, Program, main_function


INT_VALUE = 1
FLOAT_VALUE = 1.5
STRING_VALUE = 's'

# Each type a script can declare for a parameter, and the MLIL type it seeds
DECLARED_PARAM_TYPES = [
    (Value32,       MLILType.int_type()),
    (Nullable32,    MLILType.int_type()),
    (str,           MLILType.string_type()),
    (NullableStr,   MLILType.string_type()),
    (Pointer,       MLILType.pointer_type()),
]


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
    """An address-taken local has one SSA identity, so each *(&x) = v store updates the same
    entry: the third store's member must still be recorded once x is already a variant."""

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


class TestDeclaredParameterTypes(unittest.TestCase):
    """A parameter's declared type reaches MLIL through the lifter's generic type name and the SSA pass's map"""

    def test_each_declared_type_seeds_its_parameter(self):
        asm = Asm()
        asm.ret()
        parser, [func] = Program(main_function(asm)).disassemble()
        func.params = [FunctionParam(ScpParamFlags(declared)) for declared, _ in DECLARED_PARAM_TYPES]

        mlil = convert_falcom_llil_to_mlil(ED9VMLifter(parser=parser).lift_function(func))

        self.assertEqual([mlil.var_types[f'arg{i + 1}'] for i in range(len(func.params))],
                         [expected for _, expected in DECLARED_PARAM_TYPES])


if __name__ == '__main__':
    unittest.main()
