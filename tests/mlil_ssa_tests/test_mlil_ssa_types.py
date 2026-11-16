#!/usr/bin/env python3
"""Unit tests for what SSA type inference records (an address-taken local, a declared parameter) and how its types
reach HLIL (convert_ed9_mlil_ssa_to_hlil), before the file-level stage's declared types"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen.typescript import generate_typescript
from falcom.ed9.ir.hlil.hlil_converter_ssa import convert_ed9_mlil_ssa_to_hlil
from falcom.ed9.ir.hlil.pass_type_inference import ED9TypeInferencePass
from falcom.ed9.ir.llil.vm_lifter import ED9VMLifter
from falcom.ed9.ir.mlil_ssa.mlil_converter import convert_ed9_llil_to_mlil_ssa
from falcom.ed9.assembler.function import Function, FunctionParam
from falcom.ed9.structs.scp_types import Nullable32, NullableStr, Pointer, ScpParamFlags, ScpValue, Value32
from ir.core import IRParameter
from ir.hlil import HLILTypeKind
from ir.mlil.mlil import MLILAddressOf, MLILCall, MLILConst, MLILRet, MLILSetVar, MLILVar
from ir.mlil_ssa.mlil_ssa import SSAConstructor
from ir.mlil_ssa.mlil_types import MLILType, MLILVariantType
from ir.mlil_ssa.passes import SSATypeInferencePass
from falcom.ed9.ir.mlil_ssa.mlil_ssa_function import ED9MediumLevelILFunctionSSA
from tests.shared.scp_asm import Asm, Program, main_function


INT_VALUE = 1
FLOAT_VALUE = 1.5
STRING_VALUE = 's'
TEST_FUNCTION_NAME = 'test_func'
FLOAT_DEFAULT = 0.1

# Each type a script can declare for a parameter, the MLIL type it seeds and the HLIL type that gives
DECLARED_PARAM_TYPES = [
    (Value32,       MLILType.int_type(),        HLILTypeKind.INT),
    (Nullable32,    MLILType.int_type(),        HLILTypeKind.INT),
    (str,           MLILType.string_type(),     HLILTypeKind.STRING),
    (NullableStr,   MLILType.string_type(),     HLILTypeKind.STRING),
    (Pointer,       MLILType.pointer_type(),    HLILTypeKind.POINTER),
]

# What the SSA pass infers for a Value32 parameter that also receives a float: its int seed joined with the float
INT_FLOAT_VARIANT = MLILVariantType({MLILType.int_type(), MLILType.float_type()})


def declared_parameters_mlil() -> ED9MediumLevelILFunctionSSA:
    """A function that only returns, declaring each of DECLARED_PARAM_TYPES' types, through the SSA path"""
    asm = Asm()
    asm.ret()
    parser, [func] = Program(main_function(asm)).disassemble()
    func.params = [FunctionParam(ScpParamFlags(declared)) for declared, _, _ in DECLARED_PARAM_TYPES]
    return convert_ed9_llil_to_mlil_ssa(ED9VMLifter(parser=parser).lift_function(func))


class TestVariantGrowthIsRecorded(unittest.TestCase):
    """An address-taken local has one SSA identity, so each *(&x) = v store updates the same
    entry: the third store's member must still be recorded once x is already a variant."""

    def test_address_taken_local_collects_every_stored_type(self):
        # x = 1; x = 1.5; x = "s"; f(&x); return
        func = ED9MediumLevelILFunctionSSA('variant_growth')
        block = func.create_block()
        x = func.get_or_create_local('x')

        for value in (INT_VALUE, FLOAT_VALUE, STRING_VALUE):
            block.add_instruction(MLILSetVar(x, MLILConst(value)))

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        block.add_instruction(MLILRet())

        SSAConstructor(func).construct()
        SSATypeInferencePass().run(func)

        stored = {MLILType.int_type(), MLILType.float_type(), MLILType.string_type()}
        self.assertEqual(func.var_types['x'].types, stored, str(func.var_types['x']))


class TestDeclaredParameterTypes(unittest.TestCase):
    """A parameter's declared type reaches MLIL through the lifter's generic type name and the SSA pass's map"""

    def test_each_declared_type_seeds_its_parameter(self):
        mlil = declared_parameters_mlil()

        self.assertEqual([mlil.var_types[f'arg{i + 1}'] for i in range(len(DECLARED_PARAM_TYPES))],
                         [mlil_type for _, mlil_type, _ in DECLARED_PARAM_TYPES])


class TestInferredTypesReachHLIL(unittest.TestCase):
    """convert_ed9_mlil_ssa_to_hlil gives each HLIL parameter and local the SSA path's type; the file-level stage's
    declared types come after"""

    def test_each_inferred_parameter_type_reaches_the_hlil(self):
        hlil = convert_ed9_mlil_ssa_to_hlil(declared_parameters_mlil())

        self.assertEqual([param.type_hint for param in hlil.parameters],
                         [hlil_type for _, _, hlil_type in DECLARED_PARAM_TYPES])

    def test_declared_flag_wins_over_the_inferred_variant(self):
        # AniFieldAttack(arg1 = 0.1) stores floats into its Value32 parameter: the SSA pass gives
        # variant<int, float>, which rendered `arg1: any` while the pass was disabled
        mlil = ED9MediumLevelILFunctionSSA(TEST_FUNCTION_NAME, params=[IRParameter('arg1', 'int', FLOAT_DEFAULT)])
        mlil.get_or_create_parameter(1, 'arg1')
        mlil.create_block().add_instruction(MLILRet())
        mlil.var_types = {'arg1': INT_FLOAT_VARIANT}
        scp_func = Function()
        scp_func.name = TEST_FUNCTION_NAME
        scp_func.params = [FunctionParam(ScpParamFlags(Value32), ScpValue(FLOAT_DEFAULT))]

        hlil = convert_ed9_mlil_ssa_to_hlil(mlil)
        ED9TypeInferencePass([scp_func]).run([hlil])

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: number = {FLOAT_DEFAULT})', generate_typescript(hlil))


if __name__ == '__main__':
    unittest.main()
