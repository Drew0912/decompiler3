#!/usr/bin/env python3
'''Unit tests for FalcomTypeInferencePass: parameter types come from the script's declared flags.'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

from codegen.typescript import generate_typescript
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.hlil.hlil_passes import FalcomTypeInferencePass
from falcom.ed9.parser.types_parser import Function, FunctionParam
from falcom.ed9.parser.types_scp import Nullable32, NullableStr, Pointer, ScpParamFlags, ScpValue, Value32
from ir.core.il_base import IRParameter
from ir.hlil import HighLevelILFunction, HLILTypeKind, HLILVariable, VariableKind
from ir.mlil.mlil import MediumLevelILFunction, MLILRet
from ir.mlil.mlil_optimizer import optimize_mlil
from ir.mlil.mlil_types import MLILType, MLILVariantType


TEST_FUNCTION_NAME = 'test_func'
FLOAT_DEFAULT = 0.1
STRING_DEFAULT = 'abc'


def make_scp_function(*params: FunctionParam) -> Function:
    func = Function()
    func.name = TEST_FUNCTION_NAME
    func.params = list(params)
    return func


def make_mlil_function(type_name: str, default_value) -> MediumLevelILFunction:
    '''One-parameter function whose body only returns'''
    func = MediumLevelILFunction(TEST_FUNCTION_NAME, params = [IRParameter('arg1', type_name, default_value)])
    func.get_or_create_parameter(1, 'arg1')
    func.create_block().add_instruction(MLILRet())
    return optimize_mlil(func)


# What the SSA pass infers for a Value32 parameter that also receives a float: its int seed joined with the float
INT_FLOAT_VARIANT = MLILVariantType({MLILType.int_type(), MLILType.float_type()})


class TestDeclaredParameterTypes(unittest.TestCase):
    '''Each declared flag gives its parameter's HLIL type.'''

    def test_each_flag_maps_to_its_kind(self):
        scp_func = make_scp_function(
            FunctionParam(ScpParamFlags(Value32)),
            FunctionParam(ScpParamFlags(str)),
            FunctionParam(ScpParamFlags(Pointer)),
            FunctionParam(ScpParamFlags(Nullable32), ScpValue(FLOAT_DEFAULT)),
            FunctionParam(ScpParamFlags(NullableStr), ScpValue(STRING_DEFAULT)),
        )
        hlil = HighLevelILFunction(TEST_FUNCTION_NAME)
        hlil.parameters = [HLILVariable(f'arg{i + 1}', kind = VariableKind.PARAM) for i in range(len(scp_func.params))]

        FalcomTypeInferencePass(scp_func).run(hlil)

        self.assertEqual(
            [param.type_hint for param in hlil.parameters],
            [HLILTypeKind.NUMBER, HLILTypeKind.STRING, HLILTypeKind.POINTER, HLILTypeKind.NUMBER, HLILTypeKind.STRING],
        )

    def test_declared_flag_wins_over_the_inferred_variant(self):
        # AniFieldAttack(arg1 = 0.1) stores floats into its Value32 parameter: the SSA pass gives
        # variant<int, float>, which rendered `arg1: any` while the pass was disabled
        mlil = make_mlil_function('Value32', FLOAT_DEFAULT)
        mlil.var_types = {'arg1': INT_FLOAT_VARIANT}
        scp_func = make_scp_function(FunctionParam(ScpParamFlags(Value32), ScpValue(FLOAT_DEFAULT)))

        ts = generate_typescript(convert_falcom_mlil_to_hlil(mlil, scp_func))

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: number = {FLOAT_DEFAULT})', ts)

    def test_string_default_is_quoted_once(self):
        # Guard: the default value still comes from the converter, formatted by codegen
        mlil = make_mlil_function('NullableStr', STRING_DEFAULT)
        scp_func = make_scp_function(FunctionParam(ScpParamFlags(NullableStr), ScpValue(STRING_DEFAULT)))

        ts = generate_typescript(convert_falcom_mlil_to_hlil(mlil, scp_func))

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: string = "{STRING_DEFAULT}")', ts)

    def test_without_the_script_function_the_inferred_type_stays(self):
        # Guard: callers that pass no script function (the semantic validator) keep the converter's mapping
        mlil = make_mlil_function('Value32', FLOAT_DEFAULT)
        mlil.var_types = {'arg1': INT_FLOAT_VARIANT}

        ts = generate_typescript(convert_falcom_mlil_to_hlil(mlil))

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: any = {FLOAT_DEFAULT})', ts)


if __name__ == '__main__':
    unittest.main()
