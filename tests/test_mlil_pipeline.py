#!/usr/bin/env python3
'''Unit tests for the one MLIL pass list shared by production and optimize_mlil.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from ir.llil.llil import LowLevelILFunction
from ir.mlil.mlil_formatter import MLILFormatter
from ir.mlil.mlil_optimizer import mlil_optimization_passes, optimize_mlil
from ir.mlil.mlil_types import FunctionSignatureDB
from ir.mlil.passes import (
    BlockMergePass, SSAConversionPass, SSAOptimizationPass, SSATypeInferencePass, SSADeconstructionPass,
    RegGlobalValuePropagationPass,
)


FUNC_START = 0x3000
BLOCK_STRIDE = 0x10
ARG_VALUE = 7

EXPECTED_PASS_TYPES = [
    BlockMergePass, SSAConversionPass, SSAOptimizationPass, SSATypeInferencePass, SSADeconstructionPass,
    RegGlobalValuePropagationPass,
]


def build_call_function() -> LowLevelILFunction:
    # A call, then a return - the call ends its LLIL block, so translation leaves a goto to the return block
    builder = FalcomVMBuilder()
    builder.create_function('pipeline_test', FUNC_START, num_params = 0)
    builder.set_current_block(builder.create_basic_block(FUNC_START, 'entry'))
    ret_block = builder.create_basic_block(FUNC_START + BLOCK_STRIDE, 'ret')
    builder.push_func_id()
    builder.push_ret_addr(ret_block)
    builder.push_int(ARG_VALUE)
    builder.call('f')
    builder.begin_block(ret_block)
    builder.ret()
    return builder.finalize()


class TestMLILPassList(unittest.TestCase):
    def test_pass_order_is_production_order(self):
        self.assertEqual([type(p) for p in mlil_optimization_passes()], EXPECTED_PASS_TYPES)

    def test_type_inference_can_be_left_out(self):
        expected = [cls for cls in EXPECTED_PASS_TYPES if cls is not SSATypeInferencePass]
        self.assertEqual([type(p) for p in mlil_optimization_passes(infer_types = False)], expected)

    def test_signature_db_reaches_type_inference(self):
        signature_db = FunctionSignatureDB()
        inference = next(p for p in mlil_optimization_passes(signature_db = signature_db)
                         if isinstance(p, SSATypeInferencePass))
        self.assertIs(inference.signature_db, signature_db)


class TestOptimizeMLILMatchesProduction(unittest.TestCase):
    def test_same_mlil_as_the_production_converter(self):
        for infer_types in (True, False):
            with self.subTest(infer_types = infer_types):
                production = convert_falcom_llil_to_mlil(build_call_function(), optimize = True,
                                                         infer_types = infer_types)
                translated = convert_falcom_llil_to_mlil(build_call_function(), optimize = False)
                optimized = optimize_mlil(translated, infer_types_enabled = infer_types)

                self.assertEqual(MLILFormatter.format_function(optimized), MLILFormatter.format_function(production))
                self.assertEqual(len(optimized.basic_blocks), 1, 'the call-return goto was not merged away')


if __name__ == '__main__':
    unittest.main()
