'''Falcom MLIL to HLIL Converter'''

from typing import Optional
from ir.mlil.mlil import MediumLevelILFunction
from ir.hlil import HighLevelILFunction
from ir.pipeline import Pipeline
from ir.hlil.hlil_passes import (
    MLILToHLILPass,
    ExpressionSimplificationPass,
    CopyPropagationPass,
    ControlFlowOptimizationPass,
    CommonReturnExtractionPass,
    DeadCodeEliminationPass,
)
from .hlil_passes import FalcomTypeInferencePass
from .parser.types_parser import Function


def convert_falcom_mlil_to_hlil(mlil_func: MediumLevelILFunction, scp_func: Optional[Function] = None) -> HighLevelILFunction:
    '''Convert MLIL function to HLIL with Falcom-specific type information'''
    pipeline = Pipeline()
    pipeline.add_pass(MLILToHLILPass())

    # DISABLED: FalcomTypeInferencePass - testing
    # if scp_func:
    #     pipeline.add_pass(FalcomTypeInferencePass(scp_func))

    pipeline.add_pass(ExpressionSimplificationPass())
    # DISABLED: CopyPropagationPass - moved to MLIL SSA layer
    # pipeline.add_pass(CopyPropagationPass())
    pipeline.add_pass(ControlFlowOptimizationPass())
    pipeline.add_pass(CommonReturnExtractionPass())
    pipeline.add_pass(DeadCodeEliminationPass())

    return pipeline.run(mlil_func, debug=True)
