'''Falcom MLIL to HLIL Converter'''

from typing import Optional
from ir.mlil.mlil import MediumLevelILFunction
from ir.hlil import HighLevelILFunction
from ir.pipeline import Pipeline
from ir.hlil.hlil_passes import (
    MLILToHLILPass,
    ControlFlowOptimizationPass,
    LoopRecoveryPass,
    CommonReturnExtractionPass,
    DeadCodeEliminationPass,
    BranchOrderNormalizationPass,
)
from .hlil_passes import FalcomTypeInferencePass
from ...parser.types_parser import Function


def convert_falcom_mlil_to_hlil(mlil_func: MediumLevelILFunction, scp_func: Optional[Function] = None,
                                 normalize_branch_order: bool = True) -> HighLevelILFunction:
    '''Convert MLIL function to HLIL with Falcom-specific type information

    normalize_branch_order restores source order for if/else arms that structuring
    left reversed. It is the only step that departs from the order the bytecode was
    emitted in, so turn it off to read HLIL against the address-ordered levels.
    '''
    pipeline = Pipeline()
    pipeline.add_pass(MLILToHLILPass())

    # Parameter types come from the script's declared flags, not from MLIL inference
    if scp_func:
        pipeline.add_pass(FalcomTypeInferencePass(scp_func))

    pipeline.add_pass(ControlFlowOptimizationPass())
    pipeline.add_pass(LoopRecoveryPass())
    pipeline.add_pass(CommonReturnExtractionPass())
    pipeline.add_pass(DeadCodeEliminationPass())

    # Last: the control-flow shape is final by here, so this only reorders
    if normalize_branch_order:
        pipeline.add_pass(BranchOrderNormalizationPass())

    return pipeline.run(mlil_func, debug = False)
