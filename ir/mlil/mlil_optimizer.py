'''MLIL Optimizer - the one pass list that runs after LLIL->MLIL translation'''

from typing import List, Optional

from ir.pipeline import Pass, Pipeline
from .mlil import MediumLevelILFunction
from .mlil_types import FunctionSignatureDB
from .passes import (
    BlockMergePass,
    SSAConversionPass,
    SSAOptimizationPass,
    SSATypeInferencePass,
    SSADeconstructionPass,
    RegGlobalValuePropagationPass,
)


def mlil_optimization_passes(infer_types: bool = True,
                             signature_db: Optional[FunctionSignatureDB] = None) -> List[Pass]:
    '''The MLIL passes that run after LLIL->MLIL translation, in production order'''
    # A LowLevelILCall is a block terminator, so nearly every call site is one goto away from its return
    # block - undo that split before any SSA analysis runs, so every later pass sees the smaller CFG
    passes: List[Pass] = [BlockMergePass(), SSAConversionPass(), SSAOptimizationPass()]

    # Type inference runs on SSA form
    if infer_types:
        passes.append(SSATypeInferencePass(signature_db))

    passes.append(SSADeconstructionPass())
    passes.append(RegGlobalValuePropagationPass())
    return passes


def optimize_mlil(function: MediumLevelILFunction,
                  infer_types_enabled: bool = True,
                  signature_db: Optional[FunctionSignatureDB] = None) -> MediumLevelILFunction:
    '''Run the production MLIL passes on an already translated function'''
    return Pipeline(mlil_optimization_passes(infer_types_enabled, signature_db)).run(function)
