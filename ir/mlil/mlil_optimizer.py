"""MLIL Optimizer - the one pass list that runs after LLIL->MLIL translation"""

from typing import List

from ir.pipeline import Pass, Pipeline
from .mlil import MediumLevelILFunction
from .passes import (
    BlockMergePass,
    SSAConversionPass,
    SSAOptimizationPass,
    SSATypeInferencePass,
    SSADeconstructionPass,
    RegGlobalValuePropagationPass,
)


def mlil_optimization_passes(infer_types: bool = True) -> List[Pass]:
    """The MLIL passes that run after LLIL->MLIL translation, in production order"""
    # BlockMergePass must run before SSAConversionPass
    passes: List[Pass] = [BlockMergePass(), SSAConversionPass(), SSAOptimizationPass()]

    # Type inference runs on SSA form
    if infer_types:
        passes.append(SSATypeInferencePass())

    passes.append(SSADeconstructionPass())
    passes.append(RegGlobalValuePropagationPass())
    return passes


def optimize_mlil(function: MediumLevelILFunction, infer_types: bool = True) -> MediumLevelILFunction:
    """Run the production MLIL passes on an already translated function"""
    function = Pipeline(mlil_optimization_passes(infer_types)).run(function)
    function.renumber_instructions()
    return function
