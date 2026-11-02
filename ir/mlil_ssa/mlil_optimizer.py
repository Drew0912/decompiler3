"""MLIL Optimizer - the SSA path's one pass list, which runs after its LLIL->MLIL translation"""

from ir.mlil.mlil import MediumLevelILFunction
from ir.mlil.passes import BitwiseHexPass, BlockMergePass
from ir.pipeline import Pass, Pipeline
from .passes import (
    SSAConversionPass,
    SSAOptimizationPass,
    SSATypeInferencePass,
    SSADeconstructionPass,
)


def mlil_optimization_passes(infer_types: bool = True) -> list[Pass]:
    """The MLIL passes that run after LLIL->MLIL translation, in the SSA path's order (RegGlobalValuePropagationPass,
    which carries a register's or global's value forward, is left out but kept: docs/mlil/MLIL_DESIGN.md)"""
    # BlockMergePass must run before SSAConversionPass
    passes: list[Pass] = [BlockMergePass(), SSAConversionPass(), SSAOptimizationPass()]

    # Type inference runs on SSA form
    if infer_types:
        passes.append(SSATypeInferencePass())

    passes.append(SSADeconstructionPass())
    # Display only, on the final expressions
    passes.append(BitwiseHexPass())
    return passes


def optimize_mlil(function: MediumLevelILFunction, infer_types: bool = True) -> MediumLevelILFunction:
    """Run the production MLIL passes on an already translated function"""
    function = Pipeline(mlil_optimization_passes(infer_types)).run(function)
    function.renumber_instructions()
    return function
