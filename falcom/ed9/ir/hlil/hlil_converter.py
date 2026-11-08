"""Falcom MLIL to HLIL Converter"""

from ir.mlil.mlil import MediumLevelILFunction
from ir.hlil import HighLevelILFunction
from ir.pipeline import Pipeline
from ir.hlil.passes import (
    MLILToHLILPass,
    SwitchRecoveryPass,
    LoopRecoveryPass,
    CommonReturnExtractionPass,
    DeadCodeEliminationPass,
    BranchOrderNormalizationPass,
    LineMarkerRemovalPass,
)


def convert_falcom_mlil_to_hlil(mlil_func: MediumLevelILFunction, normalize_branch_order: bool = True,
                                 line_markers: bool = True) -> HighLevelILFunction:
    """Convert MLIL function to HLIL. The Falcom types come after, over the whole file (FalcomTypeInferencePass)

    normalize_branch_order restores source order for if/else arms that structuring
    left reversed. It is the only step that departs from the order the bytecode was
    emitted in, so turn it off to read HLIL against the address-ordered levels.

    line_markers keeps the line(N) comments. Off, they go after every pass that reads
    them, so the code statements and their order stay; if arms left empty are tidied
    without changing what runs (a negated condition, swapped or nested arms).
    """
    pipeline = Pipeline()
    pipeline.add_pass(MLILToHLILPass())
    pipeline.add_pass(SwitchRecoveryPass())
    pipeline.add_pass(LoopRecoveryPass())
    pipeline.add_pass(CommonReturnExtractionPass())
    pipeline.add_pass(DeadCodeEliminationPass())

    # The control-flow shape is final by here, so this only reorders
    if normalize_branch_order:
        pipeline.add_pass(BranchOrderNormalizationPass())

    # Last: every pass that reads the markers has run
    if not line_markers:
        pipeline.add_pass(LineMarkerRemovalPass())

    return pipeline.run(mlil_func, debug=False)
