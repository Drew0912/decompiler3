"""Falcom LLIL to MLIL Converter"""

from dc3.logging import log
from ir.llil import LowLevelILFunction
from ir.mlil import (
    BitwiseHexPass, BlockMergePass, CallResultPass, MediumLevelILFunction, ReturnValuePass, mlil_optimization_passes,
)
from ir.pipeline import Pipeline
from .mlil_passes import ED9LLILToMLILPass
from .stack_translator import ED9StackTranslatorPass


def convert_falcom_llil_to_mlil_ssa(llil_func: LowLevelILFunction,
                                     optimize: bool = True,
                                     infer_types: bool = True) -> MediumLevelILFunction:
    """The SSA path's MLIL, the decompile path's until the switch (IR rewrite part 2): LLIL converted to MLIL with
    Falcom-specific handling

    Args:
        llil_func: LLIL function to convert
        optimize: Whether to run SSA optimizations (default True)
        infer_types: Whether to run type inference (default True)
    """
    log.info(f'Translating {llil_func.name} @ 0x{llil_func.start_addr:08X}')

    passes = [ED9LLILToMLILPass()]

    # optimize=False keeps the raw block-per-LLIL-boundary translation
    if optimize:
        passes.extend(mlil_optimization_passes(infer_types))

    mlil_func = Pipeline(passes).run(llil_func)
    mlil_func.renumber_instructions()
    return mlil_func


def convert_falcom_llil_to_mlil_stack(llil_func: LowLevelILFunction) -> MediumLevelILFunction:
    """The symbolic-stack translator's MLIL, not yet the decompile path's: the translator, then the remaining
    single-predecessor jumps merged, the result stores nothing reads taken out, each return given the value stored
    right before it and bitwise constants marked hex. A shape it does not translate yet raises UnsupportedStackShape"""
    log.info(f'Translating {llil_func.name} @ 0x{llil_func.start_addr:08X} (stack translator)')

    passes = [ED9StackTranslatorPass(), BlockMergePass(), CallResultPass(), ReturnValuePass(), BitwiseHexPass()]
    mlil_func = Pipeline(passes).run(llil_func)
    mlil_func.renumber_instructions()
    return mlil_func
