"""Falcom LLIL to MLIL Converter"""

from dc3.logging import log
from ir.llil import LowLevelILFunction
from ir.mlil import MediumLevelILFunction, mlil_optimization_passes
from ir.pipeline import Pipeline
from .mlil_passes import ED9LLILToMLILPass


def convert_falcom_llil_to_mlil(llil_func: LowLevelILFunction,
                                 optimize: bool = True,
                                 infer_types: bool = True) -> MediumLevelILFunction:
    """Convert LLIL function to MLIL with Falcom-specific handling

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
