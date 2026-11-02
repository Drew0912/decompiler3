"""Falcom LLIL to MLIL Converter, the decompile path's (the SSA path's: falcom/ed9/ir/mlil_ssa/)"""

from dc3.logging import log
from ir.llil import LowLevelILFunction
from ir.mlil import BitwiseHexPass, BlockMergePass, CallResultPass, MediumLevelILFunction, ReturnValuePass
from ir.pipeline import Pipeline
from .stack_translator import ED9StackTranslatorPass


def convert_falcom_llil_to_mlil_stack(llil_func: LowLevelILFunction) -> MediumLevelILFunction:
    """The decompile path's MLIL, the symbolic-stack translator's: the translator, then the remaining
    single-predecessor jumps merged, the result stores nothing reads taken out, each return given the value stored
    right before it and bitwise constants marked hex. A shape it does not translate yet raises UnsupportedStackShape"""
    log.info(f'Translating {llil_func.name} @ 0x{llil_func.start_addr:08X} (stack translator)')

    passes = [ED9StackTranslatorPass(), BlockMergePass(), CallResultPass(), ReturnValuePass(), BitwiseHexPass()]
    mlil_func = Pipeline(passes).run(llil_func)
    mlil_func.renumber_instructions()
    return mlil_func
