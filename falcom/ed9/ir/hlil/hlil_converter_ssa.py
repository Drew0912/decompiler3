"""The SSA path's ED9 HLIL entry point: ED9's MLIL -> HLIL conversion, then the types the SSA path inferred. The one
module here that imports the SSA packages: only the SSA path imports it, so the decompile path never loads them"""

from ir.hlil import HighLevelILFunction
from ir.hlil.mlil_ssa_types import apply_inferred_types
from ir.mlil_ssa import MediumLevelILFunctionSSA
from .hlil_converter import convert_ed9_mlil_to_hlil


def convert_ed9_mlil_ssa_to_hlil(mlil_func: MediumLevelILFunctionSSA, **flags) -> HighLevelILFunction:
    """The SSA path's HLIL: convert_ed9_mlil_to_hlil (flags as its), then the types the SSA path inferred, so no
    caller gets one without the other"""
    hlil_func = convert_ed9_mlil_to_hlil(mlil_func, **flags)
    apply_inferred_types(mlil_func, hlil_func)
    return hlil_func
