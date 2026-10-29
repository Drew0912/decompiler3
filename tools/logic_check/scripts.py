"""The logic check over a script: every function lifted and converted as the decompiler does (round_trip off,
unreachable code left out), its LLIL against its MLIL and its MLIL against its HLIL"""

from pathlib import Path
from typing import NamedTuple

from dc3.utils import raise_recursion_limit
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.parser.scp import ScpParser
from .compare import Difference, compare_facts
from .evaluation import analyze
from .gated_comparison import compare_gated
from .hlil_layer import HLILLayer
from .llil_layer import LLILLayer
from .mlil_layer import MLILLayer


class FunctionResult(NamedTuple):
    name: str
    mlil_differences: list[Difference]  # LLIL -> MLIL
    hlil_differences: list[Difference]  # MLIL -> HLIL
    decompile_error: str | None     # the function did not lift or convert: nothing compared (from there on)
    internal_error: str | None      # the check itself failed

    @classmethod
    def decompile_failed(cls, name: str, stage: str, error: Exception,
                         mlil_differences: list | None = None) -> FunctionResult:
        """The function did not lift or convert at stage: nothing compared from there on"""
        return cls(name, mlil_differences or [], [], f'{stage}: {type(error).__name__}: {error}', None)

    @classmethod
    def check_failed(cls, name: str, stage: str, error: Exception,
                     mlil_differences: list | None = None) -> FunctionResult:
        """The check itself failed at stage"""
        return cls(name, mlil_differences or [], [], None, f'{stage}: {type(error).__name__}: {error}')


def check_script(path: Path, game: str | None, *, infer_types: bool = True,
                 function_name: str | None = None) -> list[FunctionResult]:
    """Each function's LLIL -> MLIL and MLIL -> HLIL differences, or function_name's alone; a script the parser rejects
    raises"""
    raise_recursion_limit()     # a value tree nests as deep as a chain of pushes, an eager || chain's
    only = None if function_name is None else (lambda func: func.name == function_name)
    parser, functions = ScpParser.load(path, round_trip=False, keep_unreachable_code=False, game=game,
                                       filter_func=only)
    lifter = ED9VMLifter(parser=parser)
    return [check_function(lifter, func, infer_types) for func in functions]


def check_function(lifter: ED9VMLifter, func, infer_types: bool) -> FunctionResult:
    try:
        llil = lifter.lift_function(func)
    except Exception as e:
        return FunctionResult.decompile_failed(func.name, 'LLIL', e)

    try:
        reference = analyze(LLILLayer(llil))    # before the conversion: nothing it does to the LLIL counts
    except Exception as e:
        return FunctionResult.check_failed(func.name, 'LLIL', e)

    try:
        mlil = convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=infer_types)
    except Exception as e:
        return FunctionResult.decompile_failed(func.name, 'MLIL', e)

    try:
        differences = compare_facts(reference, analyze(MLILLayer(mlil)))
    except Exception as e:
        return FunctionResult.check_failed(func.name, 'MLIL', e)

    try:
        gated = analyze(MLILLayer(mlil, hlil_view=True), gated=True)
    except Exception as e:
        return FunctionResult.check_failed(func.name, 'MLIL gated', e, differences)

    try:
        hlil = convert_falcom_mlil_to_hlil(mlil, func)
    except Exception as e:
        return FunctionResult.decompile_failed(func.name, 'HLIL', e, differences)

    try:
        hlil_differences = compare_gated(gated, analyze(HLILLayer(hlil, mlil), gated=True))
    except Exception as e:
        return FunctionResult.check_failed(func.name, 'HLIL', e, differences)

    return FunctionResult(func.name, differences, hlil_differences, None, None)


def compare_mlil_hlil(mlil_func, hlil_func) -> list[Difference]:
    """One function's differences, its MLIL the reference"""
    return compare_gated(analyze(MLILLayer(mlil_func, hlil_view=True), gated=True),
                         analyze(HLILLayer(hlil_func, mlil_func), gated=True))
