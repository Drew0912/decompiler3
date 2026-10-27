"""The logic check over a script: every function lifted and converted as the decompiler does (round_trip off,
unreachable code left out), its LLIL against its MLIL"""

import time
from pathlib import Path
from typing import NamedTuple

from dc3.utils import raise_recursion_limit
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.parser.scp import ScpParser
from .compare import Difference, compare_facts
from .evaluation import analyze
from .llil_layer import LLILLayer
from .mlil_layer import MLILLayer


class FunctionResult(NamedTuple):
    name: str
    differences: list[Difference]
    decompile_error: str | None     # the function did not lift or convert: nothing compared
    internal_error: str | None      # the check itself failed
    seconds: float                  # the check's own time, the decompile's left out


def check_script(path: Path, game: str | None, *, infer_types: bool = True) -> list[FunctionResult]:
    """Each function's LLIL -> MLIL differences; a script the parser rejects raises"""
    raise_recursion_limit()     # a value tree nests as deep as a chain of pushes, an eager || chain's
    parser, functions = ScpParser.load(path, round_trip=False, keep_unreachable_code=False, game=game)
    lifter = ED9VMLifter(parser=parser)
    results = []
    for func in functions:
        try:
            llil = lifter.lift_function(func)
        except Exception as e:
            results.append(FunctionResult(func.name, [], f'{type(e).__name__}: {e}', None, 0.0))
            continue

        started = time.perf_counter()
        try:
            reference = analyze(LLILLayer(llil))    # before the conversion, so nothing it does to the LLIL counts
        except Exception as e:
            results.append(FunctionResult(func.name, [], None, f'LLIL: {type(e).__name__}: {e}', 0.0))
            continue
        seconds = time.perf_counter() - started

        try:
            mlil = convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=infer_types)
        except Exception as e:
            results.append(FunctionResult(func.name, [], f'{type(e).__name__}: {e}', None, seconds))
            continue

        started = time.perf_counter()
        try:
            differences = compare_facts(reference, analyze(MLILLayer(mlil)))
        except Exception as e:
            results.append(FunctionResult(func.name, [], None, f'MLIL: {type(e).__name__}: {e}', seconds))
            continue
        results.append(FunctionResult(func.name, differences, None, None, seconds + time.perf_counter() - started))

    return results


def compare_llil_mlil(llil_func, mlil_func) -> list[Difference]:
    """One function's differences, its LLIL the reference"""
    return compare_facts(analyze(LLILLayer(llil_func)), analyze(MLILLayer(mlil_func)))
