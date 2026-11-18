"""A script decompiled to a .py (all in the LLIL DSL, or with a game the logic round trip's mixed file), and a
generated .py compiled in a subprocess"""

import contextlib
import io
import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

from dc3.utils import write_text_lf
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.formatter.hlil_dsl.script_formatter import HLILScriptFormatter
from falcom.ed9.formatter.llil_dsl.script_formatter import LLILScriptFormatter
from falcom.ed9.ir.hlil.hlil_converter import convert_ed9_mlil_to_hlil
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_ed9_llil_to_mlil_stack
from ir.hlil import HighLevelILFunction
from falcom.ed9.assembler.function import Function
from .results import MAX_DETAILS


# Runs a generated script as Python runs it directly: its __main__ block compiles it
ROUND_TRIP_RUNNER = "import runpy, sys; runpy.run_path(sys.argv[1], run_name='__main__')"


def decompile_to_python(dat_path: Path, py_path: Path, *, round_trip: bool = True, keep_unreachable_code: bool = True,
                        game: str | None = None) -> tuple[ScpParser, list[Function]]:
    """Same DSL emission as scp2py_base.py's process_file. Explicit flags rather than relying on
    ScpParser's class defaults, which happen to match round_trip=True today but aren't guaranteed to.
    Returns the parser and its disassembled functions so callers can fingerprint them without
    re-parsing."""
    with contextlib.redirect_stdout(io.StringIO()):
        parser, functions = ScpParser.load(dat_path, round_trip=round_trip, keep_unreachable_code=keep_unreachable_code,
                                           game=game)

    write_text_lf(py_path, LLILScriptFormatter(parser).gen_python_script(functions))
    return parser, functions


class LogicDecompile(NamedTuple):
    """A --logic-round-trip decompile: the parser, its functions and the names the .py holds in the HLIL DSL"""

    parser: ScpParser
    functions: list[Function]
    hlil_names: frozenset[str]


def logic_decompile(dat_path: Path, py_path: Path, game: str | None) -> LogicDecompile:
    """A --logic-round-trip decompile written to py_path: with a game the mixed <stem>.py as scp2py_base.py writes it
    (write_hlil_py: each function whose HLIL DSL text lowers exactly to its code in the HLIL DSL, the rest in the LLIL
    DSL); without one the all-LLIL .py, since a mixed file needs its game's DSL helper"""
    if game is None:
        parser, functions = decompile_to_python(dat_path, py_path, round_trip=False, keep_unreachable_code=False)
        return LogicDecompile(parser, functions, frozenset())

    with contextlib.redirect_stdout(io.StringIO()):
        parser, functions = ScpParser.load(dat_path, round_trip=False, keep_unreachable_code=False, game=game)

    formatter = LLILScriptFormatter(parser)
    matched = formatter.match_library_functions(functions)
    hlil_formatter = HLILScriptFormatter(parser, matched)
    for func in functions:
        hlil = dsl_hlil(parser, func)
        if hlil is not None:
            hlil_formatter.add(func, hlil)

    mixed, _ = formatter.gen_mixed_scripts(functions, hlil_formatter.lines, matched=matched)
    write_text_lf(py_path, mixed)
    return LogicDecompile(parser, functions, frozenset(hlil_formatter.lines))


def dsl_hlil(parser: ScpParser, func: Function) -> HighLevelILFunction | None:
    """func's HLIL with its line markers, as write_ir_outputs hands it to the HLIL DSL; None when the lift or a
    conversion raises (the function stays LLIL, as there)"""
    try:
        return convert_ed9_mlil_to_hlil(convert_ed9_llil_to_mlil_stack(ED9VMLifter(parser=parser).lift_function(func)))
    except Exception:
        return None


def compile_dsl(py_path: Path, run_dir: Path) -> tuple[int, list[str]]:
    """Compile a generated .py in a subprocess: (exit code, the last lines of its output, ascii-escaped). -P keeps
    run_dir off sys.path, so a script named after a top-level package (e.g. dc3.dat) can't shadow the real one; the
    script puts the repo root on sys.path itself"""
    env = dict(os.environ)
    env['PYTHONIOENCODING'] = 'utf-8'

    result = subprocess.run(
        [sys.executable, '-P', '-c', ROUND_TRIP_RUNNER, py_path.name],
        cwd=run_dir,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
    )

    tail = (result.stderr or result.stdout).strip().splitlines()[-MAX_DETAILS:]
    return result.returncode, [ascii(line) for line in tail]


def script_stem(path: Path) -> str:
    """path's name up to its first dot: the name a generated script and its rebuilt .dat take"""
    return path.name.split('.')[0]


def compile_round(stem: str, round_dir: Path, py_text: str) -> tuple[list[str], Path | None]:
    """One round's compile: writes py_text into round_dir and compiles it. Returns (the compile output's tail, the
    round's .dat path, or None when the compile failed)"""
    round_dir.mkdir()
    py_path = round_dir / f'{stem}.py'
    write_text_lf(py_path, py_text)

    returncode, tail = compile_dsl(py_path, round_dir)
    dat_path = round_dir / f'{stem}.dat'
    return tail, (dat_path if returncode == 0 and dat_path.exists() else None)
