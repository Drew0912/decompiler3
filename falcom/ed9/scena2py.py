"""Decompile ED9 .dat scripts into the Python DSL, TypeScript, and optional IR debug dumps.

Usage:
    python falcom/ed9/scena2py.py {file_path}

Flags live in scena2py_config.py, not on the command line - edit scena2py_config.py to
change which outputs are written and which ScpParser/MLIL flags are used.
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from common.logging import log
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.parser.types_parser import Function
from falcom.ed9.parser.types_scp import ScpFunctionEntry
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.mlil.mlil_formatter import MLILFormatter
from ir.hlil.hlil import HLILUnstructured, reachable_statements
from ir.hlil.hlil_formatter import HLILFormatter
from codegen import generate_typescript, generate_typescript_header
from falcom.ed9.scena2py_config import ScenaDecompileConfig

DAT_PATTERN = '*.dat'

# The HLIL passes and the TS generator recurse once or twice per nesting level, and Python's
# default limit of 1000 is close for the most deeply nested scripts; a RecursionError would drop
# that function from the output. Past the real C stack, Python still raises rather than crashing.
RECURSION_LIMIT = 10000

def collect_paths(paths: list[str]) -> list[Path]:
    """Expand directories (recursively) to their .dat files; keep file paths as-is"""
    files = []

    for name in paths:
        path = Path(name)

        if path.is_dir():
            files.extend(sorted(path.rglob(DAT_PATTERN)))

        else:
            files.append(path)

    return files

COMMON_FUNCTIONS_OMITTED_COMMENT = (
    '# Common/shared functions were omitted (include_common_functions = False).\n'
    '# This script will NOT compile back to a .dat file: calls below reference\n'
    '# common function definitions that are not present in this file.'
)

def write_python_dsl(parser: ScpParser, functions: list[Function], out_path: Path, *, common_functions_omitted: bool = False) -> None:
    preamble = [*COMMON_FUNCTIONS_OMITTED_COMMENT.splitlines(), ''] if common_functions_omitted else []
    out_path.write_text(parser.gen_python_script(functions, preamble = preamble), encoding = 'utf-8', newline = '\n')

def write_debug_info(parser: ScpParser, functions: list[Function], out_path: Path) -> None:
    """Dump the parsed header, each function's raw ScpFunctionEntry, and its per-call debug info"""
    entry_by_name: dict[str, ScpFunctionEntry] = dict(zip((f.name for f in parser.functions), parser.function_entries))

    lines = ['=== Header ===', str(parser.header), '']

    for func in functions:
        lines.append(f'=== {func.name} ===')
        lines.append('--- function_entry ---')
        lines.append(str(entry_by_name[func.name]))
        lines.append('')
        lines.append(f'--- debug_info ({len(func.debug_info)} calls) ---')

        for dbg in func.debug_info:
            lines.append(str(dbg))

        lines.append('')

    out_path.write_text('\n'.join(lines) + '\n', encoding = 'utf-8', newline = '\n')

def process_file(path: Path, config: ScenaDecompileConfig) -> None:
    sys.setrecursionlimit(max(sys.getrecursionlimit(), RECURSION_LIMIT))

    output_dir = config.output_dir / path.stem
    out = output_dir / path.name
    out_no_suffix = out.with_suffix('')

    parser, functions = ScpParser.load(path, round_trip = config.round_trip, keep_unreachable_code = config.keep_unreachable_code, filter_func = config.filter_func)

    common_functions_omitted = not config.include_common_functions
    if common_functions_omitted:
        functions = [func for func in functions if not func.is_common_func]

    # Only create the output folder once parsing has actually produced something to write
    output_dir.mkdir(parents = True, exist_ok = True)

    if config.write_py:
        write_python_dsl(parser, functions, out.with_suffix('.py'), common_functions_omitted = common_functions_omitted)

    if config.write_debug_info:
        write_debug_info(parser, functions, out.with_suffix('.debug.txt'))

    need_llil = config.write_llil_asm or config.write_llil_dot or config.write_mlil_asm or config.write_mlil_dot or config.write_hlil_ts or config.write_ts
    if not need_llil:
        return

    llil_asm_lines: list[str] = []
    mlil_asm_lines: list[str] = []
    hlil_ts_lines: list[str] = []
    ts_chunks: list[str] = []

    for func in functions:
        try:
            llil_func = ED9VMLifter(parser = parser).lift_function(func)

            if config.write_llil_asm:
                llil_asm_lines.extend(FalcomLLILFormatter.format_llil_function(llil_func))

            if config.write_llil_dot:
                (output_dir / f'{out_no_suffix.name}.{func.name}.llil.dot').write_text(FalcomLLILFormatter.to_dot(llil_func), encoding = 'utf-8', newline = '\n')

            need_mlil = config.write_mlil_asm or config.write_mlil_dot or config.write_hlil_ts or config.write_ts
            if not need_mlil:
                continue

            mlil_func = convert_falcom_llil_to_mlil(llil_func, parser, optimize = config.optimize_mlil, infer_types = config.infer_types)

            if config.write_mlil_asm:
                mlil_asm_lines.extend(MLILFormatter.format_function(mlil_func))

            if config.write_mlil_dot:
                (output_dir / f'{out_no_suffix.name}.{func.name}.mlil.dot').write_text(MLILFormatter.to_dot(mlil_func), encoding = 'utf-8', newline = '\n')

            if not (config.write_hlil_ts or config.write_ts):
                continue

            hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

            unstructured_targets = [stmt.target for stmt in reachable_statements(hlil_func.body)
                                    if isinstance(stmt, HLILUnstructured)]
            if unstructured_targets:
                log.warning(f'{path} [{func.name}]: {len(unstructured_targets)} unstructured jump(s) to '
                            f'{", ".join(unstructured_targets)}')

            if config.write_hlil_ts:
                hlil_ts_lines.extend(HLILFormatter.format_function(hlil_func))

            if config.write_ts:
                ts_chunks.append(generate_typescript(hlil_func))

        except Exception as e:
            # One bad function shouldn't lose the rest of the file's output
            log.warning(f'{path} [{func.name}]: {type(e).__name__}: {e}')

    if config.write_llil_asm:
        out.with_suffix('.llil.asm').write_text('\n'.join(llil_asm_lines), encoding = 'utf-8', newline = '\n')

    if config.write_mlil_asm:
        out.with_suffix('.mlil.asm').write_text('\n'.join(mlil_asm_lines), encoding = 'utf-8', newline = '\n')

    if config.write_hlil_ts:
        out.with_suffix('.hlil.ts').write_text('\n'.join(hlil_ts_lines), encoding = 'utf-8', newline = '\n')

    if config.write_ts:
        out.with_suffix('.ts').write_text(generate_typescript_header() + '\n'.join(ts_chunks), encoding = 'utf-8', newline = '\n')

def main() -> int:
    parser = argparse.ArgumentParser(description = 'Decompile ED9 .dat scripts into the Python DSL, TypeScript, and optional IR debug dumps')
    parser.add_argument('paths', nargs = '+', help = '.dat files or directories (searched recursively)')

    args = parser.parse_args()
    files = collect_paths(args.paths)
    config = ScenaDecompileConfig()

    failures = 0
    for path in files:
        log.info(f'Decompiling {path}')

        try:
            process_file(path, config)

        except Exception as e:
            log.error(f'{path}: {type(e).__name__}: {e}')
            failures += 1

    log.info(f'{len(files) - failures}/{len(files)} succeeded')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
