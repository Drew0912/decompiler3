"""The decompile pipeline each game's scp2py.py runs: ED9 .dat scripts into the Python DSL, TypeScript, .hlil.ts and
optional IR debug dumps.

Usage, from a game's launcher:
    python falcom/ed9/games/{game}/scp2py.py {file_path} [-o {output_dir}]

Flags live in scp2py_config.py, not on the command line (only the output folder has an
override, -o) - edit scp2py_config.py to change which outputs are written.
"""

import argparse
from pathlib import Path
from typing import Callable

from dc3.gc_policy import infrequent_gc
from dc3.logging import log
from dc3.utils import collect_paths, raise_recursion_limit, write_text_lf
from falcom.ed9.formatter.hlil_dsl.script_formatter import HLILScriptFormatter
from falcom.ed9.formatter.llil_dsl.comments import CommentOptions
from falcom.ed9.games import GAMES_DIR
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.formatter.llil_dsl.script_formatter import LLILListingFormatter, LLILScriptFormatter
from falcom.ed9.formatter.listing import write_listing
from falcom.ed9.formatter.format_hints import game_format_hints
from falcom.ed9.assembler.syscalls import game_syscall_args
from falcom.ed9.assembler.function import Function
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_formatter import ED9LLILFormatter
from falcom.ed9.ir.mlil.mlil_converter import convert_ed9_llil_to_mlil_stack
from falcom.ed9.ir.hlil.hlil_converter import convert_ed9_mlil_to_hlil, run_ed9_file_passes
from ir.mlil.mlil_formatter import MLILFormatter
from ir.hlil.hlil import HighLevelILFunction, HLILUnstructured, reachable_statements
from ir.hlil.hlil_formatter import HLILFormatter
from codegen import IdFormatHint, generate_typescript, generate_typescript_header
from falcom.ed9.scp2py_config import ScpDecompileConfig

GAME_OUTPUT_FOLDER = 'out'      # a game's default output folder, beside its launcher


def write_hook_template(parser: ScpParser, output_dir: Path) -> None:
    """A starting <stem>_hook.py next to the .py, never over an existing file"""
    module = LLILScriptFormatter(parser).hook_module_name()
    if '.' in module:
        log.warning(f"{parser.name}: hook template not written - a stem with a dot ({Path(parser.name).stem!r}) isn't supported")
        return

    path = output_dir / f'{module}.py'
    try:
        with open(path, 'x', encoding='utf-8', newline='\n') as f:
            f.write(LLILScriptFormatter(parser).gen_hook_template())
    except FileExistsError:
        log.info(f'{path} exists - not overwritten')


def output_root(config: ScpDecompileConfig, game: str) -> Path:
    """config.output_dir, or the game's out/ when it is None"""
    if config.output_dir is None:
        return GAMES_DIR / game / GAME_OUTPUT_FOLDER

    return config.output_dir


@infrequent_gc()
def process_file(path: Path, config: ScpDecompileConfig, *, game: str) -> None:
    raise_recursion_limit()

    output_dir = output_root(config, game) / path.stem
    out = output_dir / path.name

    parser, functions = ScpParser.load(path, round_trip=False, keep_unreachable_code=False, game=game,
                                       filter_func=config.filter_func)

    # Only create the output folder once parsing has actually produced something to write
    output_dir.mkdir(parents=True, exist_ok=True)

    comments = CommentOptions(
        stack_slots=config.stack_slot_comments,
        float_bits=config.float_bits_comments,
        function_ids=config.function_id_comments,
        call_args=config.call_arg_comments,
    )
    # <stem>.py needs each function's HLIL, so it is written after the IR outputs
    hlil_formatter = make_hlil_script_formatter(path, parser) if config.write_py else None
    converted = write_ir_outputs(path, parser, functions, config, out, hlil_formatter)
    if config.write_py:
        write_script(parser, functions, hlil_formatter, comments, out)

    if config.write_hook_template:
        write_hook_template(parser, output_dir)

    if config.write_llil_py:
        write_listing_script(path, parser, functions, config, comments, out)
    elif config.round_trip:
        log.warning(f'{path}: round_trip changes only {path.stem}.llil.py, and write_llil_py is off: nothing written')

    # After the scripts, so a failure in the file-level passes can't cost them
    if config.write_ts:
        write_typescript(path, parser, converted, config, out)

    # Last: the debug listing loads the file again, so its failure can't cost the other outputs
    if config.write_debug_info:
        write_listing(path, out.with_suffix('.debug.txt'), config.debug_sections, {func.index for func in functions})


def make_hlil_script_formatter(path: Path, parser: ScpParser) -> HLILScriptFormatter | None:
    """The file's HLIL DSL formatter; None, with a warning, when it can't be set up (<stem>.py is then all LLIL)"""
    try:
        return HLILScriptFormatter(parser)
    except Exception as e:
        log.warning(f'{path}: HLIL DSL not written ({type(e).__name__}: {e}); {path.stem}.py is all in the LLIL DSL')
        return None


def write_script(parser: ScpParser, functions: list[Function], hlil_formatter: HLILScriptFormatter | None,
                 comments: CommentOptions, out: Path):
    """<stem>.py with each function the DSL holds in it; all LLIL when the DSL couldn't be set up"""
    script = LLILScriptFormatter(parser) if hlil_formatter is None else hlil_formatter
    matched = script.match_library_functions(functions)     # once, for the log and the script
    if hlil_formatter is not None:
        hlil_formatter.log(script.get_inline_functions(functions, matched=matched))

    write_text_lf(out.with_suffix('.py'), script.gen_python_script(functions, comments=comments, matched=matched))


def write_listing_script(path: Path, parser: ScpParser, functions: list[Function], config: ScpDecompileConfig,
                         comments: CommentOptions, out: Path):
    """<stem>.llil.py; with round_trip from a second parse that keeps every byte, so it compiles to the original's.
    A failure (that parse is stricter) is logged, so it can't cost the outputs after it"""
    try:
        if config.round_trip:
            parser, functions = ScpParser.load_bytes(path.read_bytes(), path.name, round_trip=True,
                                                     keep_unreachable_code=True, game=parser.game,
                                                     filter_func=config.filter_func, quiet=True)

        listing = LLILListingFormatter(parser).gen_python_script(functions, comments=comments)
    except Exception as e:
        log.warning(f'{path}: {path.stem}.llil.py not written ({type(e).__name__}: {e})')
        return

    write_text_lf(out.with_suffix('.llil.py'), listing)


def callee_default_values(parser: ScpParser) -> dict[str, tuple]:
    """Each function's parameter defaults (None: none) as the IR holds them, by name - the values its .ts signature
    prints; no type lookup, so a function the outputs skip can't fail it"""
    lifter = ED9VMLifter(parser=parser)
    return {func.name: tuple(lifter.source_value(param.default_value.value) if param.default_value is not None else None
                             for param in func.params)
            for func in parser.functions}


def write_ir_outputs(path: Path, parser: ScpParser, functions: list[Function], config: ScpDecompileConfig, out: Path,
                     hlil_formatter: HLILScriptFormatter | None) -> list[tuple[Function, HighLevelILFunction]]:
    """The .llil.asm, .mlil.asm, .hlil.ts and .dot outputs the config asks for; with hlil_formatter, each function's
    HLIL handed to it. With write_ts, each function whose HLIL came out is returned, for write_typescript"""
    output_dir = out.parent

    need_file_passes = config.write_ts    # the outputs that read the file-level passes' facts
    need_hlil = config.write_hlil_ts or need_file_passes or hlil_formatter is not None
    need_mlil = config.write_mlil_asm or config.write_mlil_dot or need_hlil
    if not (config.write_llil_asm or config.write_llil_dot or need_mlil):
        return []

    llil_asm_lines: list[str] = []
    mlil_asm_lines: list[str] = []
    hlil_ts_lines: list[str] = []
    converted: list[tuple[Function, HighLevelILFunction]] = []  # each function whose HLIL came out

    for func in functions:
        try:
            llil_func = ED9VMLifter(parser=parser).lift_function(func)

            if config.write_llil_asm:
                llil_asm_lines.extend(ED9LLILFormatter.format_llil_function(llil_func))

            if config.write_llil_dot:
                write_text_lf(output_dir / f'{out.stem}.{func.name}.llil.dot', ED9LLILFormatter.to_dot(llil_func))

            if not need_mlil:
                continue

            mlil_func = convert_ed9_llil_to_mlil_stack(llil_func)

            if config.write_mlil_asm:
                mlil_asm_lines.extend(MLILFormatter.format_function(mlil_func))

            if config.write_mlil_dot:
                write_text_lf(output_dir / f'{out.stem}.{func.name}.mlil.dot', MLILFormatter.to_dot(mlil_func))

            if not need_hlil:
                continue

            hlil_func = convert_ed9_mlil_to_hlil(mlil_func, line_markers=config.line_markers)

            unstructured_targets = [stmt.target for stmt in reachable_statements(hlil_func.body)
                                    if isinstance(stmt, HLILUnstructured)]
            if unstructured_targets:
                log.warning(f'{path} [{func.name}]: {len(unstructured_targets)} unstructured jump(s) to '
                            f'{', '.join(unstructured_targets)}')

            if config.write_hlil_ts:
                hlil_ts_lines.extend(HLILFormatter.format_function(hlil_func))

            if need_file_passes:
                converted.append((func, hlil_func))

            # Last, so its failure costs no other output; the DSL's forms never depend on line_markers
            if hlil_formatter is not None:
                hlil_with_line_markers = hlil_func if config.line_markers else convert_ed9_mlil_to_hlil(mlil_func)
                hlil_formatter.add(func, hlil_with_line_markers)
        except Exception as e:
            # One bad function shouldn't lose the rest of the file's output
            log.warning(f'{path} [{func.name}]: {type(e).__name__}: {e}')

    if config.write_llil_asm:
        write_text_lf(out.with_suffix('.llil.asm'), '\n'.join(llil_asm_lines))

    if config.write_mlil_asm:
        write_text_lf(out.with_suffix('.mlil.asm'), '\n'.join(mlil_asm_lines))

    if config.write_hlil_ts:
        write_text_lf(out.with_suffix('.hlil.ts'), '\n'.join(hlil_ts_lines))

    return converted


def write_typescript(path: Path, parser: ScpParser, converted: list[tuple[Function, HighLevelILFunction]],
                     config: ScpDecompileConfig, out: Path) -> None:
    """The .ts, after the file-level passes over every converted function, whose facts it reads (the types; with the
    game's syscall rows, the ID marks and tags)"""
    warn = function_warning(path)
    syscall_args = game_syscall_args(parser.game) if config.id_names else None
    run_ed9_file_passes([hlil_func for _, hlil_func in converted], parser.functions, syscall_args, warn)

    id_hints = game_format_hints(parser.game) if syscall_args is not None else None
    write_ts(parser, converted, id_hints, warn, out)


def function_warning(path: Path) -> Callable[[str, Exception], None]:
    """Logs a function's failure in path by its name"""
    def warn(name: str, error: Exception):
        log.warning(f'{path} [{name}]: {type(error).__name__}: {error}')

    return warn


def write_ts(parser: ScpParser, converted: list[tuple[Function, HighLevelILFunction]],
             id_hints: dict[str, IdFormatHint] | None, warn: Callable[[str, Exception], None], out: Path) -> None:
    """The .ts: each converted function's TypeScript, after the file-level passes; with id_hints, an ID prints by
    name"""

    # From the whole function table (callees the output omits included): .ts leaves out a call's trailing arguments
    # equal to these defaults
    callee_defaults = callee_default_values(parser)

    # Each function on its own, as in write_ir_outputs: one that fails to print can't cost the rest
    ts_chunks = []
    for func, hlil_func in converted:
        try:
            ts_chunks.append(generate_typescript(hlil_func, callee_defaults, id_hints))
        except Exception as e:
            warn(func.name, e)

    write_text_lf(out.with_suffix('.ts'), generate_typescript_header(id_hints) + '\n'.join(ts_chunks))


def main(game: str) -> int:
    arg_parser = argparse.ArgumentParser(
        description=f'Decompile {game} .dat scripts into the Python DSL, TypeScript, .hlil.ts and optional debug dumps')
    arg_parser.add_argument('paths', nargs='+', help='.dat files or directories (searched recursively)')
    arg_parser.add_argument('-o', '--output-dir', type=Path,
                            help=f"output folder (default: scp2py_config.py's output_dir, or {game}'s out/)")

    args = arg_parser.parse_args()
    files = collect_paths(args.paths)
    config = ScpDecompileConfig()
    if args.output_dir is not None:
        config.output_dir = args.output_dir

    failures = 0
    for path in files:
        log.info(f'Decompiling {path}')

        try:
            process_file(path, config, game=game)
        except Exception as e:
            log.error(f'{path}: {type(e).__name__}: {e}')
            failures += 1

    log.info(f'{len(files) - failures}/{len(files)} succeeded')
    return 1 if failures else 0
