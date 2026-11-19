"""--logic-round-trip: the source's audits, then compile -> decompile rounds to a fixed point, each round held
against the source"""

import shutil
import tempfile
from pathlib import Path

from falcom.ed9.structs.string_pool import collect_string_refs
from .format_checks import validate_file
from .generated_scripts import compile_round, logic_decompile, script_stem
from .logic_preserved import LogicSnapshot, check_logic_preserved, check_same_hlil_functions
from .record_comparison import file_record_views
from .records_kept import SourceRecords, check_records_kept, source_records
from .results import CheckResult, Status
from .script_context import load_script
from .source_audit import check_reachability, check_source_preconditions, check_string_fidelity


MAX_CONVERGENCE_ROUNDS = 4  # give up when compile -> decompile has no fixed point by then


def audit_source(path: Path) -> tuple[list[CheckResult], dict[str, SourceRecords]]:
    """The source's checks before any round, and the records each round is held against"""
    with load_script(path) as ctx:
        pool_start = collect_string_refs(ctx.data, ctx.parser, ctx.records).pool_start
        audits = [
            check_source_preconditions(ctx, pool_start),
            check_reachability(ctx, pool_start),
            check_string_fidelity(ctx, pool_start),
        ]
        return audits, source_records(ctx)


def named_for_round(round_num: int, results: list[CheckResult]) -> list[CheckResult]:
    """results, each name prefixed with its round: 'round 2 layout'"""
    for result in results:
        result.name = f'round {round_num} {result.name}'

    return results


def stopped_changing(history: list[bytes] | list[str]) -> bool:
    return len(history) >= 2 and history[-2] == history[-1]


def check_logic_round_trip(path: Path, work_dir: Path, *, game: str | None = None) -> list[CheckResult]:
    """Decompile with round_trip=False (the everyday config), then compile -> decompile until the output stops
    changing: every round keeps the source's game logic (function order and label names may differ), and the bytes
    reach a fixed point within MAX_CONVERGENCE_ROUNDS; with a game the .py is the mixed file (logic_decompile): the
    source decompile's HLIL DSL functions are compared without their line markers, and every round prints exactly
    those in it"""
    stem = script_stem(path)
    results, source_function_records = audit_source(path)

    file_dir = Path(tempfile.mkdtemp(prefix=f'{stem}_logic_', dir=work_dir))
    source_py = file_dir / f'{stem}.py'
    source = logic_decompile(path, source_py, game)
    hlil_names = source.hlil_names
    source_snapshot = LogicSnapshot.of(source.parser, source.functions, hlil_names)
    py_texts = [source_py.read_text(encoding='utf-8')]
    dat_bytes = []

    for round_num in range(1, MAX_CONVERGENCE_ROUNDS + 1):
        # Same <stem> every round: the generated header embeds it, so a new name would keep out2 != out3 at a real
        # fixed point
        round_dir = file_dir / f'r{round_num}'
        tail, dat_path = compile_round(stem, round_dir, py_texts[-1])
        if dat_path is None:
            results.append(CheckResult('logic round trip', Status.FAIL,
                                       f'round {round_num} compile failed, kept {file_dir}', tail))
            return results

        dat_bytes.append(dat_path.read_bytes())
        format_results, _ = validate_file(dat_path)
        round_py = round_dir / f'{stem}_out.py'
        decompiled = logic_decompile(dat_path, round_py, game)
        py_texts.append(round_py.read_text(encoding='utf-8'))

        # Checked every round, not just round 1: a file that only diverges after round 1 but still
        # happens to reach a byte-level fixed point must still fail here
        round_snapshot = LogicSnapshot.of(decompiled.parser, decompiled.functions, hlil_names)
        results += named_for_round(round_num, [
            *format_results,
            check_logic_preserved(source_snapshot, round_snapshot),
            check_same_hlil_functions(hlil_names, decompiled.hlil_names),
            check_records_kept(source_function_records, file_record_views(dat_bytes[-1])),
        ])

        if stopped_changing(dat_bytes) and stopped_changing(py_texts):
            results.append(CheckResult('logic round trip', Status.PASS, f'converged at round {round_num}'))
            shutil.rmtree(file_dir, ignore_errors=True)
            return results

    results.append(CheckResult('logic round trip', Status.FAIL,
                               f'no fixed point within {MAX_CONVERGENCE_ROUNDS} rounds, kept {file_dir}'))
    return results
