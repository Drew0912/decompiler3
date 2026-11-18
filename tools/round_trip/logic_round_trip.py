"""--logic-round-trip: the source's audits, then compile -> decompile rounds to a fixed point, each round held
against the source"""

import shutil
import tempfile
from pathlib import Path

from falcom.ed9.structs.string_pool import collect_string_refs
from .format_checks import validate_file
from .generated_scripts import compile_round, logic_decompile, script_stem
from .logic_preserved import LogicSnapshot, check_mode, compare_logic
from .record_comparison import file_record_views
from .records_kept import check_records_kept, source_records
from .results import CheckResult, Status
from .script_context import load_script
from .source_audit import check_reachability, check_source_preconditions, check_string_fidelity


MAX_CONVERGENCE_ROUNDS = 4  # --logic-round-trip: give up if compile/decompile hasn't hit a fixed point by then


def check_logic_round_trip(path: Path, work_dir: Path, *, game: str | None = None) -> list[CheckResult]:
    """Decompile with round_trip=False (the everyday config), then iterate compile -> decompile
    until output stabilizes. Game logic must match the source on every round (function order and
    label names may differ); byte layout only needs to reach a fixed point within
    MAX_CONVERGENCE_ROUNDS. Every round runs in its own directory but keeps the same <stem>
    basename, since the generated header embeds it and a changing name would stop out2 == out3 from
    ever holding even at a real fixed point. With a game the .py is the mixed file (logic_decompile): the
    functions the source decompile prints in the HLIL DSL are compared without their line markers, and
    every round must print exactly those in it."""
    stem = script_stem(path)
    results = []

    ctx = load_script(path)
    try:
        pool_start = collect_string_refs(ctx.data, ctx.parser, ctx.records).pool_start
        results.append(check_source_preconditions(ctx, pool_start))
        results.append(check_reachability(ctx, pool_start))
        results.append(check_string_fidelity(ctx, pool_start))
        source_function_records = source_records(ctx)
    finally:
        ctx.fs.Close()

    file_dir = Path(tempfile.mkdtemp(prefix=f'{stem}_logic_', dir=work_dir))

    source = logic_decompile(path, file_dir / f'{stem}.py', game)
    hlil_names = source.hlil_names
    source_snapshot = LogicSnapshot.of(source.parser, source.functions, hlil_names)
    py_texts = [(file_dir / f'{stem}.py').read_text(encoding='utf-8')]
    dat_bytes = []

    for round_num in range(1, MAX_CONVERGENCE_ROUNDS + 1):
        round_dir = file_dir / f'r{round_num}'
        tail, dat_path = compile_round(stem, round_dir, py_texts[-1])
        if dat_path is None:
            results.append(CheckResult('logic round trip', Status.FAIL, f'round {round_num} compile failed, kept {file_dir}', tail))
            return results

        dat_bytes.append(dat_path.read_bytes())

        struct_results, _ = validate_file(dat_path)
        for result in struct_results:
            result.name = f'round {round_num} {result.name}'

        results.extend(struct_results)

        decompiled = logic_decompile(dat_path, round_dir / f'{stem}_out.py', game)
        py_texts.append((round_dir / f'{stem}_out.py').read_text(encoding='utf-8'))

        # Checked every round, not just round 1: a file that only diverges after round 1 but still
        # happens to reach a byte-level fixed point must still fail here
        round_snapshot = LogicSnapshot.of(decompiled.parser, decompiled.functions, hlil_names)
        for result in (compare_logic(source_snapshot, round_snapshot), check_mode(hlil_names, decompiled.hlil_names)):
            result.name = f'round {round_num} {result.name}'
            results.append(result)

        records_result = check_records_kept(source_function_records, file_record_views(dat_bytes[-1]))
        records_result.name = f'round {round_num} {records_result.name}'
        results.append(records_result)

        if round_num >= 2 and dat_bytes[-2] == dat_bytes[-1] and py_texts[-2] == py_texts[-1]:
            results.append(CheckResult('logic round trip', Status.PASS, f'converged at round {round_num}'))
            shutil.rmtree(file_dir, ignore_errors=True)
            return results

    results.append(CheckResult('logic round trip', Status.FAIL, f'no fixed point within {MAX_CONVERGENCE_ROUNDS} rounds, kept {file_dir}'))
    return results
