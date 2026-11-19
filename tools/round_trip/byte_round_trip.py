"""--round-trip: a file decompiled to its byte-exact <stem>.llil.py, recompiled and byte-compared with the original"""

import shutil
import tempfile
from pathlib import Path

from .generated_scripts import byte_exact_decompile, compile_dsl, script_stem
from .record_comparison import compare_file_records
from .results import CheckResult, Status, exception_text


def check_round_trip(path: Path, work_dir: Path, *, game: str | None = None) -> CheckResult:
    stem = script_stem(path)
    run_dir = Path(tempfile.mkdtemp(prefix=f'{stem}_', dir=work_dir))
    dat_path = run_dir / f'{stem}.dat'
    py_path = run_dir / f'{stem}.llil.py'

    shutil.copyfile(path, dat_path)
    byte_exact_decompile(dat_path, py_path, game)
    dat_path.unlink()

    returncode, tail = compile_dsl(py_path, run_dir)

    if returncode != 0 or not dat_path.exists():
        return CheckResult('round trip', Status.FAIL, f'recompile failed (exit {returncode}), kept {run_dir}', tail)

    original = path.read_bytes()
    rebuilt = dat_path.read_bytes()
    if original == rebuilt:
        shutil.rmtree(run_dir)
        return CheckResult('round trip', Status.PASS, f'identical ({len(original)} bytes)')

    summary, details = describe_difference(original, rebuilt)
    return CheckResult('round trip', Status.FAIL, f'{summary}, kept {run_dir}', details)


def describe_difference(original: bytes, rebuilt: bytes) -> tuple[str, list[str]]:
    """The round trip's summary of two differing files and its detail lines: where the bytes first differ, and how
    the debug records differ (compare_file_records). Records the comparison can't read keep the summary - otherwise
    the exception would reach main(), which reports it in place of the whole result."""
    first_diff = next((i for i, (a, b) in enumerate(zip(original, rebuilt)) if a != b),
                      min(len(original), len(rebuilt)))
    summary = f'differs at 0x{first_diff:X} (original {len(original)} bytes, rebuilt {len(rebuilt)} bytes)'
    try:
        lines = compare_file_records(original, rebuilt)
    except Exception as e:
        return f'{summary}, records unreadable', [f'records unreadable: {exception_text(e)}']

    if not lines:
        return f'{summary}, records identical', []

    return f'{summary}, records differ in {len(lines)} function{'' if len(lines) == 1 else 's'}', lines
