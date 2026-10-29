"""
IR Semantic Consistency Validator

Checks, per function of an SCP file, that each IR layer keeps the game logic of the one below it - LLIL against MLIL
and MLIL against HLIL - by the logic check (tools/logic_check/): each difference with its category, read with
docs/VALIDATOR_GUIDE.md. The file is decompiled as the decompiler does (round_trip off, unreachable code left out).
A regression export holds every function's differences; a later run compared with it reports each difference new
since the export (a regression) or gone (an improvement), by its category and key.

Usage:
    python tools/ir_semantic_validator.py test.dat                      (every function, both pairs: --batch)
    python tools/ir_semantic_validator.py --compare llil mlil test.dat
    python tools/ir_semantic_validator.py --all test.dat
    python tools/ir_semantic_validator.py test.dat --export-regression before.json
    python tools/ir_semantic_validator.py test.dat --compare-regression before.json
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, NamedTuple, TextIO

sys.path.insert(0, str(Path(__file__).parent.parent))

from logic_check import Difference, FunctionResult, check_script
from logic_check.compare import brief

BASELINE_VERSION = '3.0'        # the logic check's; 2.0 was the block matcher's
CHECK = 'tools/logic_check'
REFUSED = 2                     # exit code: a baseline of another version, which this validator cannot compare


# === Layer pairs ===

class Pair(NamedTuple):
    key: str                                                            # the JSON key
    label: str
    differences: Callable[[FunctionResult], list[Difference] | None]    # None: not compared (FunctionResult)


PAIRS = (
    Pair('llil_mlil', 'LLIL->MLIL', lambda result: result.mlil_differences),
    Pair('mlil_hlil', 'MLIL->HLIL', lambda result: result.hlil_differences),
)
PAIRS_BY_LAYERS = {('llil', 'mlil'): PAIRS[0], ('mlil', 'hlil'): PAIRS[1]}


def failed(result: FunctionResult, pairs: tuple[Pair, ...]) -> bool:
    """A difference in pairs, or the check's own error; a decompile error is the decompiler's, shown but not failed"""
    return result.internal_error is not None or any(pair.differences(result) for pair in pairs)


# === IR Pipeline ===

class IRPipeline:
    """An SCP file's functions through the logic check, decompiled as the decompiler does"""

    def __init__(self, scp_path: str):
        self.scp_path = scp_path
        self.results: list[FunctionResult] = []

    def check(self, function_name: str | None = None) -> bool:
        """Every function's results, or function_name's alone; False, the reason on stderr, when the file does not
        parse or holds no such function"""
        try:
            self.results = check_script(Path(self.scp_path), None, function_name=function_name)
        except Exception as e:
            print(f'Error parsing SCP file: {e}', file=sys.stderr)
            return False
        if not self.results:
            print('No functions found', file=sys.stderr)
            return False
        return True


# === Output ===

def difference_json(difference: Difference) -> list[str]:
    """[category, key, detail]: the key as its repr, the detail cut (brief)"""
    return [difference.category, repr(difference.key), brief(difference.detail)]


def function_json(result: FunctionResult, pairs: tuple[Pair, ...] = PAIRS) -> dict[str, Any]:
    """A pair not compared as [], as a clean one: the error fields say where the check stopped"""
    return {'function': result.name,
            **{pair.key: [difference_json(difference) for difference in pair.differences(result) or []]
               for pair in pairs},
            'decompile_error': result.decompile_error, 'internal_error': result.internal_error}


def report_json(pipeline: IRPipeline, pairs: tuple[Pair, ...] = PAIRS) -> dict[str, Any]:
    """The --json report, and the regression file"""
    return {'version': BASELINE_VERSION, 'check': CHECK, 'file': pipeline.scp_path,
            'functions': [function_json(result, pairs) for result in pipeline.results]}


class Formatter:
    """The text report, in color or not"""

    def __init__(self, use_color: bool = True):
        self.green  = '\033[32m' if use_color else ''
        self.yellow = '\033[33m' if use_color else ''
        self.red    = '\033[31m' if use_color else ''
        self.cyan   = '\033[36m' if use_color else ''
        self.dim    = '\033[2m' if use_color else ''
        self.reset  = '\033[0m' if use_color else ''

    def pair_lines(self, result: FunctionResult, pair: Pair) -> list[str]:
        differences = pair.differences(result)
        if differences is None:
            return [f'    {pair.label}: {self.yellow}not compared{self.reset}']
        if not differences:
            return [f'    {pair.label}: {self.green}PASS{self.reset}']
        counted = f"{len(differences)} difference{'s' if len(differences) > 1 else ''}"
        return [f'    {pair.label}: {self.red}FAIL{self.reset} ({counted})',
                *(f'      {difference.category}  {difference.key!r}  {self.dim}{brief(difference.detail)}{self.reset}'
                  for difference in differences)]

    def function_lines(self, result: FunctionResult, pairs: tuple[Pair, ...]) -> list[str]:
        lines = [f'  {self.cyan}{result.name}{self.reset}']
        for pair in pairs:
            lines += self.pair_lines(result, pair)
        if result.decompile_error:
            lines.append(f'    {self.yellow}decompile error: {result.decompile_error}{self.reset}')
        if result.internal_error:
            lines.append(f'    {self.red}internal error: {result.internal_error}{self.reset}')
        return lines

    def summary_lines(self, results: list[FunctionResult], pairs: tuple[Pair, ...]) -> list[str]:
        """Per pair the functions compared clean and the differences by category; then the errors"""
        lines = []
        for pair in pairs:
            checked = [differences for differences in map(pair.differences, results) if differences is not None]
            clean = sum(1 for differences in checked if not differences)
            by_category = Counter(difference.category for differences in checked for difference in differences)
            line = f'{pair.label}: {clean}/{len(checked)} functions without differences'
            if by_category:
                line += ' (' + ', '.join(f'{category} {count}' for category, count in sorted(by_category.items())) + ')'
            lines.append(line)
        decompile_errors = sum(1 for result in results if result.decompile_error)
        internal_errors = sum(1 for result in results if result.internal_error)
        if decompile_errors or internal_errors:
            lines.append(f'Decompile errors: {decompile_errors}, internal errors: {internal_errors}')
        return lines


class Validator:
    """Prints a pipeline's results"""

    def __init__(self, pipeline: IRPipeline, formatter: Formatter, stream: TextIO = sys.stdout,
                 as_json: bool = False, failed_only: bool = False):
        self.pipeline = pipeline
        self.fmt = formatter
        self.stream = stream
        self.as_json = as_json
        self.failed_only = failed_only

    def _print(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    def report(self, pairs: tuple[Pair, ...]) -> int:
        """Each function's results for pairs, then the summary; 1 if any function failed (failed)"""
        results = self.pipeline.results
        if self.as_json:
            self._print(json.dumps(report_json(self.pipeline, pairs), indent=2, ensure_ascii=False))
        else:
            labels = ' and '.join(pair.label for pair in pairs)
            self._print(f'{self.fmt.cyan}=== {self.pipeline.scp_path}: {labels} ==={self.fmt.reset}')
            self._print(f'Functions: {len(results)}\n')
            for result in results:
                if not self.failed_only or failed(result, pairs) or result.decompile_error:
                    self._print('\n'.join(self.fmt.function_lines(result, pairs)))
            self._print('\n' + '\n'.join(self.fmt.summary_lines(results, pairs)))
        return 1 if any(failed(result, pairs) for result in results) else 0

    def compare(self, layer1: str, layer2: str) -> int:
        """One layer pair across all functions"""
        pair = PAIRS_BY_LAYERS.get((layer1.lower(), layer2.lower()))
        if pair is None:
            print(f'Unsupported layer pair: {layer1} -> {layer2}', file=sys.stderr)
            return 1
        return self.report((pair,))

    def batch(self) -> int:
        """Both layer pairs, function by function"""
        return self.report(PAIRS)

    def output_dir(self, dir_path: str) -> int:
        """Each layer pair's report in a file of its own"""
        out_path = Path(dir_path)
        out_path.mkdir(parents=True, exist_ok=True)
        scp_name = Path(self.pipeline.scp_path).stem
        exit_code = 0
        for pair in PAIRS:
            pair_file = out_path / f'{scp_name}_{pair.key}.txt'
            with open(pair_file, 'w', encoding='utf-8', newline='\n') as f:
                file_validator = Validator(self.pipeline, Formatter(use_color=False), f, self.as_json, self.failed_only)
                exit_code = max(exit_code, file_validator.report((pair,)))
            print(f'{pair.label}: {pair_file}', file=sys.stderr)
        return exit_code


# === CLI ===

def create_parser() -> argparse.ArgumentParser:
    arg_parser = argparse.ArgumentParser(description='IR Semantic Consistency Validator (the logic check)')
    arg_parser.add_argument('scp_file', help='Path to SCP file')
    arg_parser.add_argument('--compare', nargs=2, metavar=('LAYER1', 'LAYER2'),
                            help='Compare two IR layers (llil mlil, or mlil hlil)')
    arg_parser.add_argument('--all', action='store_true', help='Compare both layer pairs, one after the other')
    arg_parser.add_argument('--batch', action='store_true', help='Both layer pairs, function by function (the default)')
    arg_parser.add_argument('--json', action='store_true', help='Output in JSON format')
    arg_parser.add_argument('--no-color', action='store_true', help='Disable color output')
    arg_parser.add_argument('--function', metavar='NAME', help='Check one function only')
    arg_parser.add_argument('--failed-only', action='store_true',
                            help='Show only functions with a difference or an error')
    arg_parser.add_argument('--export-regression', metavar='FILE', help='Export regression baseline')
    arg_parser.add_argument('--compare-regression', metavar='FILE', help='Compare against regression baseline')
    arg_parser.add_argument('--output-dir', metavar='DIR', help='Write results to separate files per layer pair')
    return arg_parser


# === Regression Testing ===

def export_baseline(pipeline: IRPipeline, output_file: str) -> bool:
    """The results as a regression baseline (report_json)"""
    try:
        Path(output_file).write_text(json.dumps(report_json(pipeline), indent=2, ensure_ascii=False) + '\n',
                                     encoding='utf-8', newline='\n')
        return True
    except OSError as e:
        print(f'Error exporting baseline: {e}', file=sys.stderr)
        return False


class Change(NamedTuple):
    function: str
    what: str       # a pair's label, or the kind of error
    found: str      # the difference, `category key`, or the error


def changes(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, list]:
    """current against baseline, two report_json documents: per function and pair the differences new since the
    baseline (regressions) and gone (improvements), by category and key, with each function's new and gone errors;
    and the functions only one of them holds"""
    before = {entry['function']: entry for entry in baseline['functions']}
    after = {entry['function']: entry for entry in current['functions']}
    found = {'regressions': [], 'improvements': [], 'functions_added': sorted(after.keys() - before.keys()),
             'functions_gone': sorted(before.keys() - after.keys())}
    for name in sorted(before.keys() & after.keys()):
        old, new = before[name], after[name]
        for pair in PAIRS:
            was = Counter((category, key) for category, key, _ in old.get(pair.key, []))
            now = Counter((category, key) for category, key, _ in new.get(pair.key, []))
            found['regressions'] += [Change(name, pair.label, f'{category} {key}')
                                     for category, key in sorted((now - was).elements())]
            found['improvements'] += [Change(name, pair.label, f'{category} {key}')
                                      for category, key in sorted((was - now).elements())]
        for error in ('decompile_error', 'internal_error'):
            if old[error] != new[error]:
                what = error.replace('_', ' ')
                if new[error]:
                    found['regressions'].append(Change(name, what, new[error]))
                if old[error]:
                    found['improvements'].append(Change(name, what, old[error]))
    return found


def compare_baseline(pipeline: IRPipeline, baseline_file: str) -> int:
    """The results against a regression baseline (changes): 1 on a regression; REFUSED for a baseline of another
    version"""
    try:
        baseline = json.loads(Path(baseline_file).read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        print(f'Error loading baseline: {e}', file=sys.stderr)
        return 1
    if baseline.get('version') != BASELINE_VERSION:
        print(f"Error: {baseline_file} is a version {baseline.get('version')} baseline, not {BASELINE_VERSION} (the "
              f"logic check's): re-export it with this validator", file=sys.stderr)
        return REFUSED

    found = changes(baseline, report_json(pipeline))
    print('=== Regression Test Results ===')
    print(f'Baseline: {baseline_file}')
    print(f'Functions compared: {len(pipeline.results)}')
    print()
    for title, key in (('REGRESSIONS FOUND', 'regressions'), ('Improvements', 'improvements')):
        if found[key]:
            print(f'{title}: {len(found[key])}')
            for change in found[key]:
                print(f'  {change.function} ({change.what}): {change.found}')
            print()
    for title, key in (('Functions added', 'functions_added'), ('Functions gone', 'functions_gone')):
        if found[key]:
            print(f"{title}: {len(found[key])}: {', '.join(found[key])}")
            print()
    if not any(found.values()):
        print('No changes detected from baseline')
    return 1 if found['regressions'] else 0


# === Main Entry Point ===

def run_mode(args: argparse.Namespace, pipeline: IRPipeline) -> int:
    """Runs what args asks for - a regression export or comparison, or a report - and returns its exit code"""
    if args.export_regression:
        return 0 if export_baseline(pipeline, args.export_regression) else 1

    if args.compare_regression:
        return compare_baseline(pipeline, args.compare_regression)

    validator = Validator(pipeline, Formatter(not args.no_color), as_json=args.json, failed_only=args.failed_only)
    if args.output_dir:
        return validator.output_dir(args.output_dir)

    if args.compare:
        return validator.compare(args.compare[0], args.compare[1])

    if args.all:
        # Both pairs run, in this order; either one failing fails the run
        return max(validator.compare('llil', 'mlil'), validator.compare('mlil', 'hlil'))

    # Default: batch (--batch asks for it by name)
    return validator.batch()


def main() -> int:
    args = create_parser().parse_args()
    pipeline = IRPipeline(args.scp_file)
    if not pipeline.check(function_name=args.function):
        return 1
    return run_mode(args, pipeline)


if __name__ == '__main__':
    sys.exit(main())
