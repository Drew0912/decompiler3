#!/usr/bin/env python3
"""Report debug line-number ordering at every IR level.

Line numbers reach the output as real statements (the `DEBUG_SET_LINENO` opcode
becomes `LowLevelILDebug` -> `MLILDebug` -> `HLILComment`), so their order is
purely a consequence of where those statements end up. The `.py`/LLIL/MLIL
levels are all read in address order and should agree exactly; only HLIL restructures.

That makes the useful number the *difference* between HLIL and MLIL: backward
steps present at MLIL are inherited from the game's own bytecode and are not a
decompiler defect, while the excess at HLIL is what structuring introduced.

The HLIL column describes the generated `.ts` as well: arm order is decided once,
in BranchOrderNormalizationPass, and the TypeScript emitter renders that decision
rather than making its own. If the two ever disagree again, the emitter has
started restructuring.

Counts are reported per level too, so a dropped comment (loss) or a re-emitted
region (gain) is visible and attributable.

Usage:
    python tools/ir_line_order_report.py <scp_file> [--batch] [--worst N]

Note: prefix with PYTHONIOENCODING=utf-8 for scripts containing Japanese text.
"""

import argparse
import contextlib
import io
import sys
from itertools import pairwise
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dc3.utils import collect_paths, raise_recursion_limit
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.disasm.ed9_optable import ED9Opcode
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.core import reverse_post_order
from ir.llil.llil import LowLevelILDebug
from ir.mlil.mlil import MLILDebug
from ir.hlil.hlil import iter_tree, line_marker_number


LEVELS = ('py', 'llil', 'mlil', 'hlil')
DEFAULT_WORST = 10


class FunctionReport:
    """Line sequences for one function, one entry per IR level"""

    def __init__(self, name: str, sequences: dict):
        self.name = name
        self.sequences = sequences

    @classmethod
    def backward_steps(cls, sequence: list[int]) -> int:
        """Adjacent pairs where the line number goes down"""
        return sum(1 for a, b in pairwise(sequence) if b < a)

    @property
    def introduced(self) -> int:
        """Backward steps HLIL added on top of what MLIL already had"""
        return (self.backward_steps(self.sequences['hlil']) -
                self.backward_steps(self.sequences['mlil']))

    @property
    def levels_agree(self) -> bool:
        """The three address-ordered levels must be the same sequence"""
        return (self.sequences['py'] == self.sequences['llil'] ==
                self.sequences['mlil'])


def collect_dsl_lines(func) -> list[int]:
    """DEBUG_SET_LINENO operands in address order

    Walks the blocks the lifter lifts (reverse_post_order over succs, as the lifter calls it), so
    this walk cannot drift out of step with the blocks the LLIL is built from
    """
    if func.entry_block is None:
        return []

    blocks = sorted(reverse_post_order(func.entry_block, lambda block: block.succs), key=lambda b: b.offset)
    return [int(inst.operands[0].value) for block in blocks for inst in block.instructions
            if inst.opcode == ED9Opcode.DEBUG_SET_LINENO and inst.operands]


def collect_llil_lines(llil_func) -> list[int]:
    return [int(inst.value) for block in llil_func.basic_blocks for inst in block.instructions
            if isinstance(inst, LowLevelILDebug) and inst.debug_type == 'line']


def collect_mlil_lines(mlil_func) -> list[int]:
    """Line directives in address order

    Block order is not address order at MLIL: BlockMergePass splices a block onto
    its only predecessor, wherever that sits in the block list
    """
    directives = [
        inst
        for block in mlil_func.basic_blocks
        for inst in block.instructions
        if isinstance(inst, MLILDebug) and inst.debug_type == 'line'
    ]
    directives.sort(key=lambda inst: inst.address)

    return [int(inst.value) for inst in directives]


def collect_hlil_lines(hlil_func) -> list[int]:
    """Line comments in statement-tree order - the order they are printed in"""
    markers = (line_marker_number(node) for node in iter_tree(hlil_func.body))
    return [line for line in markers if line is not None]


def analyse_file(path: Path) -> list[FunctionReport]:
    """Line sequences per function, from the pipeline scena2py.py decompiles with"""
    raise_recursion_limit()
    reports = []

    with contextlib.redirect_stdout(io.StringIO()):
        parser, functions = ScpParser.load(path, round_trip=False, keep_unreachable_code=False)

    for func in functions:
        lifter = ED9VMLifter(parser=parser)

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            llil_func = lifter.lift_function(func)
            mlil_func = convert_falcom_llil_to_mlil(llil_func, optimize=True)
            hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

            sequences = {
                'py'  : collect_dsl_lines(func),
                'llil': collect_llil_lines(llil_func),
                'mlil': collect_mlil_lines(mlil_func),
                'hlil': collect_hlil_lines(hlil_func),
            }

        reports.append(FunctionReport(func.name, sequences))

    return reports


def header_line(first_column: str) -> str:
    return f'{first_column:34}' + ''.join(f'{level:>13}' for level in LEVELS) + f'{'introduced':>12}'


def level_cell(steps: int, count: int) -> str:
    """One level's column: backward steps / line count"""
    return f'{steps:>6}/{count:<6}'


def print_function_table(reports: list[FunctionReport], worst: int | None):
    shown = [r for r in reports if len(r.sequences['hlil']) > 1 or r.introduced]

    if worst is not None:
        shown = sorted(shown, key=lambda r: -r.introduced)[:worst]

    if not shown:
        return

    header = header_line('function')
    print(header)
    print('-' * len(header))

    for report in shown:
        row = f'{report.name[:33]:34}'
        for level in LEVELS:
            sequence = report.sequences[level]
            row += level_cell(report.backward_steps(sequence), len(sequence))

        row += f'{report.introduced:>+12}'

        if not report.levels_agree:
            row += '  !! py/llil/mlil disagree'

        print(row)

    print()


def print_summary(label: str, reports: list[FunctionReport]):
    steps = {level: sum(FunctionReport.backward_steps(r.sequences[level]) for r in reports) for level in LEVELS}
    counts = {level: sum(len(r.sequences[level]) for r in reports) for level in LEVELS}
    disagree = sum(not r.levels_agree for r in reports)

    row = f'{label[:33]:34}'
    for level in LEVELS:
        row += level_cell(steps[level], counts[level])

    introduced = steps['hlil'] - steps['mlil']
    row += f'{introduced:>+12}'
    print(row)

    deltas = ' '.join(f'{lower}->{upper} {counts[upper] - counts[lower]:+d}' for lower, upper in pairwise(LEVELS))
    print(f'{'':34}counts: {deltas}')

    if disagree:
        print(f'{'':34}!! {disagree} function(s) where py/llil/mlil disagree - a bug below HLIL')


def create_parser() -> argparse.ArgumentParser:
    arg_parser = argparse.ArgumentParser(
        description='Report debug line-number ordering across IR levels',
    )
    arg_parser.add_argument('scp_file', help='Path to SCP file, or a directory to walk')
    arg_parser.add_argument('--batch', action='store_true', help='Per-file summary only')
    arg_parser.add_argument('--worst', type=int, nargs='?', const=DEFAULT_WORST,
                            help='Show only the N functions that introduced the most disorder')

    return arg_parser


def main() -> int:
    args = create_parser().parse_args()
    root = Path(args.scp_file)
    paths = collect_paths([root])

    if not paths:
        print(f'no .dat files under {root}')
        return 1

    print(header_line(''))
    print()

    grand: list[FunctionReport] = []

    for path in paths:
        try:
            reports = analyse_file(path)
        except Exception as exc:
            print(f'{path.name}: {type(exc).__name__}: {exc}')
            continue

        grand.extend(reports)

        if not args.batch:
            print(f'== {path.name}')
            print_function_table(reports, args.worst)

        print_summary(path.name, reports)
        print()

    if len(paths) > 1:
        print('=' * 72)
        print_summary('TOTAL', grand)

    return 0


if __name__ == '__main__':
    sys.exit(main())
