#!/usr/bin/env python3
'''Report debug line-number ordering at every IR level.

Line numbers reach the output as real statements (the `DEBUG_SET_LINENO` opcode
becomes `LowLevelILDebug` -> `MLILDebug` -> `HLILComment`), so their order is
purely a consequence of where those statements end up. The `.py`/LLIL/MLIL
levels are all in address order and should agree exactly; only HLIL restructures.

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
'''

import argparse
import contextlib
import io
import re
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml import *
from common import *
from falcom.ed9 import ScpParser
from falcom.ed9.disasm.ed9_optable import ED9Opcode
from falcom.ed9.lifters import ED9VMLifter
from falcom.ed9.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.hlil_converter import convert_falcom_mlil_to_hlil
from ir.llil.llil import LowLevelILDebug
from ir.mlil.mlil import MLILDebug
from ir.hlil.hlil import (
    HLILBlock,
    HLILComment,
    HLILDoWhile,
    HLILFor,
    HLILIf,
    HLILSwitch,
    HLILWhile,
)


LEVELS = ('py', 'llil', 'mlil', 'hlil')
LINE_COMMENT = re.compile(r'line\((\d+)\)')
DEFAULT_WORST = 10


class FunctionReport:
    '''Line sequences for one function, one entry per IR level'''

    def __init__(self, name: str, sequences: dict):
        self.name = name
        self.sequences = sequences

    @classmethod
    def backward_steps(cls, sequence: List[int]) -> int:
        '''Adjacent pairs where the line number goes down'''
        return sum(1 for i in range(len(sequence) - 1) if sequence[i + 1] < sequence[i])

    @property
    def introduced(self) -> int:
        '''Backward steps HLIL added on top of what MLIL already had'''
        return (self.backward_steps(self.sequences['hlil']) -
                self.backward_steps(self.sequences['mlil']))

    @property
    def levels_agree(self) -> bool:
        '''The three address-ordered levels must be the same sequence'''
        return (self.sequences['py'] == self.sequences['llil'] ==
                self.sequences['mlil'])

    def count_delta(self, lower: str, upper: str) -> int:
        return len(self.sequences[upper]) - len(self.sequences[lower])


def collect_dsl_lines(lifter: ED9VMLifter, func) -> List[int]:
    '''DEBUG_SET_LINENO operands in address order

    Uses the lifter's own block collection so this walk cannot drift out of step
    with the order the LLIL is built in.
    '''
    if func.entry_block is None:
        return []

    blocks = lifter._collect_blocks(func.entry_block)
    blocks.sort(key = lambda b: b.offset)

    lines = []
    for block in blocks:
        for inst in block.instructions:
            if inst.opcode == ED9Opcode.DEBUG_SET_LINENO and inst.operands:
                lines.append(int(inst.operands[0].value))

    return lines


def collect_llil_lines(llil_func) -> List[int]:
    lines = []
    for block in llil_func.basic_blocks:
        for inst in block.instructions:
            if isinstance(inst, LowLevelILDebug) and inst.debug_type == 'line':
                lines.append(int(inst.value))

    return lines


def collect_mlil_lines(mlil_func) -> List[int]:
    lines = []
    for block in mlil_func.basic_blocks:
        for inst in block.instructions:
            if isinstance(inst, MLILDebug) and inst.debug_type == 'line':
                lines.append(int(inst.value))

    return lines


def collect_hlil_lines(hlil_func) -> List[int]:
    '''Line comments in statement-tree order - the order they are printed in'''
    lines = []

    def walk(block: Optional[HLILBlock]):
        if not block or not block.statements:
            return

        for stmt in block.statements:
            if isinstance(stmt, HLILComment):
                match = LINE_COMMENT.search(stmt.text)
                if match:
                    lines.append(int(match.group(1)))

            elif isinstance(stmt, HLILIf):
                walk(stmt.true_block)
                walk(stmt.false_block)

            elif isinstance(stmt, (HLILWhile, HLILDoWhile, HLILFor)):
                walk(stmt.body)

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    walk(case.body)

    walk(hlil_func.body)
    return lines


def analyse_file(path: Path) -> List[FunctionReport]:
    reports = []

    with fileio.FileStream(str(path), encoding = default_encoding()) as fs:
        parser = ScpParser(fs, path.name)

        with contextlib.redirect_stdout(io.StringIO()):
            parser.parse()
            functions = parser.disasm_all_functions()

        for func in functions:
            lifter = ED9VMLifter(parser = parser)

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                llil_func = lifter.lift_function(func)
                mlil_func = convert_falcom_llil_to_mlil(llil_func, parser, optimize = True)
                hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

                sequences = {
                    'py'  : collect_dsl_lines(lifter, func),
                    'llil': collect_llil_lines(llil_func),
                    'mlil': collect_mlil_lines(mlil_func),
                    'hlil': collect_hlil_lines(hlil_func),
                }

            reports.append(FunctionReport(func.name, sequences))

    return reports


def print_function_table(reports: List[FunctionReport], worst: Optional[int]):
    shown = [r for r in reports if len(r.sequences['hlil']) > 1 or r.introduced]

    if worst is not None:
        shown = sorted(shown, key = lambda r: -r.introduced)[:worst]

    if not shown:
        return

    header = f'{"function":34}' + ''.join(f'{level:>13}' for level in LEVELS) + f'{"introduced":>12}'
    print(header)
    print('-' * len(header))

    for report in shown:
        row = f'{report.name[:33]:34}'
        for level in LEVELS:
            sequence = report.sequences[level]
            row += f'{report.backward_steps(sequence):>6}/{len(sequence):<6}'

        row += f'{report.introduced:>+12}'

        if not report.levels_agree:
            row += '  !! py/llil/mlil disagree'

        print(row)

    print()


def print_summary(label: str, reports: List[FunctionReport]):
    totals = {level: [0, 0] for level in LEVELS}
    disagree = 0

    for report in reports:
        for level in LEVELS:
            sequence = report.sequences[level]
            totals[level][0] += FunctionReport.backward_steps(sequence)
            totals[level][1] += len(sequence)

        if not report.levels_agree:
            disagree += 1

    row = f'{label[:33]:34}'
    for level in LEVELS:
        row += f'{totals[level][0]:>6}/{totals[level][1]:<6}'

    introduced = totals['hlil'][0] - totals['mlil'][0]
    row += f'{introduced:>+12}'
    print(row)

    deltas = ' '.join(
        f'{lower}->{upper} {totals[upper][1] - totals[lower][1]:+d}'
        for lower, upper in (('py', 'llil'), ('llil', 'mlil'), ('mlil', 'hlil'))
    )
    print(f'{"":34}counts: {deltas}')

    if disagree:
        print(f'{"":34}!! {disagree} function(s) where py/llil/mlil disagree - a bug below HLIL')


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description = 'Report debug line-number ordering across IR levels',
    )
    parser.add_argument('scp_file', help = 'Path to SCP file, or a directory to walk')
    parser.add_argument('--batch', action = 'store_true', help = 'Per-file summary only')
    parser.add_argument('--worst', type = int, nargs = '?', const = DEFAULT_WORST,
                        help = 'Show only the N functions that introduced the most disorder')
    parser.add_argument('--no-color', action = 'store_true', help = 'Accepted for symmetry, output is plain')

    return parser


def main() -> int:
    args = create_parser().parse_args()
    root = Path(args.scp_file)
    paths = sorted(root.rglob('*.dat')) if root.is_dir() else [root]

    if not paths:
        print(f'no .dat files under {root}')
        return 1

    print(f'{"":34}' + ''.join(f'{level:>13}' for level in LEVELS) + f'{"introduced":>12}')
    print()

    grand: List[FunctionReport] = []

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
