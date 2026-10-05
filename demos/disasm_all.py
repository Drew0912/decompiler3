#!/usr/bin/env python3
"""Disassemble all functions from"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from common import fileio
from falcom.ed9.disasm import *
from falcom.ed9.parser import *
from pathlib import Path
import argparse


def disasm_file(input_path: Path, output_path: Path):
    """Disassemble all functions in a single file"""
    print(f'Processing {input_path.name}...')

    with fileio.FileStream(str(input_path), encoding = default_encoding()) as fs:
        parser = ScpParser(fs, input_path.name)
        parser.parse()

        # Disassemble all functions
        disassembled_functions = parser.disasm_all_functions()

        # Format output
        all_lines = []
        all_lines.append(f'# Disassembly of {input_path.name}')
        all_lines.append('')

        for func in disassembled_functions:
            lines = parser.format_function(func)
            all_lines.extend(lines)
            all_lines.append('')

        # Write output
        output_path.write_text('\n'.join(all_lines), encoding = 'utf-8')
        print(f'  -> {output_path}')


def main():
    parser = argparse.ArgumentParser(description = 'Disassemble .dat files to .py files')
    parser.add_argument('path', help = 'Input file or directory')
    args = parser.parse_args()

    input_path = Path(args.path)

    if not input_path.exists():
        print(f'Error: {input_path} does not exist')
        return 1

    files = []

    if input_path.is_file():
        # Single file
        if input_path.suffix != '.dat':
            print(f'Error: {input_path} is not a .dat file')
            return 1

        files.append(input_path)

    elif input_path.is_dir():
        # Directory

        files = [f for f in sorted(input_path.glob('*.dat')) if f.is_file()]

    else:
        print(f'Error: {input_path} is neither a file nor a directory')
        return 1

    for f in files:
        dat_file = Path(f)
        output_path = dat_file.with_suffix('.py')
        try:
            disasm_file(dat_file, output_path)
        except Exception as e:
            raise RuntimeError(f'Error processing {dat_file.name}: {e}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
