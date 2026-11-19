"""One parsed and disassembled script, shared by the checks that read a file's bytes"""

import contextlib
import io
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from dc3 import fileio
from assembler import Instruction
from falcom.ed9.structs.call_debug_records import read_debug_records
from falcom.ed9.parser.code_layout import code_order, function_extents
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.assembler.function import Function
from falcom.ed9.structs.scp_types import ScpFunctionCallDebugInfo, ScpFunctionEntry


@dataclass
class ScriptContext:
    """One parsed + disassembled script shared by every check"""

    data            : bytes
    fs              : fileio.FileStream
    parser          : ScpParser
    entries         : list[ScpFunctionEntry]                # table order
    records         : list[list[ScpFunctionCallDebugInfo]]  # table order
    instructions    : list[list[Instruction]]               # table order, reachable, offset order
    code_order      : list[int]                             # table indices sorted by code offset

    def __enter__(self) -> ScriptContext:
        return self

    def __exit__(self, *exc_info):
        self.close()

    def close(self):
        self.fs.Close()

    def func_name(self, index: int) -> str:
        return self.parser.functions[index].name

    def functions_in_code_order(
        self,
        pool_start: int,
    ) -> Iterator[tuple[int, Function, list[Instruction], tuple[int, int]]]:
        """(table index, function, its reachable instructions, its (start, end) byte range) per function, in code
        order"""
        extents = function_extents(self.entries, pool_start)
        for index in self.code_order:
            yield index, self.parser.functions[index], self.instructions[index], extents[index]


def load_script(path: Path) -> ScriptContext:
    """Parse and disassemble path; the caller closes it (with load_script(path) as ctx), or this does when the file
    fails to load"""
    fs = fileio.FileStream(str(path))

    try:
        parser = ScpParser(fs, path.name)

        with contextlib.redirect_stdout(io.StringIO()):
            parser.parse()
            parser.disasm_all_functions()

        entries = parser.function_entries
        data = path.read_bytes()
        return ScriptContext(
            data=data,
            fs=fs,
            parser=parser,
            entries=entries,
            records=read_debug_records(parser, data),
            instructions=[func.reachable_instructions() for func in parser.functions],
            code_order=code_order(entries),
        )
    except BaseException:
        fs.Close()
        raise
