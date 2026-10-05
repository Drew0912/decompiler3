"""The writer's compile check: compiled bytes must decompile again - disassemble with the parser's stack simulation and
lift to LLIL - and errors point back at the script line that emitted the failing opcode. Must not import scp_writer,
which imports this module."""

import functools
import linecache
import tokenize
from types import CodeType

from ..ir.llil import ED9VMLifter
from ..parser.scp import ScpDisassemblyError, ScpParser


# Where a body emitted an opcode: the body's code and the bytecode offset of the call in it
SourceSite = tuple[CodeType, int]


class CompileCheckError(ValueError):
    """Compiled bytes that don't decompile again"""


def require_decompilable(data: bytes, name: str):
    """Raise the parser's or the lifter's error when data doesn't decompile again. Unreachable code is not checked, and
    a stack that balances but reads the wrong slot passes."""
    parser, functions = ScpParser.load_bytes(data, name, round_trip = False, keep_unreachable_code = False, quiet = True)
    for func in functions:
        for inst in parser.get_instructions(func):
            ref = func.stack_layout.slot_refs.get(inst.offset)
            if ref is not None and ref.outside_stack:
                raise ScpDisassemblyError(f'{func.name}: {inst.mnemonic} at 0x{inst.offset:X}: addresses {ref}',
                                          func.name, inst.offset)

        ED9VMLifter(parser = parser).lift_function(func)


def source_location(site: SourceSite) -> str:
    """'file:line' of the call at a source site"""
    code, lasti = site
    line = next((line for start, end, line in code.co_lines() if start <= lasti < end and line is not None),
                definition_line(code))
    return f'{code.co_filename}:{line}'


def definition_location(code: CodeType) -> str:
    """'file:line' of a function's def"""
    return f'{code.co_filename}:{definition_line(code)}'


def definition_line(code: CodeType) -> int:
    """The line of a function's def past its decorators, however many lines they take: the first def keyword token
    (never one inside a string or a comment). Its first line when the source can't be read or the def that follows
    isn't this function's (a lambda)"""
    lines = linecache.getlines(code.co_filename)[code.co_firstlineno - 1:]
    tokens = tokenize.generate_tokens(functools.partial(next, iter(lines), ''))
    try:
        for token in tokens:
            if token.type == tokenize.NAME and token.string == 'def':
                if next(tokens).string == code.co_name:
                    return code.co_firstlineno + token.start[0] - 1

                break

    except (tokenize.TokenError, SyntaxError, StopIteration):
        pass

    return code.co_firstlineno
