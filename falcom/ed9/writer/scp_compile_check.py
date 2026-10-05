"""The writer's compile check: compiled bytes must decompile again - disassemble with the parser's stack simulation and
lift to LLIL - and errors point back at the script line that emitted the failing opcode. Must not import scp_writer,
which imports this module."""

import functools
import linecache
import tokenize
from types import CodeType
from typing import Callable

from ..ir.llil import ED9LiftError, ED9VMLifter
from ..parser.scp import ScpParser
from ..parser.types_parser import Function


# Where a body emitted an opcode: the body's code and the bytecode offset of the call in it
SourceSite = tuple[CodeType, int]


class CompileCheckError(ValueError):
    """Compiled bytes that don't decompile again"""


def require_decompilable(data: bytes, name: str, code_end: int) -> tuple[ScpParser, list[Function]]:
    """Raise the parser's or the lifter's error when data, whose code ends at code_end, doesn't decompile again; return
    the quiet parse, whose warnings (run-ons, unusual slots) the caller reports. Unreachable code is not checked, and a
    stack that balances but reads the wrong slot passes."""
    parser, functions = ScpParser.load_bytes(data, name, round_trip = False, keep_unreachable_code = False, quiet = True,
                                             reject_outside_stack = True, known_code_end = code_end)
    for func in functions:
        try:
            ED9VMLifter(parser = parser).lift_function(func)

        except ED9LiftError as e:
            e.runs_on = func.runs_on
            raise

    return parser, functions


def source_location(site: SourceSite) -> str:
    """'file:line' of the call at a source site"""
    code, lasti = site
    line = next((line for start, end, line in code.co_lines() if start <= lasti < end and line is not None), None)
    return f'{code.co_filename}:{line or definition_line(code)}'


def def_site(func: Callable) -> str:
    """'file:line' of a function's own def (not of a function it wraps)"""
    code = func.__code__
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
