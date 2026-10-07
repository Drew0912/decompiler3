"""The writer's compile check: compiled bytes must decompile again - disassemble with the parser's stack simulation and
lift to LLIL - and errors point back at the script line that emitted the failing opcode. Must not import scp_writer,
which imports this module."""

import functools
import linecache
import tokenize
from types import CodeType
from typing import Callable, NamedTuple

from common.logging import log
from ..disasm import Instruction
from ..ir.llil import ED9LiftError, ED9VMLifter
from ..parser.scp import ScpFunctionError, ScpParser
from ..parser.types_parser import Function


class SourceSite(NamedTuple):
    """Where a body emitted an opcode: the body's code and the bytecode offset of the call in it. An opcode an opcode
    callback emitted is the callback's, with the site of the opcode that triggered it"""
    code: CodeType
    lasti: int
    trigger: 'SourceSite | None' = None


class CompileCheckError(ValueError):
    """Compiled bytes that don't decompile again"""


class CheckedFunction(NamedTuple):
    """A compiled function as the check needs it"""
    name: str
    offset: int         # file offset of its code
    body: Callable      # for its def line, looked up only on a failure or warning


class CompileCheck:
    """One compile's check: the compiled functions in code order, and where each opcode was emitted"""

    def __init__(self, dat_name: str, functions: list[CheckedFunction], source_map: dict[int, SourceSite | None],
                 code_offset: int):
        self.dat_name = dat_name
        self.functions = functions
        self.functions_by_name = {f.name: f for f in functions}
        self.source_map = source_map    # code position of each opcode -> where it was emitted
        self.code_offset = code_offset  # file offset where the code starts

    def run(self, data: bytes, code_end: int):
        """The compiled bytes disassemble and lift again; a failure names the script line that emitted the failing
        opcode, or the failing function's def. A function that runs on into the next function's code (no RETURN) is a
        warning while the bytes still decompile, and a note on the failure when they don't; the parser's warnings for
        unusual slots get their script line too."""
        try:
            parser, parsed_functions = require_decompilable(data, self.dat_name, code_end)

        except ScpFunctionError as e:
            note = self._run_on_note(e.function, e.runs_on)
            message = f'{self._failure_prefix(e.function, e.offset)}{e}'
            raise CompileCheckError(f'{message}; {note}' if note else message) from e

        except Exception as e:
            raise CompileCheckError(f'{self.dat_name}: {e}') from e

        runs_on = {parsed_function.name: parsed_function.runs_on for parsed_function in parsed_functions}
        for f in self.functions:
            note = self._run_on_note(f.name, runs_on.get(f.name))
            if note:
                log.warning(note)

        for parsed_function in parsed_functions:
            for inst in parser.get_instructions(parsed_function):
                ref = parsed_function.stack_layout.slot_refs.get(inst.offset)
                if ref is not None and ref.unusual:
                    log.warning(self._failure_text(parsed_function.name, f'addresses {ref}', inst))

    def _run_on_note(self, function_name: str | None, inst: Instruction | None) -> str | None:
        """How the function runs on into the next function's code, located: it has no code at all, or inst runs past
        its end (the parser found it; for an empty function that is the next one's). None when it doesn't"""
        f = self.functions_by_name.get(function_name)
        if f is None:
            return None

        following = self.functions[self.functions.index(f) + 1:]
        if following and following[0].offset == f.offset:
            return self._failure_text(f.name, f'has no code, so it runs on into {following[0].name} without RETURN')

        if inst is not None:
            end = inst.offset + inst.size
            into = next(other.name for other in following if other.offset == end)
            return self._failure_text(f.name, f'runs past its end into {into} without RETURN', inst)

        return None

    def _failure_text(self, function_name: str, message: str, inst: Instruction | None = None) -> str:
        """The failure prefix of inst, else of the function's def, then ScpFunctionError.describe()'s text"""
        offset = inst.offset if inst is not None else None
        return self._failure_prefix(function_name, offset) + ScpFunctionError.describe(function_name, message, inst)

    def _failure_prefix(self, function_name: str | None, offset: int | None) -> str:
        """'file:line: ' of the opcode compiled at a file offset, else of the function's def; '' when neither is known"""
        site = self.source_map.get(offset - self.code_offset) if offset is not None else None
        if site is not None:
            return location_prefix(site)

        f = self.functions_by_name.get(function_name)
        if f is None:
            return ''

        return f'{def_location(f.body)}: '


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


def location_prefix(site: SourceSite | None) -> str:
    """'file:line: ' of a source site, '' without one (the source map is off); an opcode an opcode callback emitted
    also names the callback and the triggering opcode's line"""
    if site is None:
        return ''

    prefix = f'{source_location(site)}: '
    if site.trigger is None:
        return prefix

    return f'{prefix}(opcode callback {site.code.co_name}, triggered at {source_location(site.trigger)}) '


def source_location(site: SourceSite) -> str:
    """'file:line' of the call at a source site"""
    code, lasti = site.code, site.lasti
    line = next((line for start, end, line in code.co_lines() if start <= lasti < end and line is not None), None)
    return f'{code.co_filename}:{line or definition_line(code)}'


def def_location(func: Callable) -> str:
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
