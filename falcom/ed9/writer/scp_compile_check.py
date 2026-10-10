"""The writer's compile check: compiled bytes must decompile again - disassemble with the parser's stack simulation and
lift to LLIL - and errors point back at the script line that emitted the failing opcode. Must not import scp_writer,
which imports this module."""

import bisect
import functools
import linecache
import re
import tokenize
from types import CodeType
from typing import Callable, NamedTuple

from common.logging import log
from ..disasm import Instruction
from ..ir.llil import ED9LiftError, ED9VMLifter
from ..parser.code_layout import dropped_ranges
from ..parser.scp import ScpFunctionError, ScpParser
from ..parser.types_parser import Function

# A stack entry in a parser message (format_stack_entry): MNEMONIC@0x.. or frame_N@0x.., the offset of its opcode
STACK_ENTRY = re.compile(r'@0x([0-9A-F]+)\b')


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
                 code_offset: int, warn_unreachable_code: bool = True):
        self.dat_name = dat_name
        self.functions = functions
        self.functions_by_name = {f.name: f for f in functions}
        self.source_map = source_map    # code position of each opcode -> where it was emitted
        self.code_offset = code_offset  # file offset where the code starts
        self.warn_unreachable_code = warn_unreachable_code

    def run(self, data: bytes, code_end: int):
        """The compiled bytes disassemble and lift again; a failure names the script line that emitted the failing
        opcode, or the failing function's def. A function that runs on into the next function's code (no RETURN) is a
        warning while the bytes still decompile, and a note on the failure when they don't; the parser's warnings for
        unusual slots and for a call returning at or before itself get their script line too, and the latter becomes
        a note on a failure in its function. Last, with warn_unreachable_code, a warning per range of code no path
        reaches."""
        try:
            parser, parsed_functions = require_decompilable(data, self.dat_name, code_end)

        except ScpFunctionError as e:
            notes = [self._run_on_note(e.function, e.runs_on)]
            notes += [self._failure_text(e.function, text, call)
                      for _, (call, text) in sorted(e.backward_returns.items())]
            text = self._with_entry_lines(str(e), e.function, e.offset)
            message = f'{self._failure_prefix(e.function, e.offset)}{text}'
            raise CompileCheckError('; '.join([message, *(note for note in notes if note)])) from e

        except Exception as e:
            raise CompileCheckError(f'{self.dat_name}: {e}') from e

        runs_on = {parsed_function.name: parsed_function.runs_on for parsed_function in parsed_functions}
        for f in self.functions:
            note = self._run_on_note(f.name, runs_on.get(f.name))
            if note:
                log.warning(note)

        reachable = []
        for parsed_function in parsed_functions:
            instructions = parser.get_instructions(parsed_function)
            reachable += instructions
            for inst in instructions:
                ref = parsed_function.stack_layout.slot_refs.get(inst.offset)
                if ref is not None and ref.unusual:
                    log.warning(self._failure_text(parsed_function.name, f'addresses {ref}', inst))

                backward_return = parsed_function.backward_returns.get(inst.offset)
                if backward_return is not None:
                    log.warning(self._failure_text(parsed_function.name, backward_return[1], inst))

        if self.warn_unreachable_code:
            self._warn_unreachable(reachable, code_end)

    def _warn_unreachable(self, reachable: list[Instruction], code_end: int):
        """A warning per range of code no function's reachable instructions cover, at its first opcode's line. All
        functions' code at once, since a function may jump into another's; a range never crosses a function's start
        (every entry is reachable), so it is the last function's starting at or before it"""
        reachable = sorted(reachable, key = lambda inst: inst.offset)
        positions = sorted(self.source_map)
        starts = [f.offset for f in self.functions]
        for start, end, _ in dropped_ranges(reachable, self.code_offset, code_end):
            owner = self.functions[bisect.bisect_right(starts, start) - 1].name
            count = (bisect.bisect_left(positions, end - self.code_offset)
                     - bisect.bisect_left(positions, start - self.code_offset))
            where = f'at 0x{start:X}..0x{end:X}'
            if count == 1:
                message = f'1 opcode {where} never runs (no path reaches it); the everyday decompile drops it'

            else:
                message = f'{count} opcodes {where} never run (no path reaches them); the everyday decompile drops them'

            log.warning(self._failure_text(owner, message, offset = start))

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

    def _failure_text(self, function_name: str, message: str, inst: Instruction | None = None,
                      offset: int | None = None) -> str:
        """The failure prefix of inst (or of the opcode at offset), else of the function's def, then
        ScpFunctionError.describe()'s text"""
        if inst is not None:
            offset = inst.offset

        return self._failure_prefix(function_name, offset) + ScpFunctionError.describe(function_name, message, inst)

    def _with_entry_lines(self, text: str, function_name: str | None, offset: int | None) -> str:
        """text with the script line after each stack entry an opcode pushed (not a parameter): '(line N)' in the file
        of the opcode at offset (else of the function's def), 'file:N' in another (an opcode callback's)"""
        site = self.source_map.get(offset - self.code_offset) if offset is not None else None
        f = self.functions_by_name.get(function_name)
        if site is not None:
            failing_file = site.code.co_filename

        else:
            failing_file = f.body.__code__.co_filename if f is not None else None

        def with_line(match: re.Match) -> str:
            entry_site = self.source_map.get(int(match[1], 16) - self.code_offset)
            if entry_site is None:
                return match[0]

            if entry_site.code.co_filename == failing_file:
                return f'{match[0]} (line {source_line(entry_site)})'

            return f'{match[0]} ({source_location(entry_site)})'

        return STACK_ENTRY.sub(with_line, text)

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
    the quiet parse, whose warnings (run-ons, unusual slots, backward returns) the caller reports. Unreachable code is
    not simulated, and a stack that balances but reads the wrong slot passes."""
    parser, functions = ScpParser.load_bytes(data, name, round_trip = False, keep_unreachable_code = False, quiet = True,
                                             reject_outside_stack = True, known_code_end = code_end)
    for func in functions:
        try:
            ED9VMLifter(parser = parser).lift_function(func)

        except ED9LiftError as e:
            e.runs_on = func.runs_on
            e.backward_returns = func.backward_returns
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
    return f'{site.code.co_filename}:{source_line(site)}'


def source_line(site: SourceSite) -> int:
    """The line of the call at a source site"""
    code, lasti = site.code, site.lasti
    line = next((line for start, end, line in code.co_lines() if start <= lasti < end and line is not None), None)
    return line or definition_line(code)


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
