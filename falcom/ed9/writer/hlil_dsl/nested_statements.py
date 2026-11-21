"""A helper's own statements nested where the helper is called (docs/dsl/HLIL_DSL.md, Ownership): Python runs a call's
arguments before the call, so a helper called in a block's list, or as a condition, has made its own statements (those
it does not return) by the time If(...), .ElseIf(...), .Else(...) or While(...) takes its arguments. Each keeps its
origin (build.py): the frame calling the If or the While is at that call's instruction, and a statement made at an
instruction of that frame inside one of the call's arguments (the code's own positions; the arguments' read from the
source) was made by that argument"""

import ast
import linecache
import sys
from types import CodeType

from .build import Build

# A source span as code.co_positions() gives one: first line, last line, first column, end column (the columns None
# when Python keeps none, -X no_debug_ranges)
Span = tuple[int | None, int | None, int | None, int | None]

CODE_UNIT_BYTES = 2     # f_lasti counts bytes, co_positions() code units

_positions: dict[int, tuple[CodeType, list[Span]]] = {}     # id(code) -> the code, kept alive, and its positions
_calls_by_end: dict[str, tuple[list[str], dict[tuple[int, int], ast.Call]]] = {}    # file -> its lines and its calls


def position(code: CodeType, lasti: int) -> Span:
    """The source span of code's instruction at lasti"""
    cached = _positions.get(id(code))
    if cached is None:
        cached = _positions[id(code)] = (code, list(code.co_positions()))

    return cached[1][lasti // CODE_UNIT_BYTES]


def forget_positions():
    """Drop the cached positions, with the code they keep alive: a build's end"""
    _positions.clear()


def inside(outer: Span, inner: Span) -> bool:
    """inner lies within outer; False when either has no columns"""
    if None in outer or None in inner:
        return False

    return (outer[0], outer[2]) <= (inner[0], inner[2]) and (inner[1], inner[3]) <= (outer[1], outer[3])


def made_inside(node, outer) -> bool:
    """node was made while the expression making outer ran: in the frame outer was made in, at an instruction within
    outer's"""
    if not outer.origin:
        return False

    frame, outer_lasti = outer.origin[0]
    lasti = next((lasti for made_in, lasti in node.origin if made_in is frame), None)
    return lasti is not None and inside(position(frame.f_code, outer_lasti), position(frame.f_code, lasti))


def take_nested_statements(build: Build, owner, arguments: tuple[int, ...]) -> dict[int, list]:
    """The statements nothing holds yet that the given arguments (by position) of the call making owner (an If or a
    While taking an arm) made, each argument's in creation order, taken out of build.unplaced. Python made them just
    before the call, so they are the newest there: the scan stops at the first made elsewhere"""
    made = {argument: [] for argument in arguments}
    if not build.unplaced:
        return made

    origin = build.origin(sys._getframe())
    if not origin:
        return made

    frame = origin[0][0]
    code = frame.f_code
    call = position(code, frame.f_lasti)
    unplaced = build.unplaced
    owner_waiting = False       # owner itself, back to unplaced once its arm's statements are out
    spans = None
    while unplaced:
        node = unplaced[-1]
        if node is owner:
            owner_waiting = True
            unplaced.pop()
            continue

        if node.parent is not None:     # a block's list took it since
            unplaced.pop()
            continue

        lasti = next((lasti for made_in, lasti in node.origin if made_in is frame), None)
        if lasti is None:
            break

        where = position(code, lasti)
        if call[2] is None:
            if where[0] is not None and where[0] < call[0]:
                break

            raise build.fail_at(node.site, f'{node!r} is made on or after the first line of a call building an arm, '
                                           'and Python keeps no columns to tell whether its arguments made it '
                                           '(-X no_debug_ranges or PYTHONNODEBUGRANGES): run Python without it')

        # A node at the call's own span was made by an earlier run of it (a Python loop)
        if not inside(call, where) or where == call:
            break

        if spans is None:
            spans = _argument_spans(code, frame.f_globals, call, max(arguments) + 1)
            if spans is None:
                raise build.fail_at(node.site, f'{node!r} is made while the arguments of this call are built, and the '
                                               "call's source can't be read to tell which argument made it (no source, "
                                               "*arguments or keywords, or a call that is not the If's or While's own, "
                                               "such as a functools.partial's): give the condition and the block as "
                                               'written arguments')

        argument = next((argument for argument, span in enumerate(spans) if inside(span, where)), None)
        if argument not in made:
            break

        unplaced.pop()
        made[argument].append(node)

    if owner_waiting:
        unplaced.append(owner)

    for statements in made.values():
        statements.reverse()

    return made


def _argument_spans(code: CodeType, names: dict, call: Span, count: int) -> list[Span] | None:
    """The spans of the count positional arguments of the call ending where call does, from code's file; None when the
    source can't be read or the arguments can't be told apart (*arguments, keywords, or a call with another count:
    not the arm's own, as through functools.partial or map)"""
    filename = code.co_filename
    lines = linecache.getlines(filename, names)
    cached = _calls_by_end.get(filename)
    if cached is None or cached[0] is not lines:
        try:
            tree = ast.parse(''.join(lines))
        except SyntaxError:
            return None

        calls = {(node.end_lineno, node.end_col_offset): node for node in ast.walk(tree) if isinstance(node, ast.Call)}
        cached = _calls_by_end[filename] = (lines, calls)

    node = cached[1].get((call[1], call[3]))
    if (node is None or len(node.args) != count or node.keywords
            or any(isinstance(argument, ast.Starred) for argument in node.args)):
        return None

    return [(argument.lineno, argument.end_lineno, argument.col_offset, argument.end_col_offset)
            for argument in node.args]
