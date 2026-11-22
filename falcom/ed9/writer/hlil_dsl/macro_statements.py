"""A macro's own statements, where its call's value goes (docs/dsl/HLIL_DSL.md, Ownership: macros). Python gives the
place a function is called only what the function returns, so a macro (@macro) returns its own statements (those it
makes and nothing holds) with its value: a list of them when it returns nothing, among its list's elements when it
returns a list, as the leading statements of the node it returns, or in a Carried around a leaf. They then go where
that value goes: into the block taking the list, before the statement using the value, before each test of the
condition it is. A statement nothing holds stands where it was made: right only when no call on the way from its
making up to the body is part of a larger expression (stands_where_made, read from the calling frames' bytecode)"""

import dis
import functools
import inspect
import sys
from types import CodeType, FrameType
from typing import Callable

from .build import Build, HLILError, Origin, active_build, dsl_error
from .control import block_elements
from .nodes import Carried, Expr, Node, Statement, TrackedNode, hold_leading

CALLS = frozenset({'CALL', 'CALL_KW', 'CALL_FUNCTION_EX'})
# What follows a call whose value goes into no larger expression: dropped, returned, or kept in a plain variable
RETURNS = 'RETURN_VALUE'
STANDS = frozenset({'POP_TOP', RETURNS, 'STORE_FAST', 'STORE_FAST_LOAD_FAST', 'STORE_NAME', 'STORE_GLOBAL',
                    'STORE_DEREF'})
NOT_RUN = frozenset({'CACHE', 'NOP', 'NOT_TAKEN'})
JUMPS = frozenset({'JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_BACKWARD_NO_INTERRUPT'})
CODE_UNIT_BYTES = 2     # an instruction or a cache entry: an opcode byte and an argument byte
ARGUMENT_BITS = 8       # an EXTENDED_ARG's argument is the next instruction's argument's high byte
MAX_JUMPS = 8           # jumps followed after one instruction before giving up (a jump to itself: while True)

_macro_codes: dict[int, CodeType] = {}      # id(code) -> the code of each macro, kept alive
_instructions: dict[int, tuple[CodeType, bytes]] = {}       # id(code) -> the code, kept alive, and its bytes


class MacroStatements(list):
    """A macro's statements, returned for nothing or with its list: a block takes them; Python can't truth-test them,
    as it would test them in place of what the macro returned (nothing, or a list that may be empty)"""

    def __bool__(self):
        raise dsl_error("a macro's statements have no truth value while the script compiles: Python's if / while / "
                        'and / or / not would test them in place of what the macro returned; use If(...)')


def macro(function: Callable) -> Callable:
    """Marks a function an HLIL body calls as a macro: its own statements go where its call's value goes. Outside a
    build the function runs as it is"""
    if not hasattr(function, '__code__'):
        # No build is running while a script's decorators apply: the line comes from the frame applying this one
        caller = sys._getframe(1)
        raise HLILError(f'{caller.f_code.co_filename}:{caller.f_lineno}: @macro marks a function (a def), not a '
                        f'{type(function).__name__}: put it right above the def, below @classmethod or @staticmethod')

    if (inspect.isgeneratorfunction(function) or inspect.iscoroutinefunction(function)
            or inspect.isasyncgenfunction(function)):
        raise dsl_error(f"@macro can't mark {function.__name__}: a generator's body runs when it is iterated, after "
                        "its call returns, so its statements can't go with the call; make it a function returning a "
                        'list')

    @functools.wraps(function)
    def call(*args, **kwargs):
        build = active_build()
        if build is None:
            return function(*args, **kwargs)

        made = len(build.nodes)
        return _with_own_statements(build, sys._getframe(), made, function(*args, **kwargs))

    _macro_codes[id(function.__code__)] = function.__code__
    return call


def _with_own_statements(build: Build, wrapper: FrameType, made: int, result):
    """result carrying the statements made since build held made nodes that nothing holds: the own statements of the
    macro wrapper called. Each must stand rightly inside the macro first: a statement a function the macro called left
    in the middle of an expression is not the macro's to carry"""
    listed = {id(element) for element in block_elements(result)} if isinstance(result, list) else ()
    own = [node for node in build.nodes[made:]
           if node.stands_alone and node.parent is None and node is not result and id(node) not in listed
           and not isinstance(node.holder, TrackedNode) and (node.holder is None or node.holder is not result)]
    if not own:
        return result

    for node in own:
        inside = next((node.origin[:position + 1] for position, (frame, _) in enumerate(node.origin)
                       if frame.f_back is wrapper), None)
        problem = stands_where_made(inside, node.carries, ends_at_body=False) if inside else None
        if problem is not None:
            raise build.fail_at(node.site, f'{node!r} {problem}')

    match result:
        case None | list() | Carried() | Node():
            for node in own:
                node.carries += 1

    match result:
        case None:
            return MacroStatements(own)

        case list():
            return MacroStatements(_merged(list(block_elements(result)), own))

        case Carried():
            hold_leading(result, own)
            return result

        case TrackedNode() if isinstance(result, Expr):
            hold_leading(result, own)
            return result

        case Statement():
            hold_leading(result, [node for node in own if node.index < result.index])
            after = [node for node in own if node.index > result.index]
            return MacroStatements([result, *after]) if after else result

        case Node():
            return Carried(own, result)

    for node in own:
        node.uncarried = type(result).__name__

    return result


def _merged(listed: list, own: list) -> list:
    """listed with the own statements (in creation order) among its elements: each before the first element made
    after it, the elements keeping their order"""
    merged = []
    taken = 0
    for statement in own:
        while taken < len(listed) and getattr(listed[taken], 'index', -1) < statement.index:
            merged.append(listed[taken])
            taken += 1

        merged.append(statement)

    return [*merged, *listed[taken:]]


def _instruction(code: CodeType, lasti: int) -> tuple[str, str]:
    """code's instruction at lasti: its name, and the name of the one run after it (its cache entries and the
    instructions that do nothing skipped, unconditional jumps followed), read from the code's bytes"""
    cached = _instructions.get(id(code))
    if cached is None:
        cached = _instructions[id(code)] = (code, code.co_code)

    raw = cached[1]
    offset = lasti + CODE_UNIT_BYTES
    extended = 0
    jumps = 0
    while 0 <= offset < len(raw) and jumps <= MAX_JUMPS:
        name = dis.opname[raw[offset]]
        argument = extended | raw[offset + 1]
        offset += CODE_UNIT_BYTES
        if name == 'EXTENDED_ARG':
            extended = argument << ARGUMENT_BITS
        elif name in JUMPS:
            while offset < len(raw) and dis.opname[raw[offset]] == 'CACHE':
                offset += CODE_UNIT_BYTES

            offset += CODE_UNIT_BYTES * (argument if name == 'JUMP_FORWARD' else -argument)
            extended = 0
            jumps += 1
        elif name not in NOT_RUN:
            return dis.opname[raw[lasti]], name

    return dis.opname[raw[lasti]], ''


def _line(code: CodeType, lasti: int) -> int | None:
    return next((line for start, end, line in code.co_lines() if start <= lasti < end), None)


def forget_instructions():
    """Drop the cached instructions, with the code they keep alive: a build's end"""
    _instructions.clear()


def stands_where_made(origin: Origin, carries: int, ends_at_body: bool = True,
                      uncarried: str | None = None) -> str | None:
    """None when a statement nothing holds, made at origin and returned by carries macros with their values, is
    rightly where it was made; else why not. The statement starts as its call's value, and is one again where a macro
    that returned it with its value is called. A value may be returned, or be dropped or kept in a variable: it stands
    there; in a larger expression that no block took it from, it has no place. Once it stands, it is a side effect of
    every call above: each must be a call whose own value is dropped, returned or kept in a variable, so no expression
    got a value that should have held the statement. ends_at_body: origin's last frame is the body's (else a macro's,
    which a message names); uncarried: the type of the value a macro returned that could not carry the statement"""
    is_value = True
    macros = 0
    for position, (frame, lasti) in enumerate(origin):
        code = frame.f_code
        name, following = _instruction(code, lasti)
        callee = origin[position - 1][0].f_code if position else None
        if (name in CALLS or is_value) and following in STANDS and (callee is None or id(callee) not in _macro_codes):
            is_value = is_value and following == RETURNS
            continue

        in_body = ends_at_body and position == len(origin) - 1
        where = f'line {_line(code, lasti)}' + ('' if in_body else f' of {code.co_name}')
        if callee is not None and id(callee) in _macro_codes:
            macros += 1
            is_value = is_value or macros <= carries

        if is_value:
            # A value's own instruction may be a loop's or a star's too (map, starmap): what follows it says as much
            if following == RETURNS:
                continue

            if following in STANDS:
                is_value = False
                continue

            if callee is None or id(callee) not in _macro_codes:
                return (f'is written inside an expression ({where}) and no block took it: a statement stands on a '
                        "line of its own or in a block's list")

            return (f'is made in the macro {callee.co_name}(), called inside an expression ({where}), and no block '
                    f'or statement took what {callee.co_name} returned with it')

        if name in CALLS and following in STANDS:
            continue

        if callee.co_flags & inspect.CO_GENERATOR:
            return (f'is made in the generator {callee.co_name}() ({where}): its body runs as it is iterated, so its '
                    "statements can't go where it is called; make it a function returning a list")

        if name not in CALLS:
            return (f'is made in {callee.co_name}(), run from inside an expression ({where}: a star, a loop over a '
                    f'generator or an attribute, not a call on a line of its own), and no block took it: call '
                    f'{callee.co_name} on a line of its own, or mark it (@macro above its def) and call it where its '
                    'statements go')

        if id(callee) in _macro_codes:
            problem = (f'is made in the macro {callee.co_name}(), called inside an expression ({where}), and '
                       f'{callee.co_name} could not return it with its value')
            if uncarried is not None:
                problem += (f" ({uncarried} can't carry a statement: a macro returns a DSL value, a statement, a list "
                            'of statements or nothing)')

            return problem

        # A body's source check refuses a call kept in a variable: the hint is a function's
        variable = '' if in_body else f', or assign its value to one plain variable first (x = {callee.co_name}(...))'
        return (f'is made in {callee.co_name}(), called inside an expression ({where}): Python gives the expression '
                f"only what {callee.co_name} returns, so the statement can't go where the call is written; mark the "
                f'function (@macro above def {callee.co_name}), or call it on a line of its own{variable}')
