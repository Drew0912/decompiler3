"""The stub a library or script function's name is bound to (docs/dsl/HLIL_DSL.md, Calls): CALL(f), the writer's
registration and the hooks reach the body through it; f(...) by bare name builds a call in an HLIL body and raises
anywhere else. Also the mark @scena.HLILCode() sets on an HLIL body"""

import functools
from typing import Callable

from .build import active_build
from .nodes import LocalCall

# Set on an HLIL body by @scena.HLILCode(); functools.wraps copies it, so a wrapper of one is compiled as HLIL too
HLIL_BODY_MARK = 'hlil_body'


def library_function(body: Callable) -> Callable:
    """A common-function library body's stub, as the script's decorators return for its own functions: CALL(f) and
    @scena.CommonImports() reach the body; f(...) by bare name builds an HLIL call, an error anywhere else"""
    @functools.wraps(body)
    def stub(*args, **kwargs):
        if active_build() is not None:
            return LocalCall(stub, body, args, kwargs)

        # Imported here: scp_writer imports this module for its decorators
        from ..scp_writer import get_scp_writer
        name = body.__name__
        raise TypeError(get_scp_writer().at_statement(f'{name}(...) builds an HLIL call; in an LLIL body write '
                                                      f'CALL({name})'))

    return stub


# The code every stub runs: a functools.wraps wrapper of a stub copies its attributes, never its code
STUB_CODE = library_function(lambda: None).__code__


def stub_body(func: Callable) -> Callable:
    """The body func stands for if it is a stub, else func"""
    return func.__wrapped__ if getattr(func, '__code__', None) is STUB_CODE else func


def mark_hlil_body(body: Callable):
    setattr(body, HLIL_BODY_MARK, True)


def is_hlil_body(body: Callable) -> bool:
    """body is compiled as HLIL: run under a build, its tree lowered; else as LLIL, emitting its own opcodes"""
    return getattr(body, HLIL_BODY_MARK, False) is True
