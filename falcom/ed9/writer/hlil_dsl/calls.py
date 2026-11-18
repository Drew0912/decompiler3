"""The HLIL DSL's calls (docs/dsl/HLIL_DSL.md, Form): a script or library function's call through its stub, another
script's through script.module.name(...), and the functions whose call makes a DSL call besides those (ED9's Syscall).
A call is the one value that may also stand as a statement"""

import inspect

from .build import Build
from .nodes import Expr, Statement, TrackedNode, claim

# The functions whose call makes a DSL call besides the stubs and script.module.name (ED9's Syscall), each registered
# where it is defined; a wrapper of one is not one, as a stub's wrapper is not a stub
_dsl_call_makers: list = []


def dsl_call_maker(function):
    _dsl_call_makers.append(function)
    return function


def makes_dsl_call(callee) -> bool:
    """callee's call makes a DSL call: script.module.name, or a registered function itself (the source check reads
    a helper's calls by it; a stub it tells by the stub's code)"""
    return isinstance(callee, ScriptFunction) or any(callee is maker for maker in _dsl_call_makers)


class Call(TrackedNode, Expr):
    """A call: a statement when nothing uses it, else its result (the VM's result register after the call)"""

    def claim_args(self, build: Build, args: tuple, kwargs: dict):
        if kwargs:
            raise build.fail(f'{self!r} takes its arguments by position (the VM passes them so), not '
                             f'{', '.join(kwargs)}=')

        self.args = tuple(claim(build, arg, self) for arg in args)
        self.children = self.args


BodyStatement = Statement | Call    # what may stand on a line of its own


class LocalCall(Call):
    """A call of a script or library function: every parameter given, since a local call ignores defaults"""

    def __init__(self, function, body, args: tuple, kwargs: dict):
        """function is what CALL takes, as an LLIL body passes it (the stub its name is bound to); body its body"""
        build = self.join_build(f'{function.__name__}(...)')
        self.function = function
        self.name = function.__name__
        # Counted as registration counts them: a functools.wraps wrapper has its wrapped function's
        param_count = len(inspect.signature(body).parameters)
        if not kwargs and len(args) != param_count:
            raise build.fail(f'{self.name} takes {param_count} arguments, {len(args)} given: a local call passes every '
                             'one, defaults too (a local CALL ignores defaults)')

        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'{self.name}(...)'


class ScriptCall(Call):
    """script.module.name(...), a call of another script's function: the arguments as written, since a script call
    may leave out trailing defaults"""

    def __init__(self, module: str, name: str, args: tuple, kwargs: dict):
        build = self.join_build(f'script.{module}.{name}(...)')
        self.module = module
        self.name = name
        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'script.{self.module}.{self.name}(...)'


class ScriptFunction:
    def __init__(self, module: str, name: str):
        self.module = module
        self.name = name

    def __call__(self, *args, **kwargs) -> ScriptCall:
        return ScriptCall(self.module, self.name, args, kwargs)

    def __repr__(self) -> str:
        return f'script.{self.module}.{self.name}'


class _ScriptModule:
    def __init__(self, module: str):
        self.module = module

    def __getattr__(self, name: str) -> ScriptFunction:
        if name.startswith('__'):
            raise AttributeError(name)

        return ScriptFunction(self.module, name)

    def __repr__(self) -> str:
        return f'script.{self.module}'


class _Script:
    """script: script.module.name(...) calls another script's function"""

    def __getattr__(self, module: str) -> _ScriptModule:
        if module.startswith('__'):
            raise AttributeError(module)

        return _ScriptModule(module)

    def __repr__(self) -> str:
        return 'script'


script = _Script()
