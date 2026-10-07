"""The hooks of one writer (ScpWriter.hooks): what <stem>_hook.py files register through scp_writer_hooks - function,
run and opcode callbacks, replaced and added functions - and how the compile applies it. It reads the writer's
functions, functions_by_name, compile_started, globals, current_function and dat_name, and calls its
_register_function, _require_open, _replace_body, _signature and _run_body. Imports scp_writer only for type checking:
scp_writer imports this module."""

import inspect
from pathlib import Path
from types import FunctionType
from typing import TYPE_CHECKING, Callable

from common.logging import log
from .scp_compile_check import SourceSite, def_location

if TYPE_CHECKING:
    from .scp_writer import ScpFunction, ScpWriter


class _OriginalFunction:
    """What original.Name returns. Not a plain function, so it can't become a replacement or a callback (the script's
    names would be set in this module)"""

    def __init__(self, writer: 'ScpWriter', f: 'ScpFunction'):
        self.writer = writer
        self.function = f
        self.__name__ = f.name  # CALL(original.Name) finds the function by name, like CALL(Name)

    @property
    def __signature__(self) -> inspect.Signature:
        """The original's, so a functools.wraps wrapper of original.Name keeps it"""
        return self.writer._signature(self.function.original_body, self.function.name)

    def __call__(self, *args, **kwargs):
        """Bound like a call to the original, never read (see ScpWriter._run_body)"""
        f = self.function
        if self.writer.current_function is None:
            raise ValueError(f'original.{f.name}() is outside a function body')

        signature = self.__signature__
        try:
            signature.bind(*args, **kwargs)

        except TypeError as e:
            raise TypeError(f'original.{f.name}(): {e}') from e

        self.writer._run_body(f, f.original_body)

    def __repr__(self) -> str:
        return f'original.{self.__name__}'


class HookRegistry:
    """What the hook files register on one writer, and the opcode callbacks' state while it compiles"""

    def __init__(self, writer: 'ScpWriter'):
        self.writer = writer

        # What the hook files register
        self.func_callbacks: list[Callable] = []             # cb(name, func) -> None or a new body
        self.replaced: dict[str, Callable] = {}              # replace_function name -> its body
        self.hook_functions: list[Callable] = []             # the hooks' own functions, never the writer's
        self.run_callbacks: list[Callable] = []              # cb(g) when the compile starts
        self.opcode_callbacks: list[Callable] = []           # cb(opcode, *args) -> True drops it
        self.added_functions: list[Callable] = []            # add_function, registered when the compile starts

        # The compile: set as it runs
        self.injected_modules: set[int] = set()              # id() of every hook module given the script's names
        self.in_opcode_callback: bool = False                # opcodes a callback emits skip the callbacks
        self.trigger_site: SourceSite | None = None          # the triggering opcode's site while callbacks run

    # Registration: the hook-file API

    def registerFuncCallback(self, cb: Callable) -> Callable:
        """See scp_writer_hooks.registerFuncCallback"""
        self._add_hook_function(cb, 'registerFuncCallback')
        self.func_callbacks.append(cb)
        return cb

    def replace_function(self, name: str):
        """See scp_writer_hooks.replace_function"""
        if not isinstance(name, str):
            raise TypeError(f"replace_function takes the function's name - @replace_function('Name') - not {name!r}")

        def wrapper(body):
            self._add_hook_function(body, f'replace_function({name!r})')
            earlier = self.replaced.get(name)
            if earlier is not None:
                log.warning(f'{def_location(body)}: replace_function({name!r}) again, '
                            f'overriding the one at {def_location(earlier)}')

            self.replaced[name] = body
            self.func_callbacks.append(lambda func_name, func: body if func_name == name else None)
            return body

        return wrapper

    def registerRunCallback(self, cb: Callable) -> Callable:
        """See scp_writer_hooks.registerRunCallback"""
        self._add_hook_function(cb, 'registerRunCallback')
        self.run_callbacks.append(cb)
        return cb

    def registerOpcodeCallback(self, cb: Callable) -> Callable:
        """See scp_writer_hooks.registerOpcodeCallback"""
        self._add_hook_function(cb, 'registerOpcodeCallback')
        self.opcode_callbacks.append(cb)
        return cb

    def add_function(self, func: Callable) -> Callable:
        """See scp_writer_hooks.add_function"""
        self._add_hook_function(func, 'add_function (used bare: @add_function)')
        if self.writer.compile_started:
            self._register_added(func)

        else:
            self.added_functions.append(func)

        return func

    def _register_added(self, func: Callable):
        """An added function joins the script's after its own functions, so their code stays where it was"""
        existing = self.writer.functions_by_name.get(func.__name__)
        if existing is not None:
            raise ValueError(f'{def_location(func)}: add_function: {func.__name__!r} is already defined at '
                             f'{def_location(existing.original_body)}; replace_function replaces a function')

        self.writer._register_function(func)

    def _add_hook_function(self, func: Callable, what: str):
        """A hook's own function, a plain one (what names it in the error): given the script's names now if the
        compile has started, else when it starts"""
        require_function(func, what)
        self.writer._require_open(func)
        self.hook_functions.append(func)
        if self.writer.compile_started:
            self._inject(func)

    def _inject(self, func: Callable):
        """Hook bodies read like the script: each script name a hook module doesn't define is set in it, once per module
        - in the modules of the functions func wraps too (a decorator from another module wraps a hook's body). Only
        once the compile has started: it reads the writer's globals"""
        for layer in wrapped_chain(func):
            module = getattr(layer, '__globals__', None)
            if module is None or id(module) in self.injected_modules:
                continue

            self.injected_modules.add(id(module))
            for name, value in self.writer.globals.items():
                if not name.startswith('__'):
                    module.setdefault(name, value)

    # When the compile starts

    def _start(self, g: dict):
        """The compile starts: added functions register after the script's, each hook module gets the script's names,
        the run callbacks run, then the function callbacks"""
        for func in self.added_functions:
            self._register_added(func)

        for func in self.hook_functions:
            self._inject(func)

        for cb in self.run_callbacks:
            cb(g)

        self._apply_function_callbacks()

    def _apply_function_callbacks(self):
        """Run the hook function callbacks over every function and give each replaced one its new body"""
        self._require_replaced_functions_exist()
        for f in self.writer.functions:
            body = f.body
            for cb in self.func_callbacks:
                replacement = self._call_function_callback(cb, f, body)
                if replacement is not None:
                    body = replacement
                    f.callback_bodies.append(body)

            if body is not f.body:
                self.writer._replace_body(f, body)

    def _require_replaced_functions_exist(self):
        for name, body in self.replaced.items():
            if name not in self.writer.functions_by_name:
                raise ValueError(f'{def_location(body)}: replace_function({name!r}): '
                                 f'the script has no function {name!r}')

    def _call_function_callback(self, cb: Callable, f: 'ScpFunction', body: Callable) -> Callable | None:
        """What cb returns for f's body so far: None, or a plain function, given the script's names unless it is that
        body passed on"""
        counts = (len(self.writer.functions), len(self.hook_functions))  # every hook registration grows hook_functions
        replacement = cb(f.name, body)
        if (len(self.writer.functions), len(self.hook_functions)) != counts:
            raise ValueError(f"{def_location(cb)}: a function callback can't register functions or callbacks")

        if replacement is None:
            return None

        require_function(replacement, f'{def_location(cb)}: {cb.__name__} for {f.name}')
        if replacement is not body:  # a body merely passed on may be the script's or a library's: no names for it
            self._inject(replacement)

        return replacement

    # During the compile: original.Name, inline_original_func() and the opcode callbacks

    def original_function(self, name: str) -> _OriginalFunction:
        """See scp_writer_hooks.original"""
        if not self.writer.compile_started:
            raise ValueError(f'original.{name} is only available once the compile starts')

        f = self.writer.functions_by_name.get(name)
        if f is None:
            raise AttributeError(f'{Path(self.writer.dat_name).stem} has no function {name!r}')

        return _OriginalFunction(self.writer, f)

    def inline_original_func(self):
        """See scp_writer_hooks.inline_original_func"""
        f = self.writer.current_function
        if f is None:
            raise ValueError('inline_original_func() is outside a function body')

        if f.body is f.original_body:
            raise ValueError(f"{f.name} wasn't replaced; inline_original_func() inlines a replaced function's original body")

        self.writer._run_body(f, f.original_body)

    def _dropped_by_opcode_callbacks(self, opcode: int, args: tuple, site: SourceSite | None) -> bool:
        """Run the opcode callbacks, in registration order, on an opcode a body emits; True when one drops it, and the
        rest don't run; False at once when none is registered. The opcodes a callback emits skip the callbacks and
        carry site as their trigger"""
        if not self.opcode_callbacks or self.in_opcode_callback:
            return False

        self.in_opcode_callback = True
        self.trigger_site = site
        try:
            for cb in self.opcode_callbacks:
                result = cb(opcode, *args)
                if result is True:
                    return True

                if result is not None and result is not False:
                    raise TypeError(f'{def_location(cb)}: opcode callback {cb.__name__} returned {result!r}: '
                                    'True drops the opcode, None or False keeps it')

            return False

        finally:
            self.in_opcode_callback = False
            self.trigger_site = None


def require_function(obj, what: str):
    """Script functions and hooks are plain functions: the source map and the error locations need their code"""
    if not isinstance(obj, FunctionType):
        raise TypeError(f'{what}: expected a plain function (def), not {obj!r}')


def wrapped_chain(func: Callable):
    """func, then each function it wraps (functools.wraps sets __wrapped__); a cycle ends the chain"""
    seen = set()
    while func is not None and id(func) not in seen:
        seen.add(id(func))
        yield func
        func = getattr(func, '__wrapped__', None)
