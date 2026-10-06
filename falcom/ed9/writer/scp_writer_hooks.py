"""The hook-file API: bare-name registrations a <stem>_hook.py makes on the writer (star-imported by scp_writer_helper,
so a hook needs only that one import), and original / inline_original_func() for hook bodies. The hooks themselves run
inside ScpWriter.build(), where the script's names (its functions, scena, ...) are also set in each hook module, so hook
bodies can use them like the script does"""

from typing import Callable

from .scp_writer import get_scp_writer


def registerFuncCallback(cb: Callable) -> Callable:
    """Hook: cb(name, func) for every function when the compile starts - None keeps it, a function replaces its body.
    Returns cb, so it also works as a decorator"""
    return get_scp_writer().registerFuncCallback(cb)


def replace_function(name: str):
    """Hook decorator: the decorated function replaces the body of the script's function name"""
    return get_scp_writer().replace_function(name)


def registerRunCallback(cb: Callable) -> Callable:
    """Hook: cb(g) with the script's globals when the compile starts, before the function callbacks; it may add
    functions and global vars. Returns cb, so it also works as a decorator"""
    return get_scp_writer().registerRunCallback(cb)


def registerOpcodeCallback(cb: Callable) -> Callable:
    """Hook: cb(opcode, *args) for each opcode a body emits, with its operands as the DSL function passed them, before
    it is written - True drops it, None or False keeps it. The opcodes cb emits itself skip the callbacks. Returns cb,
    so it also works as a decorator"""
    return get_scp_writer().registerOpcodeCallback(cb)


def add_function(func: Callable) -> Callable:
    """Hook decorator, used bare (@add_function): a new script function, compiled after the script's own; every
    parameter needs a type"""
    return get_scp_writer().add_function(func)


class _Original:
    """original.Name(...) in a hook body inlines the script's own Name - its body from before any hook - right there,
    with arguments as for a normal call to it. CALL(original.Name) is CALL(Name). Available once the compile starts"""

    def __getattr__(self, name: str) -> Callable:
        if name.startswith('__'):
            raise AttributeError(name)

        return get_scp_writer().original_function(name)


original = _Original()


def inline_original_func():
    """In a replaced function's body: inline the function's body from before any hook, right there"""
    get_scp_writer().inline_original_func()
