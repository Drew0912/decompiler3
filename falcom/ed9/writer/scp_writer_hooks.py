"""The hook-file API: bare-name registrations a <stem>_hook.py makes on the writer (star-imported by scp_writer_helper,
so a hook needs only that one import). The hooks themselves run inside ScpWriter.build()"""

from typing import Callable

from .scp_writer import get_scp_writer


def registerFuncCallback(cb: Callable):
    """Hook: cb(name, func) for every function when the compile starts - None keeps it, a function replaces its body"""
    get_scp_writer().registerFuncCallback(cb)


def replace_function(name: str):
    """Hook decorator: the decorated function replaces the body of the script's function name"""
    return get_scp_writer().replace_function(name)
