"""The HLIL DSL's names (docs/dsl/HLIL_DSL.md, Form), which a mixed script gets through its game's scp_hlil_dsl_helper,
a star import of this module; public names: docs/dsl/HOOKS.md. @scena.HLILCode() and the library's functions come
with the script's other imports"""

from .hlil_dsl.nodes import (REGS, And, DebugInt, Float, Int, Let, Local, Not, Or, PopN, Raw, Return, Set, Str, Syscall,
                             script, this)

__all__ = (
    'Set',
    'Let',
    'Return',
    'PopN',
    'DebugInt',
    'Syscall',
    'Local',
    'REGS',
    'this',
    'script',
    'Int',
    'Float',
    'Str',
    'Raw',
    'And',
    'Or',
    'Not',
)
