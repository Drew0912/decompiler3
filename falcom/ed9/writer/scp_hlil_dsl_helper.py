"""The HLIL DSL's names (docs/dsl/HLIL_DSL.md, Form), which a mixed script gets through its game's scp_hlil_dsl_helper,
a star import of this module; public names: docs/dsl/HOOKS.md. @scena.HLILCode() and the library's functions come
with the script's other imports"""

from .hlil_dsl.calls import script
from .hlil_dsl.control import Break, Continue, If, While
from .hlil_dsl.ed9_nodes import REGS, DebugInt, PopN, Raw, Syscall
from .hlil_dsl.nodes import And, Float, Int, Let, Local, Not, Or, Return, Set, Str, this

__all__ = (
    'If',
    'While',
    'Break',
    'Continue',
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
