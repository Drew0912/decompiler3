"""Logic check: does a layer keep the game logic of the one below it? Per function, each layer is evaluated over storage
that means the same on every layer, and their effects (with argument values and guards), branches, effect order and
loop-carried values are compared (docs/FUTURE_WORK.md, "Static Game-Logic Check", Step A; the IR rewrite's gate):
LLIL against MLIL, the LLIL the trust root, and MLIL against HLIL. Read-only on the IR.

The package imports the decompiler as `ir` and `falcom`: the repo root on sys.path"""

from .compare import CATEGORIES, Difference, compare_facts, compare_gated
from .evaluation import Facts, analyze
from .hlil_layer import HLILLayer
from .llil_layer import LLILLayer
from .mlil_layer import MLILLayer
from .scripts import FunctionResult, check_script, compare_llil_mlil, compare_mlil_hlil

__all__ = [
    'CATEGORIES',
    'Difference',
    'Facts',
    'FunctionResult',
    'HLILLayer',
    'LLILLayer',
    'MLILLayer',
    'analyze',
    'check_script',
    'compare_facts',
    'compare_gated',
    'compare_llil_mlil',
    'compare_mlil_hlil',
]
