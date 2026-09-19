"""User-editable settings for scena2py.py. Edit the class attribute defaults below directly."""

from pathlib import Path
from typing import Callable, Optional

from .parser.types_parser import Function

TOOL_DIR = Path(__file__).resolve().parent


class ScenaDecompileConfig:
    """Output and parser flags for scena2py.py, read directly off this instance's attributes."""

    # Primary outputs
    write_py: bool = True   # round-trippable VM-bytecode Python DSL (.py)
    write_ts: bool = True   # final TypeScript (.ts)

    # Debug/inspection outputs
    write_llil_asm: bool = False    # .llil.asm text dump
    write_llil_dot: bool = False    # one .llil.<func>.dot CFG per function. Use Graphviz Online
    write_mlil_asm: bool = True    # .mlil.asm text dump
    write_mlil_dot: bool = False    # one .mlil.<func>.dot CFG per function. Use Graphviz Online
    write_hlil_ts: bool = False     # .hlil.ts text dump (HLILFormatter text, not recompilable code)

    # Parsed header, per-function ScpFunctionEntry, per-call debug info. Populated during
    # parsing regardless of round_trip, except zero-arg-count debug records are dropped when
    # round_trip=False (ScpParser._read_functions)
    write_debug_info: bool = False    # .debug.txt

    # ScpParser flags
    round_trip: bool = False
    keep_unreachable_code: bool = False

    # Exclude common/shared functions (is_common_func) from every output format, to make
    # scripts shorter and easier to read. The .py DSL output will not compile back to a
    # .dat file with this on, since callers still reference the now-missing definitions.
    include_common_functions: bool = True

    # MLIL conversion flags, forwarded to convert_falcom_llil_to_mlil
    optimize_mlil: bool = True
    infer_types: bool = True

    # Output location
    output_dir: Path = TOOL_DIR / 'out'

    # Optional function filter, forwarded to ScpParser.disasm_all_functions(filter_func=...)
    filter_func: Optional[Callable[[Function], bool]] = None # lambda f: f.name == 'TestCitySet'

