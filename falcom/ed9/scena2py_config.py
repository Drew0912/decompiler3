"""User-editable settings for scena2py.py. Edit the class attribute defaults below directly."""

from pathlib import Path
from typing import Callable, Optional

from .parser.types_parser import Function


class ScenaDecompileConfig:
    """Output and parser flags for scena2py.py, read directly off this instance's attributes."""

    # Primary outputs
    write_py: bool = True   # round-trippable VM-bytecode Python DSL (.py)
    write_ts: bool = True   # final TypeScript (.ts)

    # Debug/inspection outputs
    write_llil_asm: bool = False   # .llil.asm text dump
    write_llil_dot: bool = False   # one .llil.<func>.dot CFG per function
    write_mlil_asm: bool = False   # .mlil.asm text dump
    write_mlil_dot: bool = False   # one .mlil.<func>.dot CFG per function
    write_hlil_ts: bool = False    # .hlil.ts text dump (HLILFormatter text, not real TypeScript)

    # ScpParser flags
    round_trip: bool = False
    keep_unreachable_code: bool = True

    # MLIL conversion flags, forwarded to convert_falcom_llil_to_mlil
    optimize: bool = True
    infer_types: bool = True

    # Output location; None means a new folder named after the input file, next to it
    output_dir: Optional[Path] = None

    # Optional function filter, forwarded to ScpParser.disasm_all_functions(filter_func=...)
    filter_func: Optional[Callable[[Function], bool]] = None
