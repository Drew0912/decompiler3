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
    write_llil_asm: bool = True    # .llil.asm text dump
    write_llil_dot: bool = True    # one .llil.<func>.dot CFG per function. Use Graphviz Online
    write_mlil_asm: bool = True    # .mlil.asm text dump
    write_mlil_dot: bool = True    # one .mlil.<func>.dot CFG per function. Use Graphviz Online
    write_hlil_ts: bool = False     # .hlil.ts text dump (HLILFormatter text, not real TypeScript)

    # .debug.txt: parsed header, per-function ScpFunctionEntry, per-call debug info. Populated during
    # parsing regardless of round_trip, except zero-arg-count debug records are dropped when
    # round_trip=False (ScpParser._read_functions) - unrelated to pair_call_debug_info/call_debug_argc,
    # which this dump doesn't show.
    write_debug_info: bool = True

    # ScpParser flags
    round_trip: bool = False
    keep_unreachable_code: bool = True

    # MLIL conversion flags, forwarded to convert_falcom_llil_to_mlil
    optimize: bool = True
    infer_types: bool = True

    # Output location; None means a new folder named after the input file, collected flat under
    # falcom/ed9/out/ (same-named inputs from different folders will collide there - see
    # default_output_dir in scena2py.py)
    output_dir: Optional[Path] = None

    # Optional function filter, forwarded to ScpParser.disasm_all_functions(filter_func=...)
    filter_func: Optional[Callable[[Function], bool]] = None
