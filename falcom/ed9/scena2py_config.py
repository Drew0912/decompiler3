"""User-editable settings for scena2py.py. Edit the class attribute defaults below directly."""

from pathlib import Path
from typing import Callable, Optional

from common import StrictBase
from .parser.scp_listing import ListingSections
from .parser.types_parser import Function

TOOL_DIR = Path(__file__).resolve().parent


class ScenaDecompileConfig(StrictBase):
    """Output and parser flags for scena2py.py, read directly off this instance's attributes."""

    # Primary outputs
    write_py: bool = True   # round-trippable VM-bytecode Python DSL (.py)
    write_ts: bool = True   # final TypeScript (.ts)
    write_hook_template: bool = False   # a starting <stem>_hook.py next to the .py (with write_py); never over an existing file

    # .py comments (scripts only; the common library always has the stack comments and never the others)
    stack_slot_comments: bool = True       # the slot each LOAD_STACK/POP_TO/... addresses, sp at labels, POP's slots
    float_bits_comments: bool = False      # PUSH_FLOAT's float32 bits and stored word: f32 0x3E999998, raw 0x8FA66666
    function_id_comments: bool = False     # above each function: # id: 0x001C offset: 0x21FF7 (table index, offset)
    call_arg_comments: bool = False        # the argument each push becomes: # arg1, or # slot 1 = arg2, passed as arg2

    # Debug/inspection outputs
    write_llil_asm: bool = False    # .llil.asm text dump
    write_llil_dot: bool = False    # one .llil.<func>.dot CFG per function. Use Graphviz Online
    write_mlil_asm: bool = True    # .mlil.asm text dump
    write_mlil_dot: bool = False    # one .mlil.<func>.dot CFG per function. Use Graphviz Online
    write_hlil_ts: bool = False     # .hlil.ts text dump (HLILFormatter text, not recompilable code)

    # .debug.txt: a listing of the whole .dat as the VM sees it (header, global vars, each function's table entry, code
    # and call-site debug records, the string pool), loaded on its own with the unreachable code decoded. Written last;
    # filter_func / include_common_functions pick the functions listed
    write_debug_info: bool = False
    debug_sections: ListingSections = ListingSections()     # what it prints: every section; e.g. ListingSections(code = False)

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

