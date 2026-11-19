"""User-editable settings for scp2py.py. Edit the class attribute defaults below directly."""

from pathlib import Path
from typing import Callable

from dc3 import StrictBase
from .formatter.listing import ListingSections
from .assembler.function import Function


class ScpDecompileConfig(StrictBase):
    """Output flags for scp2py.py, read directly off this instance's attributes"""

    # Primary outputs
    write_py: bool = True   # <stem>.py: each function whose HLIL DSL text compiles to its own code as
                            # @scena.HLILCode(), the rest in the LLIL DSL (docs/dsl/HLIL_DSL.md, File names)
    write_ts: bool = True   # final TypeScript (.ts)
    write_hlil_ts: bool = True  # the bytecode's high-level form (.hlil.ts): not TypeScript, not recompilable
    write_hook_template: bool = False   # a starting <stem>_hook.py next to the .py; never over an existing file

    # .py and .llil.py comments, on LLIL functions only (the common library: always the stack comments, no others)
    stack_slot_comments: bool = True       # the slot each LOAD_STACK/POP_TO/... addresses, sp at labels, POP's slots
    float_bits_comments: bool = False      # PUSH_FLOAT's float32 bits and stored word: f32 0x3E999998, raw 0x8FA66666
    function_id_comments: bool = False     # above each function: # id: 0x001C offset: 0x21FF7 (table index, offset)
    call_arg_comments: bool = False        # the argument each push becomes: # arg1, or # slot 1 = arg2, passed as arg2

    # Debug/inspection outputs
    write_llil_py: bool = False     # <stem>.llil.py: every function in the LLIL DSL, common functions inline, no hooks
    # With write_llil_py: <stem>.llil.py from a second parse that keeps every byte (call-site records, dead code), so it
    # compiles to the original's bytes; the other outputs never change with it. Alone: a warning, nothing written
    round_trip: bool = False
    write_llil_asm: bool = False    # .llil.asm text dump
    write_llil_dot: bool = False    # one .llil.<func>.dot CFG per function. Use Graphviz Online
    write_mlil_asm: bool = True    # .mlil.asm text dump
    write_mlil_dot: bool = False    # one .mlil.<func>.dot CFG per function. Use Graphviz Online

    # .hlil.ts and .ts: a // line(N) comment where each source line starts (the .py keeps its DEBUG_SET_LINENO)
    line_markers: bool = True

    # .ts: an ID at a reviewed syscall slot by name, from the game's metadata/syscall_args.py and its tables - so far
    # character IDs, ChrIdTable['Estelle'] or PseudoChrId.Self (chr_table.py); off, or for a game without
    # syscall_args.py, every ID a number
    id_names: bool = True

    # .debug.txt: a listing of the whole .dat as the VM sees it (header, global vars, each function's table entry, code
    # and call-site debug records, the string pool), loaded on its own with the unreachable code decoded. Written last;
    # filter_func picks the functions listed
    write_debug_info: bool = False
    debug_sections: ListingSections = ListingSections()     # what it prints: every section; e.g. ListingSections(code = False)

    # Output location: None is the game's out/ (falcom/ed9/games/<game>/out); -o sets it for one run
    output_dir: Path | None = None

    # Optional function filter, forwarded to ScpParser.disasm_all_functions(filter_func=...).
    # The output is partial on purpose: its .py is not meant to compile back to a .dat file
    filter_func: Callable[[Function], bool] | None = None  # lambda f: f.name == 'TestCitySet'
