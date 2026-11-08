from typing import Callable
import bisect
import functools
import importlib
import keyword
import pathlib
import struct
import sys

from ..structs.scp_types import *
from .parser_types import GlobalVar
from dc3 import default_indent, fileio, quote_string, StrictBase
from assembler import BasicBlock, Disassembler, Instruction
from ..assembler import *
from ..assembler.ed9_optable import *
from ..assembler.disassembler import (ScpDisassemblerContext, ScpDisassemblyError, on_block_split, on_block_start,
                                      on_disasm_function, on_instruction_decoded, on_pre_add_branch)
from ..assembler.function import Function, FunctionParam
from ..formatter.llil_dsl.comments import GLOBAL_VAR_INDEX_COMMENT, CommentOptions, append_comment
from ..formatter.llil_dsl.function_formatter import Formatter, FormatterContext
from ..structs.call_debug_records import PUSH_CONSTANT_OPS, canonical_argc, pair_records
from ..structs.string_pool import string_offset
from ..structs.common_library import (COMMON_ALL_MODULE, COMMON_INDEX_MODULE, COMMON_LIBRARY_MISSING_HINT,
                                      game_metadata_module)
from ..structs.fingerprint import function_fingerprint, fingerprint_digest
from ..structs.generated_script import (DEFINITION_SPACING, SCP_WRITER_HELPER_IMPORT, SYS_PATH_SETUP_LINES,
                                        game_writer_helper_import)
from dc3.logging import log
from dc3.utils import PROJECT_ROOT


@functools.cache
def common_library_index(game: str) -> dict[str, tuple[str, str]]:
    """game's library index (name -> module, fingerprint digest), loaded once per game per process; {} when the library
    is not generated, with the hint logged that once. The index only, not common_all: the modules load the writer,
    which a decompile never uses. A missing game package re-raises, as in a script's library import"""
    module = game_metadata_module(game, COMMON_INDEX_MODULE)
    try:
        return importlib.import_module(module).COMMON_FUNCTIONS
    except ModuleNotFoundError as e:
        if e.name != module:
            raise

    log.info(f'Every common function inline: {COMMON_LIBRARY_MISSING_HINT.format(game=game)}')
    return {}


def is_module_name(name: str) -> bool:
    """An import statement can name it: an identifier that isn't a keyword"""
    return name.isidentifier() and not keyword.iskeyword(name)


def shadows_another_module(name: str) -> bool:
    """Pylance imports a stdlib module or one of this checkout's top-level packages of that name instead of a script
    next to the hook (e.g. dc3.dat, types.dat)"""
    return name in sys.stdlib_module_names or (PROJECT_ROOT / name).is_dir() or (PROJECT_ROOT / f'{name}.py').is_file()


def suggested_module_name(stem: str) -> str:
    """A module name close to stem that no other module takes, for the hook template's rename hint: mon5078+ ->
    mon5078_, dc3 -> dc3_"""
    name = ''.join(char if f'_{char}'.isidentifier() else '_' for char in stem.strip())
    if not name.isidentifier():
        name = f'_{name}'       # a leading digit

    if keyword.iskeyword(name) or shadows_another_module(name):
        name = f'{name}_'

    return name


# The script calls: their module and function are string operands
SCRIPT_CALL_OPS = opcodes_of(InstructionKind.CALL_SCRIPT, InstructionKind.TAIL_CALL)

# Every pseudo-op encoded as the real PUSH: one ScpValue word after the size byte
PUSH_ENCODED_OPS = (*PUSH_CONSTANT_OPS, *opcodes_of(InstructionKind.PUSH_FUNC_ID, InstructionKind.PUSH_RET_ADDR))

OPCODE_SIZE             = 1     # every opcode is one byte, followed by its operands

class ScpParser(StrictBase):
    # Keep data only needed for a byte-exact round trip: the call debug records, read only for the
    # explicit arg count of each local CALL (debug_argc). Source function order is always kept - it's a free
    # reordering of already-parsed data, not extra fidelity data, so it isn't gated by this flag.
    round_trip      : bool = True

    # Decode code no branch reaches (e.g. a JMP right after RETURN) so the .py keeps it for a byte-exact round trip
    keep_unreachable_code : bool = True

    # The game (its folder under falcom/ed9/games/) whose common-function library the everyday decompile matches
    # against and the .py imports; None: no library, every common function inline, no library import
    game            : str | None = None

    # The compile check's stricter reading of bytes it just compiled: a slot outside the live stack fails instead of
    # only warning, so does a read past the stack, and no code may run or jump past the known end of the code
    reject_outside_stack : bool = False
    known_code_end  : int | None = None

    fs              : fileio.FileStream
    name            : str
    header          : ScpHeader
    function_entries: list[ScpFunctionEntry]
    functions       : list[Function]
    global_vars     : list[GlobalVar]
    function_map    : dict[str, Function]
    defaults_by_func_id : list[list[ScpValue | None]] | None = None    # func_defaults(), once the table is read
    data            : bytes | None = None   # round_trip: the file's bytes, which the call debug records pair against

    def __init__(self, fs: fileio.FileStream, name: str = ''):
        self.fs = fs
        self.name = name

    @classmethod
    def load(
        cls,
        path: pathlib.Path,
        *,
        round_trip: bool,
        keep_unreachable_code: bool,
        game: str | None = None,
        filter_func: Callable[[Function], bool] | None = None,
    ) -> tuple[ScpParser, list[Function]]:
        """Read path, parse, and disassemble every function - the setup every caller (scp2py.py,
        the common-function generator, the round-trip validator, tests) otherwise repeats by hand.
        The parser stays fully usable afterward (get_func_name_from_func_id, get_func_argc, etc.
        are all in-memory)."""
        return cls.load_bytes(path.read_bytes(), path.name, round_trip=round_trip,
                              keep_unreachable_code=keep_unreachable_code, game=game, filter_func=filter_func)

    @classmethod
    def load_bytes(
        cls,
        data: bytes,
        name: str,
        *,
        round_trip: bool,
        keep_unreachable_code: bool,
        game: str | None = None,
        filter_func: Callable[[Function], bool] | None = None,
        quiet: bool = False,
        reject_outside_stack: bool = False,
        known_code_end: int | None = None,
    ) -> tuple[ScpParser, list[Function]]:
        """load() for a script already in memory, named name; quiet drops the per-function progress and error lines
        and the unusual-slot and backward-return warnings, for a caller that reports them itself (the compile check).
        reject_outside_stack and known_code_end are the compile check's (see the class attributes)."""
        with fileio.FileStream(data) as fs:
            parser = cls(fs, name)
            parser.round_trip = round_trip
            parser.keep_unreachable_code = keep_unreachable_code
            parser.game = game
            parser.reject_outside_stack = reject_outside_stack
            parser.known_code_end = known_code_end
            parser.parse()
            functions = parser.disasm_all_functions(filter_func=filter_func, quiet=quiet)

        return parser, functions

    def get_func_index(self, name: str) -> int | None:
        """A function's table index by its name, None when the script doesn't define it"""
        func = self.function_map.get(name)
        return func.index if func is not None else None

    def get_func_name_from_func_id(self, func_id: int) -> str:
        return self.functions[func_id].name

    def get_global_name_from_index(self, index: int) -> str | None:
        if 0 <= index < len(self.global_vars):
            return self.global_vars[index].name

        return None

    def get_func_argc(self, func_id: int) -> int:
        return len(self.functions[func_id].params)

    def parse(self):
        fs = self.fs
        self.header = ScpHeader(fs=fs)

        self.function_entries   = self._read_function_entries(fs)
        self.functions          = self._read_functions(fs, self.function_entries)
        self.global_vars        = self._read_global_vars(fs)

        self.function_map = {func.name: func for func in self.functions}

    def _read_function_entries(self, fs: fileio.FileStream):
        return [ScpFunctionEntry(fs=fs) for _ in range(self.header.function_count)]

    def _read_functions(self, fs: fileio.FileStream, func_entries: list[ScpFunctionEntry]) -> list[Function]:
        functions: list[Function] = []

        for index, entry in enumerate(func_entries):
            func = Function()

            func.index = index
            func.is_common_func = entry.is_common_func == 1
            func.offset = entry.offset

            _, func.name = ScpValue.decode_word(entry.name_offset, fs=fs)

            fs.Position = entry.param_flags_offset
            param_flags = [ScpParamFlags(fs=fs) for _ in range(entry.param_count)]

            fs.Position = entry.default_params_offset
            defaults = [ScpValue(fs=fs) for _ in range(entry.default_params_count)]
            default_params = [None] * (len(param_flags) - len(defaults)) + defaults

            for i in range(entry.param_count):
                param = FunctionParam(type=param_flags[i], default_value=default_params[i])
                default = param.default_value
                if default is not None and (default.type == ScpValue.Type.String) != param.type.takes_string():
                    log.warning(f'{func.name}: parameter {i + 1} is {param.type.get_python_type()} but defaults to '
                                f'{default.value!r}: the writer rejects that, so compiling the .py will fail')

                func.params.append(param)

            functions.append(func)

        # Call debug records only give each local CALL's explicit arg count (debug_argc), kept for a byte-exact round
        # trip; paired with the calls against the file's bytes, as the listing and the validator do
        if not self.round_trip:
            return functions

        self.data = fs.ReadAll()
        for func, entry in zip(functions, func_entries):
            func.debug_info = self.read_debug_info(fs, entry)

        return functions

    def read_debug_info(self, fs: fileio.FileStream, func_entry: ScpFunctionEntry) -> list[ScpFunctionCallDebugInfo]:
        if func_entry.debug_info_count == 0:
            return []

        fs.Position = func_entry.debug_info_offset
        return [ScpFunctionCallDebugInfo(fs=fs) for _ in range(func_entry.debug_info_count)]

    def _read_global_vars(self, fs: fileio.FileStream) -> list[GlobalVar]:
        fs.Position = self.header.global_var_offset
        entries = [ScpGlobalVar(fs=fs) for _ in range(self.header.global_var_count)]
        return [GlobalVar(index=i, name=entry.name, type=entry.type) for i, entry in enumerate(entries)]


    # disassemble

    def require_code_before_strings(self, functions: list[Function]):
        """Every reachable instruction must end before the string pool, whose start is known only from references: the
        function names and the strings decoded code references. Unreachable references count only when
        keep_unreachable_code decoded them; undecoded or filtered-out code does not tighten the bound."""
        code_end = self.get_code_end(functions)
        if self.keep_unreachable_code:
            unreachable = [inst for func in functions for inst in func.unreachable_instructions()]
            code_end = min([code_end, *self.get_string_refs(unreachable)])

        for func in functions:
            for inst in func.reachable_instructions():
                if inst.offset + inst.size > code_end:
                    raise ScpDisassemblyError(
                        f'{func.name}: {inst.mnemonic} at 0x{inst.offset:X} runs past the end of the code '
                        f'(0x{code_end:X})', func.name, inst.offset
                    )

    def require_disjoint_instructions(self, functions: list[Function]):
        """Functions may share code - the same instruction at the same offset - but no instruction may partially overlap
        another, in one function or across functions"""
        sizes = {inst.offset: inst.size for func in functions for inst in func.reachable_instructions()}
        offsets = sorted(sizes)
        for offset, next_offset in zip(offsets, offsets[1:]):
            if offset + sizes[offset] > next_offset:
                raise ScpDisassemblyError(
                    f'The instruction at 0x{offset:X} overlaps the instruction at 0x{next_offset:X}', offset=next_offset
                )

    def disasm_context(self, func: Function, code_end: int | None, quiet: bool = False) -> ScpDisassemblerContext:
        """A fresh context for disassembling func, whose code ends at code_end"""
        return ScpDisassemblerContext(
            get_func_argc=self.get_func_argc,
            on_disasm_function=on_disasm_function,
            on_block_start=on_block_start,
            on_instruction_decoded=on_instruction_decoded,
            on_pre_add_branch=on_pre_add_branch,
            on_block_split=on_block_split,
            create_fallthrough_jump=ed9_create_fallthrough_jump,
            current_func=func,
            functions=self.functions,
            code_end=code_end,
            known_code_end=self.known_code_end,
            reject_outside_stack=self.reject_outside_stack,
            quiet=quiet,
        )

    def disasm_all_functions(self, filter_func=None, quiet: bool = False) -> list[Function]:
        """Disassemble all functions in the SCP file; quiet drops the per-function progress and error lines and the
        unusual-slot and backward-return warnings. A function's failure is raised as a ScpDisassemblyError naming it."""
        disassembled_functions = []
        starts = sorted({func.offset for func in self.functions})

        for func in self.functions:
            # Apply filter if provided
            if filter_func and not filter_func(func):
                continue

            if not quiet:
                log.info(f'Disassembling {func.name} @ 0x{func.offset:08X}')

            # Create new context for each function; its code ends where the next function starts, the last one's
            # where the code ends when that is known
            next_start = bisect.bisect_right(starts, func.offset)
            context = self.disasm_context(func, starts[next_start] if next_start < len(starts) else self.known_code_end,
                                          quiet)

            disasm = Disassembler(ED9_INSTRUCTION_TABLE, context)
            try:
                func.entry_block = disasm.disasm_function(self.fs, offset=func.offset, name=func.name)
                func.stack_layout = context.stack_layout(func.entry_block)
                func.runs_on = context.runs_on
                func.backward_returns = context.backward_returns
                disassembled_functions.append(func)
            except Exception as e:
                if not quiet:
                    log.error(f'Error disassembling {func.name} @ 0x{func.offset:08X}: {e}')

                error = e if isinstance(e, ScpDisassemblyError) else ScpDisassemblyError.at(func.name, e)
                error.runs_on = context.runs_on
                error.backward_returns = context.backward_returns
                if error is e:
                    raise

                raise error from e

        self.require_disjoint_instructions(disassembled_functions)

        if self.keep_unreachable_code:
            self.find_unreachable_code(disassembled_functions, has_all_functions=filter_func is None)

        # After the dead code is decoded: its calls have records too
        if self.round_trip:
            for func in disassembled_functions:
                self.pair_call_debug_info(func)

        self.require_code_before_strings(disassembled_functions)

        # The table is sorted by name, but code is laid out in source order
        disassembled_functions.sort(key=lambda func: func.offset)

        return disassembled_functions

    def pair_call_debug_info(self, func: Function):
        """Recover the args each local CALL's debug record keeps, by CALL offset, from its calls in the code the .py
        prints (reachable and decoded dead code); where that isn't the compiler's rule (canonical_argc) the .py writes
        it on the CALL, and on a call the compiler left without a record, debug_record=False"""
        pairing = pair_records(self.data, func.code_instructions(), func.debug_info, self.get_func_argc,
                               self.get_func_index, func.is_common_func)
        if not pairing.paired:
            log.warning(f'{func.name}: records not paired: {pairing.reason}; the .py writes no debug_argc')
            return

        func.call_unrecorded = set(pairing.unrecorded)
        defaults = self.func_defaults()
        for match in pairing.matches:
            if match.call.call_type != ScpFunctionCallDebugInfo.CallType.Local:
                continue

            written = match.record.arg_count
            func.call_written_argc[match.offset] = written
            if written != canonical_argc(match.call.args, defaults[match.call.target]):
                func.call_debug_argc[match.offset] = written

    def func_defaults(self) -> list[list[ScpValue | None]]:
        """Each function's defaults by table index, one entry per parameter (None without a default); built once"""
        if self.defaults_by_func_id is None:
            self.defaults_by_func_id = [[param.default_value for param in func.params] for func in self.functions]

        return self.defaults_by_func_id

    def find_unreachable_code(self, functions: list[Function], has_all_functions: bool):
        """Linearly decode the bytes no branch reaches (between reachable instructions and up to the next function)
        into func.unreachable_blocks"""
        if not functions:
            return

        starts = sorted(func.offset for func in self.functions)
        next_starts = dict(zip(starts, starts[1:]))
        code_end = self.get_code_end(functions)

        # Code order, so strings used by earlier unreachable code can lower code_end before the last function's tail
        for func in sorted(functions, key=lambda f: f.offset):
            instructions = func.reachable_instructions()
            blocks = []
            cursor = func.offset

            for inst in instructions:
                if inst.offset > cursor:
                    blocks.append(self._decode_unreachable_block(func, cursor, inst.offset))

                cursor = max(cursor, inst.offset + inst.size)

            blocks = [block for block in blocks if block is not None]
            code_end = min([code_end, *self.get_string_refs([inst for block in blocks for inst in block.instructions])])

            # The last function in code order runs up to the string pool, only known when every function's strings
            # were seen
            end = next_starts.get(func.offset, code_end if has_all_functions else None)
            if end is not None and cursor < end:
                tail = self._decode_unreachable_block(func, cursor, end)
                if tail is not None:
                    blocks.append(tail)
                    code_end = min([code_end, *self.get_string_refs(tail.instructions)])

            func.unreachable_blocks = self._prune_unreachable_blocks(func, instructions, blocks)

    def get_code_end(self, functions: list[Function]) -> int:
        """Where the string pool starts - it holds the code strings first, then the function names"""
        names = [string_offset(entry.name_offset) for entry in self.function_entries]
        code_strings = self.get_string_refs([inst for func in functions for inst in func.reachable_instructions()])
        return min([offset for offset in names if offset is not None] + code_strings)

    def get_string_refs(self, instructions: list[Instruction]) -> list[int]:
        """String pool offsets referenced by PUSH_STR and CALL_SCRIPT operands"""
        refs = []
        with self.fs.PositionSaver:
            for position in self.string_operand_positions(instructions):
                self.fs.Position = position
                offset = string_offset(self.fs.ReadULong())
                if offset is not None:
                    refs.append(offset)

        return refs

    @classmethod
    def string_operand_positions(cls, instructions: list[Instruction]) -> list[int]:
        """File positions of the operand words that may reference a string: PUSH_STR's value, CALL_SCRIPT's module
        and func"""
        return [position for inst in instructions if inst.opcode == ED9Opcode.PUSH_STR or inst.opcode in SCRIPT_CALL_OPS
                for position in cls.value_positions(inst)]

    @classmethod
    def value_positions(cls, inst: Instruction) -> list[int]:
        """File positions of an instruction's ScpValue words: a push's value, CALL_SCRIPT's module and func"""
        if inst.opcode in PUSH_ENCODED_OPS:
            return [inst.offset + inst.size - ScpValue.WORD.size]                    # PUSH ends with its ScpValue

        if inst.opcode in SCRIPT_CALL_OPS:
            return [inst.offset + OPCODE_SIZE, inst.offset + OPCODE_SIZE + ScpValue.WORD.size]  # module, func

        return []

    def _decode_unreachable_block(self, func: Function, start: int, end: int) -> BasicBlock | None:
        """Linearly decode [start, end), or None (with a warning) when the bytes aren't whole instructions"""
        block = BasicBlock(offset=start)
        fs = self.fs

        with fs.PositionSaver:
            fs.Position = start

            try:
                while fs.Position < end:
                    block.instructions.append(ED9_INSTRUCTION_TABLE.decode_instruction(fs, fs.Position))
            except (ValueError, struct.error) as e:
                log.warning(f'{func.name}: unreachable code 0x{start:X}..0x{end:X} not kept, decode failed: {e}')
                return None

            if fs.Position != end:
                log.warning(f'{func.name}: unreachable code 0x{start:X}..0x{end:X} not kept, last instruction ends at 0x{fs.Position:X}')
                return None

        return block

    @classmethod
    def _prune_unreachable_blocks(cls, func: Function, instructions: list[Instruction],
                                  blocks: list[BasicBlock]) -> list[BasicBlock]:
        """Drop unreachable blocks that branch to an offset with no kept instruction - their label would never be
        emitted"""
        reachable_offsets = {inst.offset for inst in instructions}

        while True:
            offsets = reachable_offsets | {inst.offset for block in blocks for inst in block.instructions}
            dropped = {block for block in blocks
                       if any(target not in offsets for target in block.branch_targets())}
            if not dropped:
                return blocks

            for block in blocks:
                if block in dropped:
                    log.warning(f'{func.name}: unreachable code at 0x{block.offset:X} not kept, it branches to an offset with no instruction')

            blocks = [block for block in blocks if block not in dropped]

    def format_function(self, func: Function, comments: CommentOptions = CommentOptions()) -> list[str]:
        """Format a disassembled function"""
        formatter_context = FormatterContext(
            get_func_name_from_func_id=self.get_func_name_from_func_id,
            get_global_name_from_index=self.get_global_name_from_index,
            comments=comments,
        )
        formatter = Formatter(formatter_context)
        return formatter.format_function(func)

    def gen_python_script(self, functions: list[Function], *, comments: CommentOptions = CommentOptions()) -> str:
        """Full generated .py text: header (incl. shared-library imports/manifest), every function this
        script must still define itself, then the footer. match_library_functions runs once here and its
        result feeds both the header and the inline-function filter, so the two never disagree about
        which functions are imported"""
        matched = self.match_library_functions(functions)

        lines = self.gen_python_header(functions, matched=matched)

        for func in self.get_inline_functions(functions, matched=matched):
            lines.extend(self.format_function(func, comments))
            lines.extend(DEFINITION_SPACING)

        lines.extend(self.gen_python_footer())
        return '\n'.join(lines) + '\n'

    def gen_python_header(self, functions: list[Function] | None = None, *,
                          matched: dict[str, str] | None = None) -> list[str]:
        """Generate Python header lines for output script execution.

        functions, when given, are this script's disassembled functions in code order - used to
        emit the @scena.CommonImports() manifest (see match_library_functions). Leave it as None
        when there's no function list to give (e.g. a caller building just the header on its own);
        matched lets gen_python_script pass in an already-computed match set instead of this
        recomputing it.

        With a game, the first import is the game's helper, which installs the game's writer before
        the hook import can register on it, and the whole-library import (gen_library_import) follows
        the hook import, whatever
        the fidelity mode and whether or not there is a function list, so a human editing the script
        has every common function in scope for CALL()/autocomplete even when adding one this script
        never originally used.
        """
        helper_import = SCP_WRITER_HELPER_IMPORT if self.game is None else game_writer_helper_import(self.game)
        lines = [*SYS_PATH_SETUP_LINES, helper_import, *self.gen_hook_import().splitlines(), '']
        if self.game is not None:
            lines += [*self.gen_library_import().splitlines(), '']

        lines.append(f"scena = create_scp_writer('{self.name}')")
        lines.extend(DEFINITION_SPACING)

        if self.global_vars:
            indent = default_indent()
            lines.append('@scena.GlobalVars()')
            lines.append('def globalvars():')
            for var in self.global_vars:
                declaration = f'GLOBAL_VAR({quote_string(var.name)}, {var.type})'
                lines.append(indent + append_comment(declaration, [f'{GLOBAL_VAR_INDEX_COMMENT} {var.index}']))
            lines.extend(DEFINITION_SPACING)

        if functions is not None:
            lines.extend(self.gen_common_imports(functions, matched=matched))

        return lines

    def match_library_functions(self, functions: list[Function]) -> dict[str, str]:
        """This script's common functions whose body+signature exactly match the canonical variant in
        its game's library (falcom/ed9/games/<game>/metadata/common_index.py) - name -> library module key.

        Only meaningful in the everyday (non-fidelity) mode: a byte-exact recompile needs every
        function inline and every byte of it kept, so this always returns {} when self.round_trip
        or self.keep_unreachable_code is True - the library was generated with unreachable code
        dropped, so importing it under keep_unreachable_code=True would silently drop a script's
        own dead bytes even though that flag asked to keep them. A common function whose fingerprint
        diverges from the library (different body, signature, or subsystem) is left out here and
        stays inline as an ordinary @scena.LLILCommonCode() definition, same as a non-common one.

        Also returns {} without a game, and when the game's library isn't generated (fresh checkout,
        generator never run): the index is generated with the modules, so a missing index means no
        library to import from.
        """
        if self.game is None or self.round_trip or self.keep_unreachable_code:
            return {}

        index = common_library_index(self.game)
        matched = {}
        for func in functions:
            if not func.is_common_func:
                continue

            entry = index.get(func.name)
            if entry is None:
                continue

            module_key, digest = entry
            if fingerprint_digest(function_fingerprint(self, func)) == digest:
                matched[func.name] = module_key

        return matched

    def get_inline_functions(self, functions: list[Function], *,
                             matched: dict[str, str] | None = None) -> list[Function]:
        """functions this script must still define itself - everything not matched to the shared
        library. Returns functions unchanged when the library isn't active or nothing matched."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return functions

        return [func for func in functions if func.name not in matched]

    def gen_common_imports(self, functions: list[Function], *, matched: dict[str, str] | None = None) -> list[str]:
        """The @scena.CommonImports() manifest, in this script's own code order, for every function
        matched to the shared library. Empty when nothing matched - including strict round-trip
        mode, no game and an ungenerated library, all handled by match_library_functions returning {}.
        The whole-library import itself is gen_library_import, written whenever there is a game - it's
        pure name resolution for autocomplete/hand-editing, so it doesn't need to track fidelity
        mode or match state the way the manifest (what's actually compiled in) does."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return []

        indent = default_indent()
        lines = ['@scena.CommonImports()', 'def commonImports():', f'{indent}return [']
        for func in functions:
            if func.name in matched:
                lines.append(f'{indent * 2}{func.name},')
        lines.append(f'{indent}]')
        lines.extend(DEFINITION_SPACING)

        return lines

    def hook_module_name(self) -> str:
        """The optional hook module the generated script imports"""
        return f'{pathlib.Path(self.name).stem.strip()}_hook'

    def gen_hook_import(self) -> str:
        """The try/except block importing the optional <stem>_hook module - __import__ when the stem isn't a valid
        module path (e.g. mon5078+). Only a missing hook is ignored (for a dotted stem, also a missing parent package);
        a failed import inside the hook re-raises"""
        module = self.hook_module_name()
        parts = module.split('.')
        if all(is_module_name(part) for part in parts):
            statement = f'import {module}'
        else:
            statement = f'__import__({module!r})'

        if len(parts) == 1:
            check = f'e.name != {module!r}'
        else:
            prefixes = tuple('.'.join(parts[:end]) for end in range(1, len(parts) + 1))  # parents, then the hook
            check = f'e.name not in {prefixes!r}'

        return f"""\
try:
    {statement}
except ModuleNotFoundError as e:
    if {check}:
        raise"""

    def gen_library_import(self) -> str:
        """The try/except block star-importing the game's whole common-function library (common_all). Like the hook
        import, only a missing common_all is ignored (the library is not generated, so every common function is
        inline); a failed import inside the library re-raises"""
        module = game_metadata_module(self.game, COMMON_ALL_MODULE)
        return f"""\
try:
    from {module} import *
except ModuleNotFoundError as e:
    if e.name != {module!r}:
        raise"""

    def gen_hook_template(self) -> str:
        """A starting <stem>_hook.py: every callback is a no-op even when registered, so it compiles to the same bytes
        as no hook. Its TYPE_CHECKING block shows the script's names to Pylance; when no import can name the .py's
        stem, a rename hint instead"""
        stem = pathlib.Path(self.name).stem
        if is_module_name(stem) and not shadows_another_module(stem):
            type_checking = f"""\
    from {stem} import *  # pyright: ignore[reportAssignmentType]
    import {stem} as original"""
        else:
            reason = 'is also the name of another module' if is_module_name(stem) else "isn't a valid module name"
            suggested = suggested_module_name(stem)
            type_checking = f"""\
    # {stem!r} {reason}, so Pylance can't import the script's names. To get them, rename
    # {stem}.py to a valid name (it still compiles to {self.name}; keep this file's name) and uncomment:
    # from {suggested} import *  # pyright: ignore[reportAssignmentType]
    # import {suggested} as original
    pass"""

        return f"""\
# pyright: basic
from typing import TYPE_CHECKING
{SCP_WRITER_HELPER_IMPORT}
if TYPE_CHECKING:
{type_checking}


# Functions to add
def run_hook(g):
    for func in [
    ]:
        add_function(func)


# registerRunCallback(run_hook)

def func_hook(name, func):
    return None


# registerFuncCallback(func_hook)

def opcode_hook(opcode, *args):
    return None

# registerOpcodeCallback(opcode_hook)
"""

    def gen_python_footer(self) -> list[str]:
        """Generate Python footer lines for output script execution"""
        return """\
def main():
    scena.run(globals())


if __name__ == '__main__':
    main()""".splitlines()
