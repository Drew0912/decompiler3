from typing import Callable
import bisect
import pathlib
import struct

from ..structs.scp_types import *
from .parser_types import GlobalVar
from dc3 import fileio, StrictBase
from assembler import BasicBlock, Disassembler, Instruction
from ..assembler import *
from ..assembler.ed9_optable import *
from ..assembler.disassembler import (ScpDisassemblerContext, ScpDisassemblyError, on_block_split, on_block_start,
                                      on_disasm_function, on_instruction_decoded, on_pre_add_branch)
from ..assembler.function import Function, FunctionParam
from ..structs.call_debug_records import PUSH_CONSTANT_OPS, canonical_argc, pair_records
from ..structs.string_pool import string_offset
from dc3.logging import log


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
