from re import S
from .types_scp import *
from .types_parser import *
from pprint import pprint
from ml import fileio
from ..disasm import *
from ..disasm.ed9_optable import *
from ..disasm.formatter import GLOBAL_VAR_INDEX_COMMENT
from ..writer.metadata import COMMON_LIBRARY_PACKAGE, SCP_WRITER_HELPER_IMPORT
from ..writer.metadata.common_index import COMMON_FUNCTIONS
from ..writer.metadata.signature import function_fingerprint, fingerprint_digest
from common.config import default_encoding
from common.logging import log
from ir.llil import WORD_SIZE
from typing import Any, Callable
import keyword
import pathlib
import struct

# Stack simulation instruction groups
PUSH_VARIANTS = (
    ED9Opcode.PUSH_RAW,
    ED9Opcode.PUSH_INT,
    ED9Opcode.PUSH_FLOAT,
    ED9Opcode.PUSH_STR,
    ED9Opcode.PUSH_STACK_OFFSET,
)

PUSH_VALUE_OPS = (
    ED9Opcode.GET_REG,
    ED9Opcode.LOAD_GLOBAL,
    ED9Opcode.LOAD_STACK,
    ED9Opcode.LOAD_STACK_DEREF,
)

POP_VALUE_OPS = (
    ED9Opcode.SET_REG,
    ED9Opcode.SET_GLOBAL,
    ED9Opcode.POP_TO,
    ED9Opcode.POP_TO_DEREF,
)

BINARY_OPS = (
    ED9Opcode.ADD,
    ED9Opcode.SUB,
    ED9Opcode.MUL,
    ED9Opcode.DIV,
    ED9Opcode.MOD,
    ED9Opcode.EQ,
    ED9Opcode.NE,
    ED9Opcode.GT,
    ED9Opcode.GE,
    ED9Opcode.LT,
    ED9Opcode.LE,
    ED9Opcode.BITWISE_AND,
    ED9Opcode.BITWISE_OR,
    ED9Opcode.LOGICAL_AND,
    ED9Opcode.LOGICAL_OR,
)

UNARY_OPS = (
    ED9Opcode.NEG,
    ED9Opcode.EZ,
    ED9Opcode.NOT,
)

CONDITIONAL_JUMPS = (
    ED9Opcode.POP_JMP_ZERO,
    ED9Opcode.POP_JMP_NOT_ZERO,
)

# Call-site debug-info rebuilding (shared by the parser, ScpWriter and tools/scp_roundtrip_validator.py)
PUSH_CONSTANT_OPS = (
    ED9Opcode.PUSH,
    ED9Opcode.PUSH_RAW,
    ED9Opcode.PUSH_INT,
    ED9Opcode.PUSH_FLOAT,
    ED9Opcode.PUSH_STR,
)

# LOAD_STACK_DEREF / LOAD_GLOBAL are unverified - no sample script passes them as call args
DEBUG_VARIABLE_OPS = (
    ED9Opcode.LOAD_STACK,
    ED9Opcode.PUSH_STACK_OFFSET,
    ED9Opcode.LOAD_STACK_DEREF,
    ED9Opcode.LOAD_GLOBAL,
)

SCRIPT_CALL_OPS = (
    ED9Opcode.CALL_SCRIPT,
    ED9Opcode.CALL_SCRIPT_NO_RETURN,
)

OPCODE_SIZE             = 1     # every opcode is one byte, followed by its operands
CALL_FRAME_SLOTS        = 2     # PUSH_CURRENT_FUNC_ID + PUSH_RET_ADDR, popped by CALL
CALLER_FRAME_SLOTS      = 1     # PUSH_CALLER_FRAME is simulated as one slot, popped by CALL_SCRIPT
BINARY_OPERAND_COUNT    = 2
UNARY_OPERAND_COUNT     = 1
POPPED_VALUE_COUNT      = 1     # POP_VALUE_OPS / CONDITIONAL_JUMPS


@dataclass
class TrackedValue:
    """Simulated eval-stack slot"""
    type        : ScpFunctionCallDebugInfoArg.Type
    payload     : Any = None                # caller data for constants
    call_key    : tuple | None = None       # key of the earliest call nested in this value


@dataclass
class TrackedCall:
    """Call site, ordered like its debug-info record"""
    call_type   : ScpFunctionCallDebugInfo.CallType
    target      : Any                       # CALL operand, (module, func) or (subsystem, cmd)
    ret_label   : Any                       # PUSH_RET_ADDR operand of a local CALL
    args        : list[TrackedValue]        # top of stack first (parameter order)
    key         : tuple


class CallDebugInfoTracker:
    """Rebuilds call-site debug-info records from opcodes fed in address order.

    Records are in source pre-order: an outer call's record comes before calls nested in its args,
    so each call is keyed by where it starts (its frame push) rather than by its CALL instruction.
    """

    def __init__(self, get_param_count: Callable[[Any], int]):
        self.get_param_count    = get_param_count
        self.stack              : list[TrackedValue | None] = []    # None is a call frame slot
        self.frames             : list[list] = []                   # [key, ret_label] of calls not made yet
        self.calls              : list[TrackedCall] = []
        self.counter            = 0
        self.last_call_key      = None
        self.has_line_info      = False

    def on_opcode(self, opcode: int, operands: list | tuple, payload: Any = None):
        ArgType = ScpFunctionCallDebugInfoArg.Type
        CallType = ScpFunctionCallDebugInfo.CallType

        if opcode == ED9Opcode.DEBUG_SET_LINENO:
            self.has_line_info = True

        elif opcode in PUSH_CONSTANT_OPS:
            self.stack.append(TrackedValue(ArgType.Constant, payload = payload))

        elif opcode in (ED9Opcode.PUSH_CURRENT_FUNC_ID, ED9Opcode.PUSH_CALLER_FRAME):
            self.frames.append([self.next_key(), None])
            self.stack.append(None)

        elif opcode == ED9Opcode.PUSH_RET_ADDR:
            if self.frames:
                self.frames[-1][1] = operands[0]

            self.stack.append(None)

        elif opcode == ED9Opcode.GET_REG:
            self.stack.append(TrackedValue(ArgType.CallResult, call_key = self.last_call_key))

        elif opcode in DEBUG_VARIABLE_OPS:
            self.stack.append(TrackedValue(ArgType.Variable))

        elif opcode in BINARY_OPS:
            self.push_expression(self.pop(BINARY_OPERAND_COUNT))

        elif opcode in UNARY_OPS:
            self.push_expression(self.pop(UNARY_OPERAND_COUNT))

        elif opcode in POP_VALUE_OPS or opcode in CONDITIONAL_JUMPS:
            self.pop(POPPED_VALUE_COUNT)

        elif opcode == ED9Opcode.POP:
            self.pop(operands[0] // WORD_SIZE)

        elif opcode == ED9Opcode.DEBUG_LOG:
            self.pop(operands[0])

        elif opcode == ED9Opcode.CALL:
            args = self.pop(self.get_param_count(operands[0]))
            self.pop(CALL_FRAME_SLOTS)
            key, ret_label = self.close_frame()
            self.add_call(CallType.Local, operands[0], ret_label, args, key)

        elif opcode == ED9Opcode.CALL_SCRIPT:
            module, func, argc = operands
            args = self.pop(argc)
            self.pop(CALLER_FRAME_SLOTS)
            key, _ = self.close_frame()
            self.add_call(CallType.Script, (module, func), None, args, key)

        elif opcode == ED9Opcode.CALL_SCRIPT_NO_RETURN:
            # No PUSH_CALLER_FRAME precedes this opcode - only the arguments were pushed. Popping
            # CALLER_FRAME_SLOTS or closing a frame here would consume state belonging to an
            # enclosing call and corrupt its debug-record ordering. Its own key must still sort
            # before any call nested in its arguments (source pre-order) - same reasoning as SYSCALL.
            module, func, argc = operands
            args = self.pop(argc)
            nested_keys = [arg.call_key for arg in args if arg.call_key is not None]
            key = self.key_before(min(nested_keys)) if nested_keys else self.next_key()
            self.add_call(CallType.ScriptNoReturn, (module, func), None, args, key)

        elif opcode == ED9Opcode.SYSCALL:
            # Args stay on the stack - the following POP removes them
            subsystem, cmd, argc = operands
            args = self.peek(argc)
            nested_keys = [arg.call_key for arg in args if arg.call_key is not None]
            key = self.key_before(min(nested_keys)) if nested_keys else self.next_key()
            self.add_call(CallType.Syscall, (subsystem, cmd), None, args, key)

    def ordered_calls(self) -> list[TrackedCall]:
        """Calls in debug-info record order"""
        return sorted(self.calls, key = lambda call: call.key)

    def next_key(self) -> tuple:
        key = (self.counter, 0)
        self.counter += 1
        return key

    @classmethod
    def key_before(cls, key: tuple) -> tuple:
        """Sorts right before key and every call nested inside it"""
        return (key[0], key[1] - 1)

    def close_frame(self) -> tuple:
        if self.frames:
            key, ret_label = self.frames.pop()
            return key, ret_label

        return self.next_key(), None

    def push_expression(self, operands: list[TrackedValue]):
        keys = [value.call_key for value in operands if value.call_key is not None]
        self.stack.append(TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression, call_key = min(keys) if keys else None))

    def peek(self, count: int) -> list[TrackedValue]:
        """Top count slots, top first; frame slots and underflow (from branches) become Expression placeholders"""
        top = self.stack[max(0, len(self.stack) - count):] if count else []
        values = [value or TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression) for value in reversed(top)]
        return values + [TrackedValue(ScpFunctionCallDebugInfoArg.Type.Expression) for _ in range(count - len(values))]

    def pop(self, count: int) -> list[TrackedValue]:
        values = self.peek(count)
        del self.stack[max(0, len(self.stack) - count):]
        return values

    def add_call(self, call_type: ScpFunctionCallDebugInfo.CallType, target: Any, ret_label: Any, args: list[TrackedValue], key: tuple):
        self.last_call_key = key

        # No record for calls compiled without line info (common functions, calls before the first DEBUG_SET_LINENO)
        if self.has_line_info:
            self.calls.append(TrackedCall(call_type, target, ret_label, args, key))


@dataclass
class ScpDisassemblerContext(DisassemblerContext):
    """ED9/SCP-specific disassembler context with optimization state"""
    current_func     : 'Function | None' = None  # Current function being disassembled
    stack_simulation : list = None  # Stack simulation for current block
    saved_stacks     : dict[int, list] = None  # offset -> stack snapshot for branches

    def __post_init__(self):
        if self.stack_simulation is None:
            self.stack_simulation = []
        if self.saved_stacks is None:
            self.saved_stacks = {}

    def save_stack_for_offset(self, offset: int):
        """Save current stack state for given offset"""
        self.saved_stacks[offset] = self.stack_simulation.copy()

    def restore_stack_for_offset(self, offset: int):
        """Restore stack state for given offset, if saved"""
        if offset in self.saved_stacks:
            self.stack_simulation = self.saved_stacks[offset].copy()


class ScpParser(StrictBase):
    # Keep data only needed for a byte-exact round trip: zero-arg debug records and the explicit
    # arg count of each local CALL (debug_argc). Source function order is always kept - it's a free
    # reordering of already-parsed data, not extra fidelity data, so it isn't gated by this flag.
    round_trip      : bool = True

    # Decode code no branch reaches (e.g. a JMP right after RETURN) so the .py keeps it for a byte-exact round trip
    keep_unreachable_code : bool = True

    fs              : fileio.FileStream
    name            : str
    header          : ScpHeader
    function_entries: list[ScpFunctionEntry]
    functions       : list[Function]
    global_vars     : list[GlobalVar]
    function_map    : dict[str, Function]

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
        filter_func: Callable[[Function], bool] | None = None,
    ) -> tuple['ScpParser', list[Function]]:
        """Open path, parse, and disassemble every function - the setup every caller (scena2py.py,
        the common-function generator, the round-trip validator, tests) otherwise repeats by hand.
        The file handle is closed before returning; the parser stays fully usable afterward
        (get_instructions, get_func_name_from_func_id, etc. are all in-memory)."""
        with fileio.FileStream(str(path), encoding = default_encoding()) as fs:
            parser = cls(fs, path.name)
            parser.round_trip = round_trip
            parser.keep_unreachable_code = keep_unreachable_code
            parser.parse()
            functions = parser.disasm_all_functions(filter_func = filter_func)

        return parser, functions

    def get_func_by_name(self, name: str) -> Function:
        return self.function_map[name]

    def get_func_name_from_func_id(self, func_id: int) -> str:
        if func_id >= len(self.functions):
            raise ValueError(f'func_id out of range: {func_id} >= {len(self.functions)}')

        return self.functions[func_id].name

    def get_global_name_from_index(self, index: int) -> str | None:
        if 0 <= index < len(self.global_vars):
            return self.global_vars[index].name

        return None

    def get_func_argc(self, func_id: int) -> int:
        if func_id >= len(self.functions):
            raise ValueError(f'func_id out of range: {func_id} >= {len(self.functions)}')

        return len(self.functions[func_id].params)

    def parse(self):
        self._read_header()

    def _read_header(self):
        fs = self.fs
        self.header = ScpHeader(fs = fs)

        self.function_entries   = self._read_function_entries(fs)
        self.functions          = self._read_functions(fs, self.function_entries)
        self.global_vars        = self._read_global_vars(fs)

        self.function_map = {func.name: func for func in self.functions}

    def _read_function_entries(self, fs: fileio.FileStream):
        return [ScpFunctionEntry(fs = fs) for _ in range(self.header.function_count)]

    def _read_functions(self, fs: fileio.FileStream, func_entries: list[ScpFunctionEntry]) -> list[Function]:
        functions: list[Function] = []

        # load function

        for i, entry in enumerate(func_entries):
            func = Function()

            func.is_common_func = entry.is_common_func == 1
            func.offset = entry.offset

            func_name = ScpValue().from_value(entry.name_offset, fs = fs)
            func.name = func_name.value

            fs.Position = entry.param_flags_offset
            param_flags = [ScpParamFlags(fs = fs) for _ in range(entry.param_count)]

            fs.Position = entry.default_params_offset
            default_params = [ScpValue(fs = fs) for _ in range(entry.default_params_count)]
            if len(default_params) > len(param_flags):
                raise ValueError(f'default_params count is greater than param_flags count: {len(default_params)} > {len(param_flags)}')

            while len(default_params) < len(param_flags):
                default_params.insert(0, None)

            for i in range(entry.param_count):
                param = FunctionParam(type = param_flags[i], default_value = default_params[i])
                func.params.append(param)

            # func.params.reverse()

            functions.append(func)

        # init debug info

        for i, func in enumerate(functions):
            entry = func_entries[i]
            fs.Position = entry.debug_info_offset
            debug_info_list = self.read_debug_info(fs, entry)

            for dbg_info in debug_info_list:
                # round_trip keeps zero-arg records so records line up 1:1 with call sites
                if dbg_info.arg_count == 0 and not self.round_trip:
                    continue

                info = FunctionCallDebugInfo()
                info.call_type = dbg_info.call_type

                if dbg_info.func_id != 0xFFFFFFFF:
                    if dbg_info.func_id >= len(functions):
                        raise ValueError(f'debug info func_id out of range: {dbg_info.func_id} >= {len(functions)}')

                    info.func_name = functions[dbg_info.func_id].name

                else:
                    info.func_name = f'{dbg_info.call_type}'

                fs.Position = dbg_info.info_offset
                for _ in range(dbg_info.arg_count):
                    arg_value = ScpValue(fs = fs)
                    arg_type = fs.ReadULong()

                    info.args.append(FunctionCallDebugInfo.ArgInfo(arg_type, arg_value))

                func.debug_info.append(info)

        return functions

    def read_debug_info(self, fs: fileio.FileStream, func_entry: ScpFunctionEntry) -> list[ScpFunctionCallDebugInfo]:
        debug_info_list = []

        if func_entry.debug_info_count == 0:
            return debug_info_list

        fs.Position = func_entry.debug_info_offset
        for _ in range(func_entry.debug_info_count):
            dbg_info = ScpFunctionCallDebugInfo(fs = fs)
            debug_info_list.append(dbg_info)

        return debug_info_list

    def _read_global_vars(self, fs: fileio.FileStream) -> list[GlobalVar]:
        hdr = self.header
        fs.Position = hdr.global_var_offset

        global_vars: list[GlobalVar] = []

        for i in range(hdr.global_var_count):
            gvar_info = ScpGlobalVar(fs = fs)

            global_var = GlobalVar(
                index = i,
                name = gvar_info.name,
                type = gvar_info.type,
            )

            global_vars.append(global_var)

        return global_vars


    # disassemble

    def on_disasm_function(self, context: ScpDisassemblerContext, offset: int, name: str):
        """Initialize stack simulation with function parameters"""
        # Get function object and parameter count
        func = next((f for f in self.functions if f.offset == offset or f.name == name), None)
        argc = len(func.params) if func else 0

        # Store current function in context
        context.current_func = func

        # Clear stack and push parameters
        context.stack_simulation.clear()
        context.saved_stacks.clear()

        # Create simple placeholder objects for parameters
        class ParamPlaceholder:
            def __init__(self, idx: int, offset: int):
                self.offset = offset
                self.mnemonic = f'param_{idx}'

        for i in range(argc):
            param_inst = ParamPlaceholder(i, offset - (argc - i))
            context.stack_simulation.append(param_inst)

    def on_block_start(self, context: ScpDisassemblerContext, offset: int):
        """Restore stack state for this block"""
        context.restore_stack_for_offset(offset)

    def on_pre_add_branch(self, context: ScpDisassemblerContext, target: BranchTarget):
        """Called before adding a branch - save stack state for branch target"""
        context.save_stack_for_offset(target.offset)

    def on_instruction_decoded(self, context: ScpDisassemblerContext, inst: Instruction, block: BasicBlock) -> list[BranchTarget]:
        """Called for every instruction during disassembly"""

        if not True:
            if inst.opcode == ED9Opcode.DEBUG_SET_LINENO:
                print(f'[0x{inst.offset:08X}] Decoded: {inst.mnemonic}({inst.operands[0].value}) (opcode=0x{inst.opcode:02X})')
            else:
                print(f'[0x{inst.offset:08X}] Decoded: {inst.mnemonic:<20} (opcode=0x{inst.opcode:02X})')

        # Simulate stack operations
        stack = context.stack_simulation
        opcode = inst.opcode

        if opcode == ED9Opcode.RETURN:
            if stack:
                raise ValueError(f'Stack is not empty at return: {stack}')

        # PUSH operations - add to stack
        if opcode in PUSH_VARIANTS:
            stack.append(inst)

        # GET_REG, LOAD_GLOBAL, LOAD_STACK, etc - push value
        elif opcode in PUSH_VALUE_OPS:
            stack.append(inst)

        # POP operations - remove from stack
        elif opcode == ED9Opcode.POP:
            count = inst.operands[0].value if inst.operands else 1
            count //= 4
            for _ in range(count):
                stack.pop()

        elif opcode == ED9Opcode.DEBUG_LOG:
            count = inst.operands[0].value if inst.operands else 0
            for _ in range(count):
                stack.pop()

        # SET_REG, SET_GLOBAL, POP_TO, etc - pop value
        elif opcode in POP_VALUE_OPS:
            stack.pop()

        # Binary operations - pop 2, push 1
        elif opcode in BINARY_OPS:
            stack.pop()
            stack.pop()
            stack.append(inst)  # Result of operation

        # Unary operations - pop 1, push 1
        elif opcode in UNARY_OPS:
            stack.pop()
            stack.append(inst)  # Result of operation

        # Conditional jumps - pop 1
        elif opcode in CONDITIONAL_JUMPS:
            stack.pop()

        # Optimize CALL pattern
        if opcode == ED9Opcode.CALL:
            if len(stack) < 2:
                return []

            func_id = inst.operands[0].value
            argc = context.get_func_argc(func_id)

            # Pattern: PUSH(func_id), PUSH(ret_addr), PUSH(arg1), ..., PUSH(argN), CALL
            # Stack (top to bottom): argN, ..., arg1, ret_addr, func_id
            if len(stack) < argc + 2:
                return []

            targets = []

            # Pop argc arguments from stack simulation to get ret_addr and func_id
            ret_addr_inst = stack[-(argc + 1)]
            func_id_inst = stack[-(argc + 2)]

            for _ in range(argc + 2):
                stack.pop()

            # Check if these are PUSH instructions (not results of operations)
            if not isinstance(ret_addr_inst, Instruction) or not isinstance(func_id_inst, Instruction):
                return []

            # Optimize func_id PUSH to PUSH_CURRENT_FUNC_ID
            if func_id_inst.opcode in PUSH_VARIANTS:
                func_id_inst.opcode = ED9Opcode.PUSH_CURRENT_FUNC_ID
                func_id_inst.descriptor = context.instruction_table.get_descriptor(ED9Opcode.PUSH_CURRENT_FUNC_ID)
                func_id_inst.operands.clear()

            # Optimize ret_addr PUSH to PUSH_RET_ADDR
            if ret_addr_inst.opcode in PUSH_VARIANTS:
                ret_addr = ret_addr_inst.operands[0].value
                ret_addr_inst.opcode = ED9Opcode.PUSH_RET_ADDR
                ret_addr_inst.descriptor = context.instruction_table.get_descriptor(ED9Opcode.PUSH_RET_ADDR)
                # Change operand to OFFSET from instruction descriptor
                op_desc = OperandDescriptor.from_format_string(ret_addr_inst.descriptor.operand_fmt, ED9_FORMAT_TABLE)[0]
                ret_addr_inst.operands = [Operand(descriptor = op_desc, value = ret_addr)]
                # Create branch target for return address
                targets.append(BranchTarget.unconditional(int(ret_addr)))

            return targets

        return []

    def disasm_all_functions(self, filter_func = None) -> list[Function]:
        """Disassemble all functions in the SCP file"""
        disassembled_functions = []

        for func in self.functions:
            # Apply filter if provided
            if filter_func and not filter_func(func):
                continue

            log.info(f'Disassembling {func.name} @ 0x{func.offset:08X}')

            # Create new context for each function
            context = ScpDisassemblerContext(
                get_func_argc           = self.get_func_argc,
                on_disasm_function      = self.on_disasm_function,
                on_block_start          = self.on_block_start,
                on_instruction_decoded  = self.on_instruction_decoded,
                on_pre_add_branch       = self.on_pre_add_branch,
                create_fallthrough_jump = ed9_create_fallthrough_jump,
            )

            disasm = Disassembler(ED9_INSTRUCTION_TABLE, context)
            try:
                func.entry_block = disasm.disasm_function(self.fs, offset = func.offset, name = func.name)
                disassembled_functions.append(func)
            except Exception as e:
                log.error(f'Error disassembling {func.name} @ 0x{func.offset:08X}: {e}')
                raise

            if self.round_trip:
                self.pair_call_debug_info(func)

        if self.keep_unreachable_code:
            self.find_unreachable_code(disassembled_functions, has_all_functions = filter_func is None)

        # The table is sorted by name, but code is laid out in source order
        disassembled_functions.sort(key = lambda func: func.offset)

        return disassembled_functions

    def get_instructions(self, func: Function) -> list[Instruction]:
        """Reachable instructions of a disassembled function in offset order"""
        return Formatter.reachable_instructions(func.entry_block)

    def pair_call_debug_info(self, func: Function):
        """Recover each local CALL's explicit arg count - its debug record drops trailing default args"""
        tracker = CallDebugInfoTracker(get_param_count = self.get_func_argc)
        for inst in self.get_instructions(func):
            tracker.on_opcode(inst.opcode, [operand.value for operand in inst.operands])

        calls = tracker.ordered_calls()
        if len(calls) != len(func.debug_info):
            log.warning(f'{func.name}: {len(calls)} call sites but {len(func.debug_info)} debug records, debug_argc not recovered')
            return

        for call, info in zip(calls, func.debug_info):
            if call.call_type != ScpFunctionCallDebugInfo.CallType.Local or call.ret_label is None:
                continue

            if len(info.args) != len(call.args):
                func.call_debug_argc[f'loc_{call.ret_label:X}'] = len(info.args)

    def find_unreachable_code(self, functions: list[Function], has_all_functions: bool):
        """Linearly decode the bytes no branch reaches (between reachable instructions and up to the next function) into func.unreachable_blocks"""
        if not functions:
            return

        starts = sorted(func.offset for func in self.functions)
        next_starts = dict(zip(starts, starts[1:]))
        code_end = self.get_code_end(functions)

        # Code order, so strings used by earlier unreachable code can lower code_end before the last function's tail
        for func in sorted(functions, key = lambda f: f.offset):
            instructions = self.get_instructions(func)
            blocks = []
            cursor = func.offset

            for inst in instructions:
                if inst.offset > cursor:
                    blocks.append(self._decode_unreachable_block(func, cursor, inst.offset))

                cursor = max(cursor, inst.offset + inst.size)

            blocks = [block for block in blocks if block is not None]
            code_end = min([code_end, *self.get_string_refs([inst for block in blocks for inst in block.instructions])])

            # The last function in code order runs up to the string pool, only known when every function's strings were seen
            end = next_starts.get(func.offset, code_end if has_all_functions else None)
            if end is not None and cursor < end:
                tail = self._decode_unreachable_block(func, cursor, end)
                if tail is not None:
                    blocks.append(tail)
                    code_end = min([code_end, *self.get_string_refs(tail.instructions)])

            func.unreachable_blocks = self._prune_unreachable_blocks(func, instructions, blocks)

    def get_code_end(self, functions: list[Function]) -> int:
        """Where the string pool starts - it holds the code strings first, then the function names"""
        names = [self.get_string_offset(entry.name_offset) for entry in self.function_entries]
        code_strings = self.get_string_refs([inst for func in functions for inst in self.get_instructions(func)])
        return min([offset for offset in names if offset is not None] + code_strings)

    def get_string_refs(self, instructions: list[Instruction]) -> list[int]:
        """String pool offsets referenced by PUSH_STR and CALL_SCRIPT operands"""
        positions = []
        for inst in instructions:
            if inst.opcode == ED9Opcode.PUSH_STR:
                positions.append(inst.offset + inst.size - WORD_SIZE)  # PUSH ends with its ScpValue

            elif inst.opcode in SCRIPT_CALL_OPS:
                positions.append(inst.offset + OPCODE_SIZE)             # module
                positions.append(inst.offset + OPCODE_SIZE + WORD_SIZE) # func

        refs = []
        with self.fs.PositionSaver:
            for position in positions:
                self.fs.Position = position
                offset = self.get_string_offset(self.fs.ReadULong())
                if offset is not None:
                    refs.append(offset)

        return refs

    @classmethod
    def get_string_offset(cls, raw_value: int) -> int | None:
        """String pool offset of a raw ScpValue, None when it isn't a String"""
        if raw_value >> ScpValue.TYPE_SHIFT != ScpValue.Type.String:
            return None

        return raw_value & ScpValue.PAYLOAD_MASK

    def _decode_unreachable_block(self, func: Function, start: int, end: int) -> BasicBlock | None:
        """Linearly decode [start, end), or None (with a warning) when the bytes aren't whole instructions"""
        block = BasicBlock(start_offset = start, end_offset = end)
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
    def _prune_unreachable_blocks(cls, func: Function, instructions: list[Instruction], blocks: list[BasicBlock]) -> list[BasicBlock]:
        """Drop unreachable blocks that branch to an offset with no kept instruction - their label would never be emitted"""
        reachable_offsets = {inst.offset for inst in instructions}

        while True:
            offsets = reachable_offsets | {inst.offset for block in blocks for inst in block.instructions}
            dropped_ids = {id(block) for block in blocks if any(target not in offsets for target in Formatter.branch_targets(block))}
            if not dropped_ids:
                return blocks

            for block in blocks:
                if id(block) in dropped_ids:
                    log.warning(f'{func.name}: unreachable code at 0x{block.offset:X} not kept, it branches to an offset with no instruction')

            blocks = [block for block in blocks if id(block) not in dropped_ids]

    def format_function(self, func: Function) -> list[str]:
        """Format a disassembled function"""
        formatter_context = FormatterContext(
            get_func_name_from_func_id  = self.get_func_name_from_func_id,
            get_global_name_from_index  = self.get_global_name_from_index,
        )
        formatter = Formatter(formatter_context)
        return formatter.format_function(func)

    def gen_python_script(self, functions: list[Function], *, preamble: list[str] = ()) -> str:
        """Full generated .py text: header (incl. shared-library imports/manifest), an optional
        preamble (e.g. scena2py.py's common-functions-omitted warning), every function this script
        must still define itself, then the footer. match_library_functions runs exactly once here
        and its result is threaded through the header and the inline-function filter, so the two
        can never disagree about which functions got imported - see write_python_dsl/
        decompile_to_python, which used to compute it separately in each half."""
        matched = self.match_library_functions(functions)

        lines = self.gen_python_header(functions, matched = matched)
        lines.extend(preamble)

        for func in self.get_inline_functions(functions, matched = matched):
            lines.extend(self.format_function(func))
            lines.append('')

        lines.extend(self.gen_python_footer())
        return '\n'.join(lines) + '\n'

    def gen_python_header(self, functions: list[Function] | None = None, *, matched: dict[str, str] | None = None) -> list[str]:
        """Generate Python header lines for output script execution.

        functions, when given, are this script's disassembled functions in code order - used to
        emit the shared-library imports and @scena.CommonImports() manifest (see
        match_library_functions). Leave it as None when there's no function list to give (e.g. a
        caller building just the header on its own); matched lets gen_python_script pass in an
        already-computed match set instead of this recomputing it.
        """
        lines = f'''\
{SCP_WRITER_HELPER_IMPORT}
try:
    {self.gen_hook_import()}
except ModuleNotFoundError:
    pass

scena = create_scp_writer('{self.name}')

'''.splitlines()

        if self.global_vars:
            indent = default_indent()
            lines.append('@scena.GlobalVars()')
            lines.append('def globalvars():')
            for var in self.global_vars:
                lines.append(f'{indent}GLOBAL_VAR({quote_string(var.name)}, {var.type}){GLOBAL_VAR_INDEX_COMMENT} {var.index}')
            lines.append('')

        if functions is not None:
            lines.extend(self.gen_common_imports(functions, matched = matched))

        return lines

    def match_library_functions(self, functions: list[Function]) -> dict[str, str]:
        """This script's common functions whose body+signature exactly match the shared library's
        canonical variant (falcom/ed9/writer/metadata/common_index.py) - name -> library module key.

        Only meaningful in the everyday (non-fidelity) mode: a byte-exact recompile needs every
        function inline and every byte of it kept, so this always returns {} when self.round_trip
        or self.keep_unreachable_code is True - the library was generated with unreachable code
        dropped, so importing it under keep_unreachable_code=True would silently drop a script's
        own dead bytes even though that flag asked to keep them. A common function whose fingerprint
        diverges from the library (different body, signature, or subsystem) is left out here and
        stays inline as an ordinary @scena.LLILCommonCode() definition, same as a non-common one.
        """
        if self.round_trip or self.keep_unreachable_code:
            return {}

        matched = {}
        for func in functions:
            if not func.is_common_func:
                continue

            entry = COMMON_FUNCTIONS.get(func.name)
            if entry is None:
                continue

            module_key, digest = entry
            if fingerprint_digest(function_fingerprint(self, func)) == digest:
                matched[func.name] = module_key

        return matched

    def get_inline_functions(self, functions: list[Function], *, matched: dict[str, str] | None = None) -> list[Function]:
        """functions this script must still define itself - everything not matched to the shared
        library. Returns functions unchanged when the library isn't active or nothing matched."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return functions

        return [func for func in functions if func.name not in matched]

    def gen_common_imports(self, functions: list[Function], *, matched: dict[str, str] | None = None) -> list[str]:
        """Per-module imports plus the @scena.CommonImports() manifest, in this script's own code
        order, for every function matched to the shared library. Empty when nothing matched."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return []

        names_by_module: dict[str, list[str]] = {}
        for name, module_key in matched.items():
            names_by_module.setdefault(module_key, []).append(name)

        indent = default_indent()
        lines = []
        for module_key in sorted(names_by_module):
            names = ', '.join(sorted(names_by_module[module_key]))
            lines.append(f'from {COMMON_LIBRARY_PACKAGE}.{module_key} import {names}')

        lines.append('')
        lines.append('@scena.CommonImports()')
        lines.append('def commonImports():')
        lines.append(f'{indent}return [')
        for func in functions:
            if func.name in matched:
                lines.append(f'{indent * 2}{func.name},')
        lines.append(f'{indent}]')
        lines.append('')

        return lines

    def gen_hook_import(self) -> str:
        """Import of the optional <stem>_hook module - __import__ when the stem isn't a valid module path (e.g. mon5078+)"""
        module = f'{pathlib.Path(self.name).stem.strip()}_hook'
        if all(part.isidentifier() and not keyword.iskeyword(part) for part in module.split('.')):
            return f'import {module}'

        return f'__import__({module!r})'

    def gen_python_footer(self) -> list[str]:
        """Generate Python footer lines for output script execution"""
        return f'''\
def main():
    scena.run(globals())

if __name__ == '__main__':
    Try(main)          
        '''.splitlines()
