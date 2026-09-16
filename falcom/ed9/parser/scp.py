from re import S
from .types_scp import *
from .types_parser import *
from pprint import pprint
from ..disasm import *
from ..disasm.ed9_optable import *
import pathlib

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
    fs              : fileio.FileStream
    name            : str
    header          : ScpHeader
    functions       : list[Function]
    global_vars     : list[GlobalVar]
    function_map    : dict[str, Function]

    def __init__(self, fs: fileio.FileStream, name: str = ''):
        self.fs = fs
        self.name = name

    def get_func_by_name(self, name: str) -> Function:
        return self.function_map[name]

    def get_func_name_from_func_id(self, func_id: int) -> str:
        if func_id >= len(self.functions):
            raise ValueError(f'func_id out of range: {func_id} >= {len(self.functions)}')

        return self.functions[func_id].name

    def get_func_argc(self, func_id: int) -> int:
        if func_id >= len(self.functions):
            raise ValueError(f'func_id out of range: {func_id} >= {len(self.functions)}')

        return len(self.functions[func_id].params)

    def parse(self):
        self._read_header()

    def _read_header(self):
        fs = self.fs
        self.header = ScpHeader(fs = fs)

        func_entries        = self._read_function_entries(fs)
        self.functions      = self._read_functions(fs, func_entries)
        self.global_vars    = self._read_global_vars(fs)

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
                if dbg_info.arg_count == 0:
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

    def _read_global_vars(self, fs: fileio.FileStream) -> list[ScpGlobalVar]:
        hdr = self.header
        fs.Position = hdr.global_var_offset

        global_vars: list[GlobalVar] = []

        for i in range(hdr.global_var_count):
            gvar_info = ScpGlobalVar(fs = fs)
            var_name = ScpValue(fs = fs).value
            var_type = gvar_info.type

            global_var = GlobalVar(
                index = i,
                name = var_name,
                type = var_type,
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

        elif opcode == ED9Opcode.POPN:
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

            print(f'Disassembling {func.name} @ 0x{func.offset:08X}')

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
                print(f'Error disassembling {func.name} @ 0x{func.offset:08X}: {e}')
                raise

        return disassembled_functions

    def format_function(self, func: Function) -> list[str]:
        """Format a disassembled function"""
        formatter_context = FormatterContext(get_func_name_from_func_id = self.get_func_name_from_func_id)
        formatter = Formatter(formatter_context)
        return formatter.format_function(func)

    def gen_python_header(self) -> list[str]:
        """Generate Python header lines for output script execution"""
        return f'''\
from falcom.ed9.writer.scp_writer_helper import *
try:
    import {pathlib.Path(self.name).stem.strip()}_hook
except ModuleNotFoundError:
    pass
            
scena = create_scp_writer('{self.name}')
            
'''.splitlines()

    def gen_python_footer(self) -> list[str]:
        """Generate Python footer lines for output script execution"""
        return f'''\
def main():
    scena.run(globals())

if __name__ == '__main__':
    Try(main)          
        '''.splitlines()
