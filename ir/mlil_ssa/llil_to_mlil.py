"""LLIL to MLIL Translator - Stack elimination (core operations only)"""

from ir.llil import *
from ir.mlil.llil_ops import BINARY_OP_TYPES, UNARY_OP_TYPES
from ir.mlil.mlil import *
from .mlil_ssa_function import MediumLevelILFunctionSSA, MLILBuilderSSA


class LLILToMLILTranslator:
    """LLIL to MLIL translator (base class)"""

    RESULT_REGISTER: int | None = None      # the VM's result register, if a return's value travels in one
    FUNCTION_CLASS: type[MediumLevelILFunctionSSA] = MediumLevelILFunctionSSA   # a VM's subclass gives its rules

    def __init__(self):
        self.builder = MLILBuilderSSA(self.FUNCTION_CLASS)
        self.llil_func: LowLevelILFunction | None = None
        self.block_map: dict[LowLevelILBasicBlock, MediumLevelILBasicBlock] = {}

    def translate(self, llil_func: LowLevelILFunction) -> MediumLevelILFunctionSSA:
        """Translate LLIL function to MLIL"""
        self.llil_func = llil_func
        self.builder.create_function(llil_func.name, llil_func.start_addr, llil_func.params)
        self.builder.function.llil_function = llil_func
        self.builder.function.result_register = self.RESULT_REGISTER

        for llil_block in llil_func.basic_blocks:
            self.block_map[llil_block] = self.builder.create_block(llil_block.start, llil_block.label)

        for llil_block in llil_func.basic_blocks:
            mlil_block = self.block_map[llil_block]
            self.builder.set_current_block(mlil_block)
            self._translate_block(llil_block)

        return self.builder.finalize()

    def _translate_block(self, llil_block: LowLevelILBasicBlock):
        """Translate a single LLIL block to MLIL"""
        for llil_inst in llil_block.instructions:
            self.builder.set_current_source(llil_inst.address, llil_inst.inst_index)
            self._translate_instruction(llil_inst)

    def _translate_instruction(self, llil_inst: LowLevelILInstruction):
        """Translate LLIL instruction to MLIL"""
        # Stack operations
        if isinstance(llil_inst, LowLevelILStackStore):
            self._translate_stack_store(llil_inst)

        # Frame operations
        elif isinstance(llil_inst, LowLevelILFrameStore):
            self._translate_frame_store(llil_inst)

        # Pointer dereference
        elif isinstance(llil_inst, LowLevelILStore):
            self._translate_store(llil_inst)

        # Registers: each a variable
        elif isinstance(llil_inst, LowLevelILRegStore):
            value = self._translate_expr(llil_inst.value)
            self.builder.set_var(self.builder.get_or_create_register_var(llil_inst.reg_index), value)

        # Control flow
        elif isinstance(llil_inst, LowLevelILJmp):
            target = self.block_map[llil_inst.target]
            self.builder.goto(target)
        elif isinstance(llil_inst, LowLevelILIf):
            condition = self._translate_expr(llil_inst.condition)
            true_target = self.block_map[llil_inst.true_target]
            false_target = self.block_map[llil_inst.false_target]
            self.builder.branch_if(condition, true_target, false_target)
        elif isinstance(llil_inst, LowLevelILRet):
            self.builder.ret(self._result_read())
        elif isinstance(llil_inst, LowLevelILCall):
            self._translate_call(llil_inst)
        elif isinstance(llil_inst, LowLevelILSyscall):
            args = [self._translate_expr(arg) for arg in llil_inst.args]
            self.builder.syscall(llil_inst.subsystem, llil_inst.cmd, args, self._result_var())

        # SpAdd - eliminated in MLIL (stack pointer management removed)
        elif isinstance(llil_inst, LowLevelILSpAdd):
            pass

        # Debug
        elif isinstance(llil_inst, LowLevelILDebug):
            self.builder.debug(llil_inst.debug_type, llil_inst.value)
        else:
            # Unknown instruction - must be handled by derived class
            raise NotImplementedError(
                f'Unhandled LLIL instruction type: {type(llil_inst).__name__}. '
                f'This may be an architecture-specific instruction that should be '
                f'handled in a derived translator class.'
            )

    def _stack_var(self, slot_index: int) -> MLILVariable:
        """The local variable of a stack slot"""
        return self.builder.get_or_create_local(mlil_stack_var_name(slot_index), slot_index)

    def _param_var(self, frame_slot: int) -> MLILVariable:
        """The parameter variable of a frame slot"""
        param_index = self.parameter_position(frame_slot)
        return self.builder.get_or_create_parameter(param_index, mlil_arg_var_name(param_index))

    def _translate_stack_store(self, llil_inst: LowLevelILStackStore):
        """Translate StackStore to SetVar (local variable)"""
        var = self._stack_var(llil_inst.slot_index)
        value = self._translate_expr(llil_inst.value)
        self.builder.set_var(var, value)

    def parameter_position(self, frame_slot: int) -> int:
        """The 1-based parameter in frame slot frame_slot: the VM's calling convention"""
        raise NotImplementedError(f'{type(self).__name__} gives no calling convention')

    def _translate_frame_store(self, llil_inst: LowLevelILFrameStore):
        """Translate FrameStore to SetVar (parameter)"""
        var = self._param_var(llil_inst.slot_offset)
        value = self._translate_expr(llil_inst.value)
        self.builder.set_var(var, value)

    def _translate_store(self, llil_inst: LowLevelILStore):
        """Translate Store to StoreDeref (*ptr = value)"""
        dest = self._translate_expr(llil_inst.dest)
        value = self._translate_expr(llil_inst.value)
        self.builder.store_deref(dest, value)

    def _result_var(self) -> MLILVariable | None:
        """The result register's variable, where a call leaves its result: None on a VM without one"""
        if self.RESULT_REGISTER is None:
            return None

        return self.builder.get_or_create_register_var(self.RESULT_REGISTER)

    def _result_read(self) -> MediumLevelILInstruction | None:
        """What a return passes on: the result register, or nothing on a VM without one"""
        result = self._result_var()
        return None if result is None else MLILVar(result)

    def _translate_call(self, llil_inst: LowLevelILCall):
        """Translate function call"""
        # Translate arguments
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        # Generate call (target is always a string)
        self.builder.call(llil_inst.target, mlil_args, self._result_var())

        # Add goto to return target (makes this block terminal)
        # return_target is always a LowLevelILBasicBlock
        return_block = self.block_map[llil_inst.return_target]
        self.builder.goto(return_block)

    def _translate_expr(self, llil_expr: LowLevelILInstruction) -> MediumLevelILInstruction:
        """Translate LLIL expression to MLIL"""
        # Constants
        if isinstance(llil_expr, LowLevelILConst):
            return MLILConst(llil_expr.value)

        # Stack operations → Variables
        elif isinstance(llil_expr, LowLevelILStackLoad):
            return MLILVar(self._stack_var(llil_expr.slot_index))
        elif isinstance(llil_expr, LowLevelILFrameLoad):
            return MLILVar(self._param_var(llil_expr.slot_offset))
        elif isinstance(llil_expr, LowLevelILStackAddr):
            return MLILAddressOf(MLILVar(self._stack_var(llil_expr.slot_index)))
        elif isinstance(llil_expr, LowLevelILFrameAddr):
            return MLILAddressOf(MLILVar(self._param_var(llil_expr.slot_offset)))
        elif isinstance(llil_expr, LowLevelILLoad):
            return MLILDeref(self._translate_expr(llil_expr.src))
        elif isinstance(llil_expr, LowLevelILRegLoad):
            return MLILVar(self.builder.get_or_create_register_var(llil_expr.reg_index))

        # Binary and unary operations
        elif type(llil_expr) in BINARY_OP_TYPES:
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return BINARY_OP_TYPES[type(llil_expr)](lhs, rhs)
        elif type(llil_expr) in UNARY_OP_TYPES:
            return UNARY_OP_TYPES[type(llil_expr)](self._translate_expr(llil_expr.operand))
        else:
            # Unknown expression - must be handled by derived class
            raise NotImplementedError(
                f'Unhandled LLIL expression type: {type(llil_expr).__name__}. '
                f'This may be an architecture-specific expression that should be '
                f'handled in a derived translator class.'
            )
