"""Falcom ED9 VM LLIL to MLIL Translator"""

from ir.llil import *
from ir.mlil import *
from ir.mlil_ssa import *
from ..llil.llil_ext import *
from ..llil.constants import *

# REG[0] is the VM result register: calls write it and RETURN reads it
RESULT_REG_INDEX = 0


class FalcomLLILToMLILTranslator(LLILToMLILTranslator):
    """Falcom-specific LLIL to MLIL translator"""

    RESULT_REGISTER = RESULT_REG_INDEX

    def _result_reg_var(self) -> MLILVariable:
        """Variable modelling the VM result register"""
        return self.builder.get_or_create_register_var(RESULT_REG_INDEX)

    def _call_output(self) -> MLILVariable:
        """Local calls write their result to the VM result register"""
        return self._result_reg_var()

    def _translate_instruction(self, llil_inst: LowLevelILInstruction):
        """Translate LLIL instruction, handling Falcom-specific operations"""
        # A stack store of a caller frame value prepares the call: MLIL omits it
        if isinstance(llil_inst, LowLevelILStackStore) and self._is_caller_frame_value(llil_inst.value):
            return

        # Falcom-specific instructions
        if isinstance(llil_inst, LowLevelILGlobalStore):
            value = self._translate_expr(llil_inst.value)
            self.builder.store_global(llil_inst.index, value)
        elif isinstance(llil_inst, LowLevelILRegStore):
            value = self._translate_expr(llil_inst.value)
            reg_var = self.builder.get_or_create_register_var(llil_inst.reg_index)
            self.builder.set_var(reg_var, value)
        elif isinstance(llil_inst, LowLevelILRet):
            # The VM returns whatever the result register holds
            self.builder.ret(MLILVar(self._result_reg_var()))
        elif isinstance(llil_inst, LowLevelILCallScriptNoReturn):
            self._translate_call_script_no_return(llil_inst)
        elif isinstance(llil_inst, LowLevelILCallScript):
            self._translate_call_script(llil_inst)
        elif isinstance(llil_inst, LowLevelILSyscall):
            self._translate_syscall(llil_inst)
        elif isinstance(llil_inst, LowLevelILPopN):
            self.builder.intrinsic('POPN', [self._translate_expr(value) for value in llil_inst.values])
        elif isinstance(llil_inst, LowLevelILDebugInt):
            self.builder.intrinsic('DEBUG_INT', [MLILConst(llil_inst.value)])
        else:
            # Fall back to generic handling
            super()._translate_instruction(llil_inst)

    def _is_caller_frame_value(self, expr: LowLevelILInstruction) -> bool:
        """Check if expression is a caller frame value (should be omitted in MLIL)"""
        return isinstance(expr, (
            LowLevelILConstFuncId,
            LowLevelILConstRetAddrBlock,
            LowLevelILConstScript,
            LowLevelILConstFrameMarker,
        ))

    def _translate_call_script(self, llil_inst: LowLevelILCallScript):
        """Translate Falcom script call"""
        # Translate arguments
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        # Generate MLIL CallScript
        self.builder.call_script(llil_inst.module, llil_inst.func, mlil_args, self._result_reg_var())

        # Add goto to return target (always a LowLevelILBasicBlock in Falcom)
        return_block = self.block_map[llil_inst.return_target]
        self.builder.goto(return_block)

    def _translate_call_script_no_return(self, llil_inst: LowLevelILCallScriptNoReturn):
        """Translate a tail-call script call as `return module.func(args)`

        A tail call still delivers the callee's result to our own caller, so this MLIL shape
        satisfies the "every block ends in a terminal" invariant and reuses the existing
        call/return path instead of needing a dedicated terminal call node
        """
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        self.builder.call_script(llil_inst.module, llil_inst.func, mlil_args, self._result_reg_var())
        self.builder.ret(MLILVar(self._result_reg_var()))

    def _translate_syscall(self, llil_inst: LowLevelILSyscall):
        """Translate Falcom syscall"""
        # Translate arguments from LLIL
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        # Generate MLIL Syscall
        self.builder.syscall(llil_inst.subsystem, llil_inst.cmd, mlil_args, self._result_reg_var())

    def _translate_expr(self, llil_expr: LowLevelILInstruction) -> MediumLevelILInstruction:
        """Translate LLIL expression, handling Falcom-specific types"""
        # Falcom-specific expressions
        if isinstance(llil_expr, LowLevelILGlobalLoad):
            return MLILLoadGlobal(llil_expr.index)
        elif isinstance(llil_expr, LowLevelILRegLoad):
            return MLILVar(self.builder.get_or_create_register_var(llil_expr.reg_index))

        # Falcom-specific constants
        elif isinstance(llil_expr, LowLevelILConstFuncId):
            return MLILConst('<current_func_id>', is_hex=False)
        elif isinstance(llil_expr, LowLevelILConstRetAddrBlock):
            return MLILConst(f'<ret_addr:{llil_expr.block.label}>', is_hex=False)
        elif isinstance(llil_expr, LowLevelILConstScript):
            return MLILConst('<current_script>', is_hex=False)
        else:
            # Fall back to generic handling
            return super()._translate_expr(llil_expr)
