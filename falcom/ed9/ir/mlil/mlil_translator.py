'''Falcom ED9 VM LLIL to MLIL Translator'''

from ir.llil import *
from ir.mlil import *
from ..llil.llil_ext import *
from ..llil.constants import *

# DEBUG_LOG becomes a call so existing call handling covers it; script function names never contain a dot
DEBUG_LOG_CALL_TARGET = 'debug.log'

# REG[0] is the VM result register: calls write it and RETURN reads it
RESULT_REG_INDEX = 0


class FalcomLLILToMLILTranslator(LLILToMLILTranslator):
    '''Falcom-specific LLIL to MLIL translator'''

    def _result_reg_var(self) -> MLILVariable:
        '''Variable modelling the VM result register'''
        return self.builder.get_or_create_register_var(RESULT_REG_INDEX)

    def _call_output(self) -> MLILVariable:
        '''Local calls write their result to the VM result register'''
        return self._result_reg_var()

    def _translate_instruction(self, llil_inst: LowLevelILInstruction):
        '''Translate LLIL instruction, handling Falcom-specific operations'''

        # Skip caller frame preparation (implementation detail, not needed in MLIL)
        if isinstance(llil_inst, LowLevelILPushCallerFrame):
            return  # Omit from MLIL - calling convention detail

        # Skip stack stores for caller frame values
        if isinstance(llil_inst, LowLevelILStackStore):
            if self._is_caller_frame_value(llil_inst.value):
                return  # Omit caller frame preparation from MLIL

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
            self.builder.ret(self.builder.var(self._result_reg_var()))

        elif isinstance(llil_inst, LowLevelILCallScriptNoReturn):
            self._translate_call_script_no_return(llil_inst)

        elif isinstance(llil_inst, LowLevelILCallScript):
            self._translate_call_script(llil_inst)

        elif isinstance(llil_inst, LowLevelILSyscall):
            self._translate_syscall(llil_inst)

        elif isinstance(llil_inst, LowLevelILDebugLog):
            self._translate_debug_log(llil_inst)

        else:
            # Fall back to generic handling
            super()._translate_instruction(llil_inst)

    def _is_caller_frame_value(self, expr: LowLevelILInstruction) -> bool:
        '''Check if expression is a caller frame value (should be omitted in MLIL)'''
        return isinstance(expr, (
            LowLevelILConstFuncId,
            LowLevelILConstRetAddrBlock,
            LowLevelILConstScript,
            LowLevelILConstScriptName,
        ))

    def _translate_call_script(self, llil_inst: LowLevelILCallScript):
        '''Translate Falcom script call'''
        # Translate arguments
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        # Generate MLIL CallScript
        self.builder.call_script(llil_inst.module, llil_inst.func, mlil_args, self._result_reg_var())

        # Add goto to return target (always a LowLevelILBasicBlock in Falcom)
        return_block = self.block_map[llil_inst.return_target]
        self.builder.goto(return_block)

    def _translate_call_script_no_return(self, llil_inst: LowLevelILCallScriptNoReturn):
        '''Translate a tail-call script call as `return module.func(args)`

        A tail call still delivers the callee's result to our own caller, so this MLIL shape
        satisfies the "every block ends in a terminal" invariant and reuses the existing
        call/return path instead of needing a dedicated terminal call node.
        '''
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        self.builder.call_script(llil_inst.module, llil_inst.func, mlil_args, self._result_reg_var())
        self.builder.ret(self.builder.var(self._result_reg_var()))

    def _translate_syscall(self, llil_inst: LowLevelILSyscall):
        '''Translate Falcom syscall'''
        # Verify args match argc
        if llil_inst.argc > 0 and not llil_inst.args:
            raise ValueError(f'Syscall argc={llil_inst.argc} but args is empty')

        if len(llil_inst.args) != llil_inst.argc:
            raise ValueError(f'Syscall argc={llil_inst.argc} but got {len(llil_inst.args)} args')

        # Translate arguments from LLIL
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        # Generate MLIL Syscall
        self.builder.syscall(llil_inst.subsystem, llil_inst.cmd, mlil_args, self._result_reg_var())

    def _translate_debug_log(self, llil_inst: LowLevelILDebugLog):
        '''Translate Falcom debug log to a debug.log call (not a block terminal, so no goto)

        No output, and clobbers_registers=False: a debug print has no VM register/global
        side effects at all, so it must not clobber reg0 (or anything else) either - it
        leaves every register alone (verified in the sample scripts, where no GET_REG ever
        follows a DEBUG_LOG).
        '''
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]
        self.builder.call(DEBUG_LOG_CALL_TARGET, mlil_args, clobbers_registers = False)

    def _translate_expr(self, llil_expr: LowLevelILInstruction) -> MediumLevelILInstruction:
        '''Translate LLIL expression, handling Falcom-specific types'''

        # Falcom-specific expressions
        if isinstance(llil_expr, LowLevelILGlobalLoad):
            return self.builder.load_global(llil_expr.index)

        elif isinstance(llil_expr, LowLevelILRegLoad):
            return self.builder.var(self.builder.get_or_create_register_var(llil_expr.reg_index))

        # Falcom-specific constants
        elif isinstance(llil_expr, LowLevelILConstFuncId):
            return MLILConst('<current_func_id>', is_hex = False)

        elif isinstance(llil_expr, LowLevelILConstRetAddrBlock):
            return MLILConst(f'<ret_addr:{llil_expr.block.label}>', is_hex = False)

        elif isinstance(llil_expr, LowLevelILConstScript):
            return MLILConst('<current_script>', is_hex = False)

        else:
            # Fall back to generic handling
            return super()._translate_expr(llil_expr)
