"""Falcom ED9 VM LLIL to MLIL Translator"""

from falcom.ed9.assembler.vm import RESULT_REGISTER, parameter_position
from ir.llil import *
from ir.mlil import *
from ir.mlil_ssa import *
from ..llil.llil_ext import *
from ..llil.constants import *
from .mlil_ssa_function import ED9MediumLevelILFunctionSSA


class ED9LLILToMLILTranslator(LLILToMLILTranslator):
    """ED9-specific LLIL to MLIL translator"""

    RESULT_REGISTER = RESULT_REGISTER
    FUNCTION_CLASS  = ED9MediumLevelILFunctionSSA

    def parameter_position(self, frame_slot: int) -> int:
        return parameter_position(self.llil_func.num_params, frame_slot)

    def _translate_instruction(self, llil_inst: LowLevelILInstruction):
        """Translate LLIL instruction, handling ED9-specific operations"""
        # A stack store of a caller frame value prepares the call: MLIL omits it
        if isinstance(llil_inst, LowLevelILStackStore) and self._is_caller_frame_value(llil_inst.value):
            return

        # ED9-specific instructions
        if isinstance(llil_inst, LowLevelILGlobalStore):
            value = self._translate_expr(llil_inst.value)
            self.builder.store_global(llil_inst.index, value)
        elif isinstance(llil_inst, LowLevelILCallScriptNoReturn):
            self._translate_call_script_no_return(llil_inst)
        elif isinstance(llil_inst, LowLevelILCallScript):
            self._translate_call_script(llil_inst)
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
        """Translate ED9 script call"""
        # Translate arguments
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        self.builder.extern_call(llil_inst.module, llil_inst.func, mlil_args, self._result_var())

        # Add goto to return target (always a LowLevelILBasicBlock in ED9)
        return_block = self.block_map[llil_inst.return_target]
        self.builder.goto(return_block)

    def _translate_call_script_no_return(self, llil_inst: LowLevelILCallScriptNoReturn):
        """Translate a tail-call script call as `return module.func(args)`

        A tail call still delivers the callee's result to our own caller, so this MLIL shape
        satisfies the "every block ends in a terminal" invariant and reuses the existing
        call/return path instead of needing a dedicated terminal call node
        """
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        self.builder.extern_call(llil_inst.module, llil_inst.func, mlil_args, self._result_var())
        self.builder.ret(self._result_read())

    def _translate_expr(self, llil_expr: LowLevelILInstruction) -> MediumLevelILInstruction:
        """Translate LLIL expression, handling ED9-specific types"""
        # ED9-specific expressions
        if isinstance(llil_expr, LowLevelILGlobalLoad):
            return MLILLoadGlobal(llil_expr.index)

        # ED9-specific constants
        elif isinstance(llil_expr, LowLevelILConstFuncId):
            return MLILConst('<current_func_id>', is_hex=False)
        elif isinstance(llil_expr, LowLevelILConstRetAddrBlock):
            return MLILConst(f'<ret_addr:{llil_expr.block.label}>', is_hex=False)
        elif isinstance(llil_expr, LowLevelILConstScript):
            return MLILConst('<current_script>', is_hex=False)
        else:
            # Fall back to generic handling
            return super()._translate_expr(llil_expr)
