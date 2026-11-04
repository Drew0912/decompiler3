"""Falcom ED9 symbolic-stack LLIL -> MLIL translator: the VM's result register, its calling convention, globals,
script calls (the tail call among them) and DEBUG_LOG on the generic translator; a call frame value read as data
refused"""

from falcom.ed9.disasm.stack_effects import RESULT_REGISTER
from ir.llil.llil import LowLevelILBasicBlock, LowLevelILCall, LowLevelILInstruction, WORD_SIZE
from ir.mlil.mlil import MediumLevelILCall, MediumLevelILInstruction, MLILCallScript, MLILLoadGlobal, MLILVariable
from ir.mlil.stack_translator import StackTranslator, StackTranslatorPass, UnsupportedStackShape, Write, WriteKind
from ..llil.constants import (
    LowLevelILConstFuncId, LowLevelILConstRetAddrBlock, LowLevelILConstScript, LowLevelILConstFrameMarker,
)
from ..llil.llil_ext import (
    LowLevelILCallScript, LowLevelILCallScriptNoReturn, LowLevelILDebugLog, LowLevelILGlobalLoad, LowLevelILGlobalStore,
)

# DEBUG_LOG becomes a call so call handling covers it; script function names never contain a dot
DEBUG_LOG_CALL_TARGET = 'debug.log'


class FalcomStackTranslator(StackTranslator):
    RESULT_REGISTER    = RESULT_REGISTER
    IN_PLACE_ARGUMENTS = (*StackTranslator.IN_PLACE_ARGUMENTS, LowLevelILDebugLog)

    def parameter_position(self, frame_offset: int) -> int:
        """Arguments are pushed right to left, so the first parameter is in the highest frame slot and STACK[fp + 0]
        holds the last one"""
        return self.llil_func.num_params - frame_offset // WORD_SIZE

    def make_call(self, inst: LowLevelILCall, args: list[MediumLevelILInstruction],
                  output: MLILVariable | None) -> MediumLevelILCall:
        if isinstance(inst, (LowLevelILCallScript, LowLevelILCallScriptNoReturn)):
            return MLILCallScript(inst.module, inst.func, args, output, tail_call=not inst.returns)

        return super().make_call(inst, args, output)

    def translate_statement(self, inst: LowLevelILInstruction) -> LowLevelILBasicBlock | None:
        if isinstance(inst, LowLevelILGlobalStore):
            value = self.translate_expr(inst.value)
            self.copy_out(Write(WriteKind.GLOBAL, inst.index))
            self.builder.store_global(inst.index, value)
        elif isinstance(inst, LowLevelILDebugLog):
            # A debug print changes no register, global or memory: nothing to copy, no result
            args = [self.translate_expr(arg) for arg in inst.args]
            self.builder.call(DEBUG_LOG_CALL_TARGET, args, clobbers_registers=False)
        else:
            return super().translate_statement(inst)

        return None

    def translate_expr(self, node: LowLevelILInstruction) -> MediumLevelILInstruction:
        if isinstance(node, LowLevelILGlobalLoad):
            return self.builder.stamp(MLILLoadGlobal(node.index))
        # A call's setup is never translated: one of its values here is a hand edit reading the VM's frame as data,
        # which no MLIL node holds
        if isinstance(node, (LowLevelILConstFuncId, LowLevelILConstRetAddrBlock, LowLevelILConstScript,
                             LowLevelILConstFrameMarker)):
            raise UnsupportedStackShape(f'{self.llil_func.name}: a call frame value read as data')

        return super().translate_expr(node)


class ED9StackTranslatorPass(StackTranslatorPass):
    def __init__(self):
        super().__init__(FalcomStackTranslator)
