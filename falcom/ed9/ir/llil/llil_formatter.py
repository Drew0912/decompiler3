"""Falcom LLIL Formatter - shows the pops the VM builder hides and a bytecode float's bits"""

from ir.core import Constant, SourceFloat
from ir.llil import *
from falcom.ed9.structs.scp_types import ScpValue
from .llil_ext import *


class FalcomLLILFormatter(LLILFormatter):
    @classmethod
    def _format_global_store_expanded(cls, global_store: LowLevelILGlobalStore) -> list[str]:
        """Format global store with expanded pseudo-code"""
        return [
            f'GLOBAL[{global_store.index}] = STACK[--sp] ; {global_store.value}',
        ]

    @classmethod
    def format_instruction_expanded(cls, inst: LowLevelILInstruction) -> list[str] | None:
        if isinstance(inst, LowLevelILGlobalStore):
            return cls._format_global_store_expanded(inst)

        return super().format_instruction_expanded(inst)

    @classmethod
    def _format_simplified(cls, inst: LowLevelILInstruction) -> list[str]:
        """SET_REG, POP_JMP_*, POP_TO and POP_TO_DEREF hide their pop (hidden_for_formatter): their line shows it"""
        # SET_REG
        if isinstance(inst, LowLevelILRegStore):
            lines = [f'REG[{inst.reg_index}] = STACK[--sp]  ; {inst.value}']

        # POP_JMP_ZERO / POP_JMP_NOT_ZERO
        elif isinstance(inst, LowLevelILIf):
            cond = inst.condition
            lhs = cond.lhs if isinstance(cond.lhs, Constant) else 'STACK[--sp]'
            true_name = inst.true_target.block_name
            false_name = inst.false_target.block_name
            lines = [f'if ({lhs} {cond.operation_name} {cond.rhs}) goto {true_name} else {false_name}']

        # POP_TO into a local
        elif isinstance(inst, LowLevelILStackStore) and inst.offset != 0:
            lines = [f'STACK[{inst.slot_index}] = STACK[--sp] ; {inst.value}']

        # POP_TO into a parameter
        elif isinstance(inst, LowLevelILFrameStore):
            lines = [f'STACK[{frame_offset_text(inst.offset)}] = STACK[--sp] ; {inst.value}']

        # POP_TO_DEREF
        elif isinstance(inst, LowLevelILStore):
            lines = [f'*{inst.dest} = STACK[--sp] ; {inst.value}']
        else:
            lines = super()._format_simplified(inst)

        # A float from the bytecode also shows its exact bits; a plain float has none to show
        if isinstance(inst, LowLevelILStackStore) and isinstance(inst.value, LowLevelILConst):
            if isinstance(inst.value.value, SourceFloat):
                lines[-1] = f'{lines[-1]} {ScpValue.float_bits_text(inst.value.value)}'

        return lines
