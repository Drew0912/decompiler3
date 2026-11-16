"""ED9's call result pass: the generic pass with ED9's call rule"""

from ir.mlil.mlil import MediumLevelILCall
from ir.mlil.passes.pass_call_result import CallResultPass


class ED9CallResultPass(CallResultPass):
    """Nothing saves a register (docs/falcom/ed9/ED9_VM.md, Registers), so any call may write the result register"""

    def call_may_change_register(self, call: MediumLevelILCall, reg_index: int) -> bool:
        return True
