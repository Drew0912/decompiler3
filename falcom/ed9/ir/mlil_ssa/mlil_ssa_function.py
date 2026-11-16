"""ED9's MLIL function on the SSA path: its call and return rules"""

from ir.mlil.mlil import MediumLevelILCall
from ir.mlil_ssa.mlil_ssa_function import MediumLevelILFunctionSSA


class ED9MediumLevelILFunctionSSA(MediumLevelILFunctionSSA):
    """Nothing saves, restores or clears a register (docs/falcom/ed9/ED9_VM.md, Registers): a callee shares the
    registers, as it shares the script's globals, so a call may change any of them, and a return leaves them as they
    are"""

    def call_may_change_register(self, call: MediumLevelILCall, reg_index: int) -> bool:
        return True

    def call_may_change_global(self, call: MediumLevelILCall, global_index: int) -> bool:
        return True

    def return_leaves_register(self, reg_index: int) -> bool:
        return True
