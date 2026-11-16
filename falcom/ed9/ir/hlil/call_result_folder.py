"""ED9's call result folder: the generic folder with ED9's call rule"""

from ir.hlil.call_result_folder import CallResultFolder
from ir.mlil.mlil import MediumLevelILCall, MediumLevelILInstruction
from ..mlil.stack_translator import CALL_MAY_CHANGE


class ED9CallResultFolder(CallResultFolder):
    """A call may change every register, global and dereference (CALL_MAY_CHANGE), so no read of one moves across it"""

    def call_may_change(self, call: MediumLevelILCall, node: MediumLevelILInstruction) -> bool:
        return isinstance(node, CALL_MAY_CHANGE)
