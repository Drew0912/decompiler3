"""LLIL to MLIL conversion pass"""

from ir.pipeline import Pass
from ir.llil import LowLevelILFunction
from ..llil_to_mlil import LLILToMLILTranslator
from ..mlil_ssa_function import MediumLevelILFunctionSSA


class LLILToMLILPass(Pass):
    """LLIL to MLIL conversion pass (base)"""

    def __init__(self, translator_class: type = None):
        self.translator_class = translator_class or LLILToMLILTranslator

    def run(self, llil_func: LowLevelILFunction) -> MediumLevelILFunctionSSA:
        """Convert LLIL function to MLIL"""
        translator = self.translator_class()
        return translator.translate(llil_func)
