"""LLIL to MLIL conversion pass"""

from ir.pipeline import Pass
from ir.llil import LowLevelILFunction
from ir.mlil.mlil import MediumLevelILFunction
from ..llil_to_mlil import LLILToMLILTranslator


class LLILToMLILPass(Pass):
    """LLIL to MLIL conversion pass (base)"""

    def __init__(self, translator_class: type = None):
        self.translator_class = translator_class or LLILToMLILTranslator

    def run(self, llil_func: LowLevelILFunction) -> MediumLevelILFunction:
        """Convert LLIL function to MLIL"""
        translator = self.translator_class()
        return translator.translate(llil_func)
