"""MLIL to HLIL Conversion Pass"""

from ir.pipeline import Pass
from ir.mlil.mlil import MediumLevelILFunction
from ..hlil import HighLevelILFunction
from ..mlil_to_hlil import MLILToHLILConverter


class MLILToHLILPass(Pass):
    """MLIL to HLIL conversion pass"""

    def run(self, mlil_func: MediumLevelILFunction) -> HighLevelILFunction:
        return MLILToHLILConverter(mlil_func).convert()
