"""MLIL to HLIL Conversion Pass"""

from ir.pipeline import Pass
from ir.mlil.mlil import MediumLevelILFunction
from ..call_result_folder import CallResultFolder
from ..hlil import HighLevelILFunction
from ..mlil_to_hlil import MLILToHLILConverter


class MLILToHLILPass(Pass):
    """MLIL to HLIL conversion pass, through a call result folder class (the VM's call rule)"""

    def __init__(self, folder_class: type[CallResultFolder] = CallResultFolder):
        self.folder_class = folder_class

    def run(self, mlil_func: MediumLevelILFunction) -> HighLevelILFunction:
        return MLILToHLILConverter(mlil_func, folder_class=self.folder_class).convert()
