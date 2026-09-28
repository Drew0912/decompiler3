'''Falcom ED9 MLIL Passes'''

from ir.mlil.mlil_passes import LLILToMLILPass
from .mlil_translator import FalcomLLILToMLILTranslator


class ED9LLILToMLILPass(LLILToMLILPass):
    '''ED9-specific LLIL to MLIL conversion pass'''

    def __init__(self):
        super().__init__(translator_class = FalcomLLILToMLILTranslator)
