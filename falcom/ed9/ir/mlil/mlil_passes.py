'''Falcom ED9 MLIL Passes'''

from ir.pipeline import *
from ir.llil import *
from ir.mlil import *
from ir.mlil.mlil_passes import *
from .mlil_translator import *


class ED9LLILToMLILPass(LLILToMLILPass):
    '''ED9-specific LLIL to MLIL conversion pass'''

    def __init__(self):
        super().__init__(translator_class=FalcomLLILToMLILTranslator)
