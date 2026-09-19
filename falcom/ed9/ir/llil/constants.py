'''Falcom VM specific constants and types'''

from typing import TYPE_CHECKING
from ir.llil.llil import *


class LowLevelILConstFuncId(LowLevelILConst):
    '''Falcom VM function ID constant'''

    def __init__(self):
        # Special constant with no actual value
        super().__init__(None, is_hex=False)

    def __str__(self) -> str:
        return '<func_id>'


class LowLevelILConstRetAddr(LowLevelILConst):
    '''Falcom VM return address constant (label-based)'''

    def __init__(self, label: str):
        # Store label as the value
        super().__init__(label, is_hex=False)
        self.label = label

    def __str__(self) -> str:
        return f'<&{self.label}>'


class LowLevelILConstRetAddrBlock(LowLevelILConst):
    '''Falcom VM return address constant (block-based)'''

    def __init__(self, block: 'LowLevelILBasicBlock'):
        # Store block reference as the value
        super().__init__(block, is_hex=False)
        self.block = block

    def __str__(self) -> str:
        return f'<&{self.block.label}>'


class LowLevelILConstScript(LowLevelILConst):
    '''Falcom VM current script constant'''

    def __init__(self):
        # Special constant with no actual value
        super().__init__(None, is_hex=False)

    def __str__(self) -> str:
        return '<script_ptr>'


class LowLevelILConstScriptName(LowLevelILConst):
    '''Falcom VM current script name constant (context marker)'''

    def __init__(self, name: str):
        super().__init__(name)

    @property
    def name(self) -> str:
        return self.value

    def __str__(self) -> str:
        if self.name:
            return f'<script_name:{self.name}>'
        else:
            return '<script_name>'


class FalcomConstants:
    '''Falcom VM specific constants factory'''

    @classmethod
    def current_func_id(cls):
        return LowLevelILConstFuncId()

    @classmethod
    def ret_addr(cls, label: str):
        return LowLevelILConstRetAddr(label)

    @classmethod
    def ret_addr_block(cls, block: 'LowLevelILBasicBlock'):
        return LowLevelILConstRetAddrBlock(block)

    @classmethod
    def current_script(cls):
        return LowLevelILConstScript()

    @classmethod
    def current_script_name(cls, name: str):
        return LowLevelILConstScriptName(name)
