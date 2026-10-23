"""Falcom VM specific constants and types"""

from ir.llil.llil import *


class LowLevelILConstFuncId(LowLevelILConst):
    """Falcom VM function ID constant"""

    def __init__(self):
        # Special constant with no actual value
        super().__init__(None)

    def __str__(self) -> str:
        return '<func_id>'


class LowLevelILConstRetAddrBlock(LowLevelILConst):
    """Falcom VM return address constant (block-based)"""

    def __init__(self, block: 'LowLevelILBasicBlock'):
        # Store block reference as the value
        super().__init__(block)
        self.block = block

    def __str__(self) -> str:
        return f'<&{self.block.label}>'


class LowLevelILConstScript(LowLevelILConst):
    """Falcom VM current script constant"""

    def __init__(self):
        # Special constant with no actual value
        super().__init__(None)

    def __str__(self) -> str:
        return '<script_ptr>'


class LowLevelILConstScriptName(LowLevelILConst):
    """Falcom VM current script name constant (context marker)"""

    def __init__(self):
        super().__init__('')

    def __str__(self) -> str:
        return '<script_name>'
