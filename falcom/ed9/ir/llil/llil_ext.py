"""Falcom-specific LLIL Extensions"""

from enum import IntEnum
from typing import List
from ir.llil import *


class LowLevelILFalcomOperation(IntEnum):
    """Falcom-specific LLIL operations"""

    LLIL_GLOBAL_LOAD           = LowLevelILOperation.LLIL_USER_DEFINED      # Load from global variable array
    LLIL_GLOBAL_STORE          = LowLevelILOperation.LLIL_USER_DEFINED + 1  # Store to global variable array
    LLIL_DEBUG_LOG             = LowLevelILOperation.LLIL_USER_DEFINED + 2  # Debug print of stack values
    LLIL_CALL_SCRIPT           = LowLevelILOperation.LLIL_USER_DEFINED + 4  # Call script function
    LLIL_CALL_SCRIPT_NO_RETURN = LowLevelILOperation.LLIL_USER_DEFINED + 5  # Tail-call script function


class LowLevelILCallScript(LowLevelILCall):
    """CALL_SCRIPT - Call a script function with automatic stack cleanup (statement)"""

    def __init__(
        self,
        module: str,
        func: str,
        args: List['LowLevelILExpr'],
        return_target: 'LowLevelILBasicBlock'
    ):
        target = f'{module}.{func}'
        super().__init__(target, return_target, args)
        self.operation    = LowLevelILFalcomOperation.LLIL_CALL_SCRIPT
        self.module       = module          # Script module name (e.g., 'system')
        self.func         = func            # Function name (e.g., 'OnTalkBegin')

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'call_script(`{self.module}.{self.func}`, [{args_str}]) -> {self.return_target.label}'


class LowLevelILCallScriptNoReturn(LowLevelILCall):
    """CALL_SCRIPT_NO_RETURN - tail call to a script function; caller never regains control (statement)

    Unlike CALL_SCRIPT, the bytecode emits no PUSH_CALLER_FRAME before this opcode - the compiler
    only pushes the arguments, since the callee's frame takes over instead of returning here
    """

    def __init__(
        self,
        module: str,
        func: str,
        args: List['LowLevelILExpr'],
    ):
        target = f'{module}.{func}'
        super().__init__(target, return_target=None, args=args, returns=False)
        self.operation    = LowLevelILFalcomOperation.LLIL_CALL_SCRIPT_NO_RETURN
        self.module       = module          # Script module name (e.g., 'system')
        self.func         = func            # Function name (e.g., 'OnTalkBegin')

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'call_script_no_return(`{self.module}.{self.func}`, [{args_str}])'


class LowLevelILGlobalLoad(LowLevelILExpr):
    """LOAD_GLOBAL - Load from global variable array (expression)"""

    def __init__(self, index: int):
        super().__init__(LowLevelILFalcomOperation.LLIL_GLOBAL_LOAD)
        self.index = index

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}]'


class LowLevelILGlobalStore(LowLevelILStatement):
    """SET_GLOBAL - Store to global variable array (statement)"""

    def __init__(self, index: int, value: LowLevelILExpr):
        super().__init__(LowLevelILFalcomOperation.LLIL_GLOBAL_STORE)
        self.index = index
        self.value = value  # Expression popped from stack

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}] = {self.value}'


class LowLevelILDebugLog(LowLevelILStatement):
    """DEBUG_LOG - Debug print of the top argc stack values, message first (statement)"""

    def __init__(self, args: List['LowLevelILExpr']):
        super().__init__(LowLevelILFalcomOperation.LLIL_DEBUG_LOG)
        self.args = args    # Top of stack first (from vstack)

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'DEBUG_LOG({args_str})'
