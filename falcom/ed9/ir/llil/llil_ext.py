'''Falcom-specific LLIL Extensions'''

from enum import IntEnum
from typing import Optional, Union, List, TYPE_CHECKING
from ir.llil import *
from .constants import *


class LowLevelILFalcomOperation(IntEnum):
    '''Falcom-specific LLIL operations'''
    LLIL_PUSH_CALLER_FRAME = LowLevelILOperation.LLIL_PUSH_CALLER_FRAME  # Push caller frame (4 values)
    LLIL_CALL_SCRIPT = LowLevelILOperation.LLIL_CALL_SCRIPT              # Call script function
    LLIL_GLOBAL_LOAD = LowLevelILOperation.LLIL_USER_DEFINED     # Load from global variable array
    LLIL_GLOBAL_STORE = LowLevelILOperation.LLIL_USER_DEFINED + 1  # Store to global variable array
    LLIL_DEBUG_LOG = LowLevelILOperation.LLIL_USER_DEFINED + 2     # Debug print of stack values


class LowLevelILPushCallerFrame(LowLevelILStatement):
    '''PUSH_CALLER_FRAME - Push caller frame to save call context (statement)'''

    def __init__(
        self,
        func_id: 'LowLevelILConstFuncId',
        ret_addr: 'LowLevelILConstRetAddrBlock',
        script_ptr: 'LowLevelILConstScript',
        script_name: 'LowLevelILConstScriptName'
    ):
        super().__init__(LowLevelILFalcomOperation.LLIL_PUSH_CALLER_FRAME)

        if not isinstance(ret_addr, LowLevelILConstRetAddrBlock):
            raise TypeError(
                f'ret_addr must be LowLevelILConstRetAddrBlock, got {type(ret_addr).__name__}'
            )

        self.func_id          = func_id                     # FalcomConstants.current_func_id()
        self.ret_addr         = ret_addr                    # FalcomConstants.ret_addr() or ret_addr_block()
        self.script_ptr       = script_ptr                  # FalcomConstants.current_script()
        self.script_name      = script_name                 # FalcomConstants.current_script_name()
        self.slot_index       : Optional[int] = None        # Will be set by builder to track stack position

    def __str__(self) -> str:
        return f'push_caller_frame({self.ret_addr})'


class LowLevelILCallScript(LowLevelILCall):
    '''CALL_SCRIPT - Call a script function with automatic stack cleanup (statement)'''

    def __init__(
        self,
        module: str,
        func: str,
        caller_frame: LowLevelILPushCallerFrame,
        args: List['LowLevelILExpr'],
        return_target: 'LowLevelILBasicBlock'
    ):
        target = f'{module}.{func}'
        super().__init__(target, return_target)
        self.operation    = LowLevelILFalcomOperation.LLIL_CALL_SCRIPT
        self.module       = module          # Script module name (e.g., 'system')
        self.func         = func            # Function name (e.g., 'OnTalkBegin')
        self.caller_frame = caller_frame    # Caller frame (popped from vstack)
        self.args         = args            # Arguments (popped from vstack)
        self.arg_count    = len(args)       # Number of arguments

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'call_script(`{self.module}.{self.func}`, [{args_str}]) -> {self.return_target.label}'


class LowLevelILGlobalLoad(LowLevelILExpr):
    '''LOAD_GLOBAL - Load from global variable array (expression)'''

    def __init__(self, index: int):
        super().__init__(LowLevelILFalcomOperation.LLIL_GLOBAL_LOAD)
        self.index = index

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}]'


class LowLevelILGlobalStore(LowLevelILStatement):
    '''SET_GLOBAL - Store to global variable array (statement)'''

    def __init__(self, index: int, value: LowLevelILExpr):
        super().__init__(LowLevelILFalcomOperation.LLIL_GLOBAL_STORE)
        self.index = index
        self.value = value  # Expression popped from stack

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}] = {self.value}'


class LowLevelILDebugLog(LowLevelILStatement):
    '''DEBUG_LOG - Debug print of the top argc stack values, message first (statement)'''

    def __init__(self, args: List['LowLevelILExpr']):
        super().__init__(LowLevelILFalcomOperation.LLIL_DEBUG_LOG)
        self.args = args    # Top of stack first (from vstack)

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'DEBUG_LOG({args_str})'
