"""Falcom-specific LLIL Extensions"""

from enum import IntEnum
from ir.llil import *


class LowLevelILFalcomOperation(IntEnum):
    """Falcom-specific LLIL operations"""

    LLIL_GLOBAL_LOAD           = LowLevelILOperation.LLIL_USER_DEFINED      # Load from global variable array
    LLIL_GLOBAL_STORE          = LowLevelILOperation.LLIL_USER_DEFINED + 1  # Store to global variable array
    LLIL_POPN                  = LowLevelILOperation.LLIL_USER_DEFINED + 2  # Pop stack values, kept as one statement
    LLIL_DEBUG_INT             = LowLevelILOperation.LLIL_USER_DEFINED + 3  # Log an immediate at level 0
    LLIL_CALL_SCRIPT           = LowLevelILOperation.LLIL_USER_DEFINED + 4  # Call script function
    LLIL_CALL_SCRIPT_NO_RETURN = LowLevelILOperation.LLIL_USER_DEFINED + 5  # Tail-call script function


class LowLevelILCallScript(LowLevelILCall):
    """CALL_SCRIPT - Call a script function with automatic stack cleanup (statement)"""

    def __init__(
        self,
        module: str,
        func: str,
        args: list[LowLevelILExpr],
        return_target: LowLevelILBasicBlock
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
        args: list[LowLevelILExpr],
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

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}] = {self.value}'


class LowLevelILPopN(LowLevelILStatement):
    """POPN - the top count stack values, message first, which it pops (statement); the VM prints nothing"""

    def __init__(self, values: list[LowLevelILExpr]):
        super().__init__(LowLevelILFalcomOperation.LLIL_POPN)
        self.values = values    # Top of stack first (from vstack)

    def operands(self) -> tuple[LowLevelILInstruction, ...]:
        return tuple(self.values)

    def __str__(self) -> str:
        values_str = ', '.join(str(value) for value in self.values)
        return f'POPN({values_str})'


class LowLevelILDebugInt(LowLevelILStatement):
    """DEBUG_INT - log an immediate at level 0, which the VM's logger drops (statement)"""

    def __init__(self, value: int):
        super().__init__(LowLevelILFalcomOperation.LLIL_DEBUG_INT)
        self.value = value

    def __str__(self) -> str:
        return f'DEBUG_INT({self.value})'
