"""Per-opcode Python functions for the scp_writer DSL, mirroring the ED9 VM instruction set"""

from typing import Callable

from .scp_writer import get_scp_writer
from ..disasm import ED9Opcode
from ..parser.types_scp import *

sint8   = int
uint8   = int
sint16  = int
uint16  = int
sint32  = int
uint32  = int
float32 = float | int


def PUSH(value: sint32 | float32 | str | RawInt):
    """Push value onto stack (Opcode 0x00)"""
    assert isinstance(value, sint32 | float32 | str | RawInt)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH, value)


def POP(byte_count: uint8):
    """Pop byte_count bytes (byte_count // WORD_SIZE values) and discard them (Opcode 0x01)"""
    assert isinstance(byte_count, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.POP, byte_count)


def LOAD_STACK(offset: sint32):
    """Push stack[sp + offset // WORD_SIZE] (always sp-relative, parameters included) (Opcode 0x02)"""
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.LOAD_STACK, offset)


def LOAD_STACK_DEREF(offset: sint32):
    """Push *stack[sp + offset // WORD_SIZE] - reads through a pointer the caller passed in a parameter slot
    (Opcode 0x03)"""
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.LOAD_STACK_DEREF, offset)


def PUSH_STACK_OFFSET(offset: sint32):
    """Push a reference/offset for stack[sp + offset // WORD_SIZE] (Opcode 0x04)"""
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_STACK_OFFSET, offset)


def POP_TO(offset: sint32):
    """Pop, then store to stack[sp + offset // WORD_SIZE] (sp taken after the pop) (Opcode 0x05)"""
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_TO, offset)


def POP_TO_DEREF(offset: sint32):
    """Pop, then store through the pointer in stack[sp + offset // WORD_SIZE] (sp taken after the pop) (Opcode 0x06)"""
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_TO_DEREF, offset)


def LOAD_GLOBAL(name: str | sint32):
    """Push GLOBALS[name] onto stack (Opcode 0x07)"""
    assert isinstance(name, str | sint32)
    index = name if isinstance(name, sint32) else get_scp_writer().global_var_index(name)
    return get_scp_writer().handle_opcode(ED9Opcode.LOAD_GLOBAL, index)


def SET_GLOBAL(name: str | sint32):
    """Pop to GLOBALS[name] (Opcode 0x08)"""
    assert isinstance(name, str | sint32)
    index = name if isinstance(name, sint32) else get_scp_writer().global_var_index(name)
    return get_scp_writer().handle_opcode(ED9Opcode.SET_GLOBAL, index)


def GET_REG(index: uint8):
    """Push REG[index] onto stack (REG[0] holds a function's return value) (Opcode 0x09)"""
    assert isinstance(index, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.GET_REG, index)


def SET_REG(index: uint8):
    """Pop to REG[index] (Opcode 0x0A)"""
    assert isinstance(index, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.SET_REG, index)


def JMP(target: str):
    """Jump to a label, by name (Opcode 0x0B)"""
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.JMP, target)


def CALL(func: Callable):
    """Call a script function, passed as the function itself - CALL(Foo), not CALL('Foo') (Opcode 0x0C)"""
    assert callable(func), f'CALL takes the function itself, not {func!r}'
    return get_scp_writer().handle_opcode(ED9Opcode.CALL, func)


def RETURN():
    """Return to the caller; the stack must be empty (parameters and locals popped), and a return value is set
    beforehand with SET_REG(0) (Opcode 0x0D)"""
    return get_scp_writer().handle_opcode(ED9Opcode.RETURN)


def POP_JMP_NOT_ZERO(target: str):
    """Pop value and jump if value not equal zero (Opcode 0x0E)"""
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_JMP_NOT_ZERO, target)


def POP_JMP_ZERO(target: str):
    """Pop value and jump if value equal zero (Opcode 0x0F)"""
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_JMP_ZERO, target)


def ADD():
    """Pop rhs, then lhs; push lhs + rhs (Opcode 0x10)"""
    return get_scp_writer().handle_opcode(ED9Opcode.ADD)


def SUB():
    """Pop rhs, then lhs; push lhs - rhs (Opcode 0x11)"""
    return get_scp_writer().handle_opcode(ED9Opcode.SUB)


def MUL():
    """Pop rhs, then lhs; push lhs * rhs (Opcode 0x12)"""
    return get_scp_writer().handle_opcode(ED9Opcode.MUL)


def DIV():
    """Pop rhs, then lhs; push lhs / rhs (Opcode 0x13)"""
    return get_scp_writer().handle_opcode(ED9Opcode.DIV)


def MOD():
    """Pop rhs, then lhs; push lhs % rhs (Opcode 0x14)"""
    return get_scp_writer().handle_opcode(ED9Opcode.MOD)


def EQ():
    """Pop rhs, then lhs; push lhs == rhs (Opcode 0x15)"""
    return get_scp_writer().handle_opcode(ED9Opcode.EQ)


def NE():
    """Pop rhs, then lhs; push lhs != rhs (Opcode 0x16)"""
    return get_scp_writer().handle_opcode(ED9Opcode.NE)


def GT():
    """Pop rhs, then lhs; push lhs > rhs (Opcode 0x17)"""
    return get_scp_writer().handle_opcode(ED9Opcode.GT)


def GE():
    """Pop rhs, then lhs; push lhs >= rhs (Opcode 0x18)"""
    return get_scp_writer().handle_opcode(ED9Opcode.GE)


def LT():
    """Pop rhs, then lhs; push lhs < rhs (Opcode 0x19)"""
    return get_scp_writer().handle_opcode(ED9Opcode.LT)


def LE():
    """Pop rhs, then lhs; push lhs <= rhs (Opcode 0x1A)"""
    return get_scp_writer().handle_opcode(ED9Opcode.LE)


def BITWISE_AND():
    """Pop rhs, then lhs; push lhs & rhs (Opcode 0x1B)"""
    return get_scp_writer().handle_opcode(ED9Opcode.BITWISE_AND)


def BITWISE_OR():
    """Pop rhs, then lhs; push lhs | rhs (Opcode 0x1C)"""
    return get_scp_writer().handle_opcode(ED9Opcode.BITWISE_OR)


def LOGICAL_AND():
    """Pop rhs, then lhs; push lhs && rhs (Opcode 0x1D)"""
    return get_scp_writer().handle_opcode(ED9Opcode.LOGICAL_AND)


def LOGICAL_OR():
    """Pop rhs, then lhs; push lhs || rhs (Opcode 0x1E)"""
    return get_scp_writer().handle_opcode(ED9Opcode.LOGICAL_OR)


def NEG():
    """Pop x; push -x (Opcode 0x1F)"""
    return get_scp_writer().handle_opcode(ED9Opcode.NEG)


def EZ():
    """Pop x; push x == 0 (logical not) (Opcode 0x20)"""
    return get_scp_writer().handle_opcode(ED9Opcode.EZ)


def NOT():
    """Pop x; push ~x (bitwise not) (Opcode 0x21)"""
    return get_scp_writer().handle_opcode(ED9Opcode.NOT)


def CALL_SCRIPT(module: str | ScpValue, func: str | ScpValue, argc: uint8):
    """Call func from module (Opcode 0x22)"""
    assert isinstance(module, str | ScpValue)
    assert isinstance(func, str | ScpValue)
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.CALL_SCRIPT, module, func, argc)


def CALL_SCRIPT_NO_RETURN(module: str | ScpValue, func: str | ScpValue, argc: uint8):
    """Call func from module with no return (tail call) (Opcode 0x23)"""
    assert isinstance(module, str | ScpValue)
    assert isinstance(func, str | ScpValue)
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.CALL_SCRIPT_NO_RETURN, module, func, argc)


def SYSCALL(subsystem: uint8, cmd: uint8, argc: uint8):
    """System call on the top argc stack values, which it reads without popping (Opcode 0x24)"""
    assert isinstance(subsystem, uint8)
    assert isinstance(cmd, uint8)
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.SYSCALL, subsystem, cmd, argc)


def PUSH_CALLER_FRAME(return_addr: str):
    """Push caller frame [func_id, &ret_addr, script_ptr, script_ptr, script_name] (Opcode 0x25)"""
    assert isinstance(return_addr, str)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_CALLER_FRAME, return_addr)


def DEBUG_SET_LINENO(lineno: uint16):
    """Line number (debug info) (Opcode 0x26)"""
    assert isinstance(lineno, uint16)
    return get_scp_writer().handle_opcode(ED9Opcode.DEBUG_SET_LINENO, lineno)


def DEBUG_LOG(argc: uint8):
    """Debug print of the top argc stack values, message first; pops them (Opcode 0x27)"""
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.DEBUG_LOG, argc)


def UNKNOWN_28(operand_bytes: bytes = b''):
    """Never seen in a script, operand format unknown - writes the opcode then operand_bytes as-is, for testing
    (Opcode 0x28)"""
    assert isinstance(operand_bytes, bytes)
    return get_scp_writer().handle_opcode(ED9Opcode.UNKNOWN_28, operand_bytes)


def PUSH_CURRENT_FUNC_ID():
    """Push the current function's index - a local call starts with it, then PUSH_RET_ADDR, the arguments and CALL.
    A pseudo-op: a PUSH_RAW on disk (Opcode 0x1000)"""
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_CURRENT_FUNC_ID)


def PUSH_RET_ADDR(target: str):
    """Push the address of label target, where a local call returns to; pushed right after PUSH_CURRENT_FUNC_ID.
    A pseudo-op: a PUSH_RAW on disk (Opcode 0x1001)"""
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_RET_ADDR, target)


def PUSH_RAW(value: RawInt):
    """Push value typed Raw, not Integer. A pseudo-op: a PUSH on disk (Opcode 0x1002)"""
    assert isinstance(value, RawInt)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_RAW, value)


def PUSH_INT(value: sint32):
    """Push integer value. A pseudo-op: a PUSH on disk (Opcode 0x1003)"""
    assert isinstance(value, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_INT, value)


def PUSH_FLOAT(value: float32):
    """Push float value (an int is converted). A pseudo-op: a PUSH on disk (Opcode 0x1004)"""
    assert isinstance(value, float32)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_FLOAT, value)


def PUSH_STR(value: str):
    """Push string value. A pseudo-op: a PUSH on disk (Opcode 0x1005)"""
    assert isinstance(value, str)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_STR, value)
