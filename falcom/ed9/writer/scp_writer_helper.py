"""Per-opcode Python functions for the scp_writer DSL, mirroring the ED9 VM instruction set"""

from .scp_writer import *
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
    '''Opcode 0x00: Push value onto stack'''
    assert isinstance(value, sint32 | float32 | str | RawInt)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH, value)


def POP(byte_count: uint8):
    '''Opcode 0x01: Pop stack by number given by byte_count (discard popped values)'''
    assert isinstance(byte_count, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.POP, byte_count)


def LOAD_STACK(offset: sint32):
    '''Opcode 0x02: Load stack[fp(param)/sp(local) + offset // WORD_SIZE]'''
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.LOAD_STACK, offset)


def LOAD_STACK_DEREF(offset: sint32):
    '''Opcode 0x03: Load *stack[sp + offset // WORD_SIZE] (only with REG[0]?)'''
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.LOAD_STACK_DEREF, offset)


def PUSH_STACK_OFFSET(offset: sint32):
    '''Opcode 0x04: Push a reference/offset for stack[sp + offset // WORD_SIZE]'''
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_STACK_OFFSET, offset)


def POP_TO(offset: sint32):
    '''Opcode 0x05: Pop to stack[sp + offset]'''
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_TO, offset)


def POP_TO_DEREF(offset: sint32):
    '''Opcode 0x06: Pop dereferenced value to stack[sp + offset]'''
    assert isinstance(offset, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_TO_DEREF, offset)


def GLOBAL_VAR(name: str, type: sint32):
    '''Declares one entry of the script's global variable table (see @scena.GlobalVars())'''
    assert isinstance(name, str)
    assert isinstance(type, sint32)
    return get_scp_writer().add_global_var(name, type)


def LOAD_GLOBAL(name: str | sint32):
    '''Opcode 0x07: Push GLOBALS[name] onto stack'''
    assert isinstance(name, str | sint32)
    index = name if isinstance(name, sint32) else get_scp_writer().global_var_index(name)
    return get_scp_writer().handle_opcode(ED9Opcode.LOAD_GLOBAL, index)


def SET_GLOBAL(name: str | sint32):
    '''Opcode 0x08: Pop to GLOBALS[name]'''
    assert isinstance(name, str | sint32)
    index = name if isinstance(name, sint32) else get_scp_writer().global_var_index(name)
    return get_scp_writer().handle_opcode(ED9Opcode.SET_GLOBAL, index)


def GET_REG(index: uint8):
    '''Opcode 0x09: Push REG[index] onto stack (Only REG[0] is used for call return value?)'''
    assert isinstance(index, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.GET_REG, index)


def SET_REG(index: uint8):
    '''Opcode 0x0A: Pop to REG[index]'''
    assert isinstance(index, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.SET_REG, index)


def JMP(target: str):
    '''Opcode 0x0B: Jump to label/offset'''
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.JMP, target)


def CALL(func: str):
    '''Opcode 0x0C: Call function based on id, neated to take func name.'''
    assert isinstance(func.__name__, str)

    # if not any(f.name == func.__name__ for f in get_scp_writer().functions):
    #     raise TypeError("Call has unknown func.")
    
    return get_scp_writer().handle_opcode(ED9Opcode.CALL, func)


def RETURN():
    '''Return instruction, restores caller frame and sets return value to REG[0] (Opcode 0x0D)'''
    return get_scp_writer().handle_opcode(ED9Opcode.RETURN)


def POP_JMP_NOT_ZERO(target: str):
    '''Pop value and jump if value not equal zero (Opcode 0x0E)'''
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_JMP_NOT_ZERO, target)


def POP_JMP_ZERO(target: str):
    '''Pop value and jump if value equal zero (Opcode 0x0F)'''
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.POP_JMP_ZERO, target)

# Pop rhs first, then lhs
def ADD():
    # 0x10
    return get_scp_writer().handle_opcode(ED9Opcode.ADD)


def SUB():
    # 0x11
    return get_scp_writer().handle_opcode(ED9Opcode.SUB)


def MUL():
    # 0x12
    return get_scp_writer().handle_opcode(ED9Opcode.MUL)


def DIV():
    # 0x13
    return get_scp_writer().handle_opcode(ED9Opcode.DIV)


def MOD():
    # 0x14
    return get_scp_writer().handle_opcode(ED9Opcode.MOD)


def EQ():
    # 0x15
    return get_scp_writer().handle_opcode(ED9Opcode.EQ)


def NE():
    # 0x16
    return get_scp_writer().handle_opcode(ED9Opcode.NE)


def GT():
    # 0x17
    return get_scp_writer().handle_opcode(ED9Opcode.GT)


def GE():
    # 0x18
    return get_scp_writer().handle_opcode(ED9Opcode.GE)


def LT():
    # 0x19
    return get_scp_writer().handle_opcode(ED9Opcode.LT)


def LE():
    # 0x1A
    return get_scp_writer().handle_opcode(ED9Opcode.LE)


def BITWISE_AND():
    # 0x1B
    return get_scp_writer().handle_opcode(ED9Opcode.BITWISE_AND)


def BITWISE_OR():
    # 0x1C
    return get_scp_writer().handle_opcode(ED9Opcode.BITWISE_OR)


def LOGICAL_AND():
    # 0x1D
    return get_scp_writer().handle_opcode(ED9Opcode.LOGICAL_AND)


def LOGICAL_OR():
    # 0x1E
    return get_scp_writer().handle_opcode(ED9Opcode.LOGICAL_OR)


def NEG():
    # 0x1F
    return get_scp_writer().handle_opcode(ED9Opcode.NEG)


def EZ():
    # 0x20
    return get_scp_writer().handle_opcode(ED9Opcode.EZ)


def NOT():
    # 0x21
    return get_scp_writer().handle_opcode(ED9Opcode.NOT)


def CALL_SCRIPT(module: str | ScpValue, func: str | ScpValue, argc: uint8):
    '''Call func from module (Opcode 0x22)'''
    assert isinstance(module, str| ScpValue)
    assert isinstance(func, str | ScpValue)
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.CALL_SCRIPT, module, func, argc)


def CALL_SCRIPT_NO_RETURN(module: str | ScpValue, func: str | ScpValue, argc: uint8):
    '''Call func from module with no return (Tailcall)(Opcode 0x23)'''
    assert isinstance(module, str | ScpValue)
    assert isinstance(func, str | ScpValue)
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.CALL_SCRIPT_NO_RETURN, module, func, argc)


def SYSCALL(subsystem: uint8, cmd: uint8, argc: uint8):
    '''System call, takes argc in LLIL (Opcode 0x24)'''
    assert isinstance(subsystem, uint8)
    assert isinstance(cmd, uint8)
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.SYSCALL, subsystem, cmd, argc)


def PUSH_CALLER_FRAME(return_addr: str):
    '''Push caller frame [func_id, &ret_addr, script_ptr, script_ptr, script_name] (Opcode 0x25) '''
    assert isinstance(return_addr, str)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_CALLER_FRAME, return_addr)


def DEBUG_SET_LINENO(lineno: uint16):
    '''Line number, leftover debug info? (Opcode 0x26)'''
    assert isinstance(lineno, uint16)
    return get_scp_writer().handle_opcode(ED9Opcode.DEBUG_SET_LINENO, lineno)


def DEBUG_LOG(argc: uint8):
    '''Debug print of the top argc stack values, message first; pops them (Opcode 0x27)'''
    assert isinstance(argc, uint8)
    return get_scp_writer().handle_opcode(ED9Opcode.DEBUG_LOG, argc)


def UNKNOWN_28(operand_bytes: bytes = b''):
    '''Never seen in a script, operand format unknown - writes the opcode then operand_bytes as-is, for testing (Opcode 0x28)'''
    assert isinstance(operand_bytes, bytes)
    return get_scp_writer().handle_opcode(ED9Opcode.UNKNOWN_28, operand_bytes)


def PUSH_CURRENT_FUNC_ID():
    '''Opcode 0x1000 (pseudo-instruction, decoded from PUSH ahead of a CALL)'''
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_CURRENT_FUNC_ID)


def PUSH_RET_ADDR(target: str):
    '''Opcode 0x1001 (pseudo-instruction, decoded from PUSH ahead of a CALL)'''
    assert isinstance(target, str)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_RET_ADDR, target)


def PUSH_RAW(value: RawInt):
    '''Opcode 0x1002 (pseudo-instruction, decoded from PUSH)'''
    assert isinstance(value, RawInt)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_RAW, value)


def PUSH_INT(value: sint32):
    '''Opcode 0x1003 (pseudo-instruction, decoded from PUSH)'''
    assert isinstance(value, sint32)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_INT, value)


def PUSH_FLOAT(value: float32):
    '''Opcode 0x1004 (pseudo-instruction, decoded from PUSH)'''
    assert isinstance(value, float32)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_FLOAT, value)


def PUSH_STR(value: str):
    '''Opcode 0x1005 (pseudo-instruction, decoded from PUSH)'''
    assert isinstance(value, str)
    return get_scp_writer().handle_opcode(ED9Opcode.PUSH_STR, value)
