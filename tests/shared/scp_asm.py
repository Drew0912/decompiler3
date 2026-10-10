#!/usr/bin/env python3
'''Hand-coded ED9 bytecode for parser-level tests: Asm encodes mnemonics with labels and strings, Program lays out
functions, a string pool and a function table for a real ScpParser. The constants are values the tests share.'''

from typing import NamedTuple
import struct

from common import fileio
from common.config import default_encoding
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.parser.types_parser import Function, FunctionParam
from falcom.ed9.parser.types_scp import ScpFunctionEntry, ScpParamFlags, ScpValue, Value32
from ir.llil.llil import WORD_SIZE


CALLER_ID = 0
CALLEE_ID = 1
GLOBAL_INDEX = 0
REG_INDEX = 0
LEFT_VALUE = 7
RIGHT_VALUE = 8
FLOAT_VALUE = 0.3
SYSCALL_SUBSYSTEM = 1
SYSCALL_FUNC = 2
FUNC_NAME = 'f'
CALLEE_NAME = 'callee'
MODULE_NAME = 'this'
SCRIPT_FUNC_NAME = 'g'
STRINGS = (MODULE_NAME, SCRIPT_FUNC_NAME)
STRING_TERMINATOR = b'\0'
WORD_MASK = 0xFFFFFFFF
OFFSET_OPS = {
    'jmp': ED9Opcode.JMP, 'jz': ED9Opcode.POP_JMP_ZERO, 'jnz': ED9Opcode.POP_JMP_NOT_ZERO,
    'frame': ED9Opcode.PUSH_CALLER_FRAME,
}
BYTE_OPERAND_OPS = {
    'pop': ED9Opcode.POP, 'get_reg': ED9Opcode.GET_REG, 'set_reg': ED9Opcode.SET_REG, 'debug_log': ED9Opcode.DEBUG_LOG,
}
NO_OPERAND_OPS = {
    'add': ED9Opcode.ADD, 'sub': ED9Opcode.SUB, 'mul': ED9Opcode.MUL, 'div': ED9Opcode.DIV, 'mod': ED9Opcode.MOD,
    'eq': ED9Opcode.EQ, 'ne': ED9Opcode.NE, 'gt': ED9Opcode.GT, 'ge': ED9Opcode.GE,
    'lt': ED9Opcode.LT, 'le': ED9Opcode.LE,
    'bitwise_and': ED9Opcode.BITWISE_AND, 'bitwise_or': ED9Opcode.BITWISE_OR,
    'logical_and': ED9Opcode.LOGICAL_AND, 'logical_or': ED9Opcode.LOGICAL_OR,
    'neg': ED9Opcode.NEG, 'ez': ED9Opcode.EZ, 'not_': ED9Opcode.NOT,       # not_: `not` is a keyword
    'ret': ED9Opcode.RETURN,
}
SCRIPT_CALL_OPS = {'call_script': ED9Opcode.CALL_SCRIPT, 'call_script_no_return': ED9Opcode.CALL_SCRIPT_NO_RETURN}
STACK_SLOT_OPS = {
    'load_stack': ED9Opcode.LOAD_STACK, 'load_stack_deref': ED9Opcode.LOAD_STACK_DEREF,
    'push_stack_offset': ED9Opcode.PUSH_STACK_OFFSET,
    'pop_to': ED9Opcode.POP_TO, 'pop_to_deref': ED9Opcode.POP_TO_DEREF,
}
OTHER_OPS = (
    'label', 'push_raw', 'push_int', 'push_float', 'push_str', 'load_global', 'set_global', 'call', 'syscall',
    'debug_set_lineno',
)
MNEMONICS = (*OFFSET_OPS, *BYTE_OPERAND_OPS, *NO_OPERAND_OPS, *SCRIPT_CALL_OPS, *STACK_SLOT_OPS, *OTHER_OPS)
PARAM_COUNT = 3


def word(value: int) -> bytes:
    return struct.pack('<I', value & WORD_MASK)


def scp_value(kind: ScpValue.Type, payload: int) -> bytes:
    return word(kind << ScpValue.TYPE_SHIFT | payload & ScpValue.PAYLOAD_MASK)


def measuring(value) -> int:
    '''Resolves any label or string to 0: only the encoded size matters when measuring'''
    return 0


class Asm:
    '''Hand-coded ED9 bytecode: labels resolve to offsets, strings to a pool after the code'''

    def __init__(self):
        self.items = []

    def __getattr__(self, name):
        if name not in MNEMONICS:
            raise AttributeError(name)

        return lambda *args: self.items.append((name, args))

    def size(self) -> int:
        return sum(len(self.encode(name, args, measuring, measuring)) for name, args in self.items)

    def assemble(self, base: int, strings: dict[str, int]) -> tuple[bytes, dict[str, int]]:
        labels = {}
        position = base
        for name, args in self.items:
            if name == 'label':
                labels[args[0]] = position

            position += len(self.encode(name, args, measuring, measuring))

        def resolve(value) -> int:
            return labels[value] if isinstance(value, str) else value

        code = b''.join(self.encode(name, args, resolve, strings.__getitem__) for name, args in self.items)
        return code, labels

    @classmethod
    def encode(cls, name: str, args: tuple, resolve, string_offset) -> bytes:
        match name:
            case 'label':
                return b''

            case 'push_raw':
                return bytes([ED9Opcode.PUSH, WORD_SIZE]) + word(resolve(args[0]))

            case 'push_int':
                return bytes([ED9Opcode.PUSH, WORD_SIZE]) + scp_value(ScpValue.Type.Integer, args[0])

            case 'push_float':
                return bytes([ED9Opcode.PUSH, WORD_SIZE]) + word(ScpValue(args[0]).to_word())

            case 'push_str':
                return bytes([ED9Opcode.PUSH, WORD_SIZE]) + scp_value(ScpValue.Type.String, string_offset(args[0]))

            case _ if name in STACK_SLOT_OPS:
                return bytes([STACK_SLOT_OPS[name]]) + struct.pack('<i', args[0])

            case 'load_global':
                return bytes([ED9Opcode.LOAD_GLOBAL]) + word(args[0])

            case 'set_global':
                return bytes([ED9Opcode.SET_GLOBAL]) + word(args[0])

            case 'call':
                return bytes([ED9Opcode.CALL]) + struct.pack('<H', args[0])

            case 'syscall':
                return bytes([ED9Opcode.SYSCALL, *args])            # subsystem, function, argument count

            case 'debug_set_lineno':
                return bytes([ED9Opcode.DEBUG_SET_LINENO]) + struct.pack('<H', args[0])

            case _ if name in OFFSET_OPS:
                return bytes([OFFSET_OPS[name]]) + word(resolve(args[0]))

            case _ if name in BYTE_OPERAND_OPS:
                return bytes([BYTE_OPERAND_OPS[name], args[0]])

            case _ if name in NO_OPERAND_OPS:
                return bytes([NO_OPERAND_OPS[name]])

            case _:
                strings = (scp_value(ScpValue.Type.String, string_offset(text)) for text in STRINGS)
                return bytes([SCRIPT_CALL_OPS[name]]) + b''.join(strings) + bytes([args[0]])


class Func(NamedTuple):
    name : str
    argc : int
    asm  : Asm


class Program:
    '''Hand-coded functions for a real ScpParser: code, then a string pool (the call strings, then the function names,
    as in a real script), then any trailing bytes. Labels are per function.'''

    def __init__(self, *functions: Func, trailing: bytes = b'', pool: tuple = STRINGS, aliases: tuple = ()):
        '''pool: the strings before the function names; aliases: (name, offset) function-table entries with no code'''
        position = sum(func.asm.size() for func in functions)
        strings = {}
        names = (*(func.name for func in functions), *(name for name, _ in aliases))
        for text in (*pool, *names):
            strings[text] = position
            position += len(text.encode()) + len(STRING_TERMINATOR)

        self.strings = strings

        self.trailing_offset = position
        code = bytearray()
        self.entries = []
        self.function_entries = []
        self.labels = {}
        for func in functions:
            blob, self.labels[func.name] = func.asm.assemble(len(code), strings)
            self.add_entry(func.name, len(code), func.argc)
            code += blob

        for name, offset in aliases:
            self.add_entry(name, offset)

        for text in strings:
            code += text.encode() + STRING_TERMINATOR

        self.code = bytes(code + trailing)

    def add_entry(self, name: str, offset: int, argc: int = 0):
        '''A function-table entry, numbered in table order as ScpParser._read_functions numbers them'''
        entry = Function()
        entry.index = len(self.entries)
        entry.name = name
        entry.offset = offset
        entry.is_common_func = False
        entry.params = [FunctionParam(ScpParamFlags(Value32)) for _ in range(argc)]
        self.entries.append(entry)
        table_entry = ScpFunctionEntry()
        table_entry.name_offset = ScpValue.Type.String << ScpValue.TYPE_SHIFT | self.strings[name]
        self.function_entries.append(table_entry)

    def parser(self, keep_unreachable_code: bool = False) -> ScpParser:
        fs = fileio.FileStream(encoding = default_encoding())
        fs.OpenMemory(self.code)
        parser = ScpParser(fs, 'test.dat')
        parser.functions = self.entries
        parser.function_entries = self.function_entries
        parser.function_map = {func.name: func for func in self.entries}
        parser.global_vars = []
        parser.round_trip = False
        parser.keep_unreachable_code = keep_unreachable_code
        return parser

    def disassemble(self, keep_unreachable_code: bool = False) -> tuple[ScpParser, list[Function]]:
        parser = self.parser(keep_unreachable_code)
        return parser, parser.disasm_all_functions()

    def label(self, name: str) -> int:
        '''The address of a label in the function named FUNC_NAME'''
        return self.labels[FUNC_NAME][name]


def main_function(asm: Asm) -> Func:
    return Func(FUNC_NAME, 0, asm)


def returning_callee(argc: int = 0) -> Func:
    callee = Asm()
    if argc:
        callee.pop(argc * WORD_SIZE)

    callee.ret()
    return Func(CALLEE_NAME, argc, callee)
