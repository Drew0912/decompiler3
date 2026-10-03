#!/usr/bin/env python3
'''Unit tests for the parser's disassembly-time stack simulation. Every edge into a
block must carry the same stack height; entries that meet at one position on a join form one group, and a call checks
and rewrites every push of the groups it consumes. Calls declare their own return edges. A push an ordinary consumer
uses or overwrites cannot also be a call setup, no instruction may overlap another (in any function), and code must end
before the string pool. Each function keeps the simulated stack's layout for comments.'''

from pathlib import Path
from typing import NamedTuple
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml import fileio
from common.config import default_encoding
from falcom.ed9.disasm import (
    BranchKind, Disassembler, DisassemblerContext, ED9_INSTRUCTION_TABLE, ED9Opcode, Formatter, FormatterContext,
)
from falcom.ed9.disasm.ed9_optable import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS, ed9_create_fallthrough_jump
from falcom.ed9.parser.scp import OPCODE_SIZE, ScpDisassemblerContext, ScpParser
from falcom.ed9.parser.types_parser import Function, FunctionParam, SlotRef, StackLayout
from falcom.ed9.parser.types_scp import ScpFunctionEntry, ScpParamFlags, ScpValue, Value32
from falcom.ed9.ir.llil import ED9VMLifter
from ir.llil.llil import WORD_SIZE


CALLER_ID = 0
CALLEE_ID = 1
GLOBAL_INDEX = 0
REG_INDEX = 0
LEFT_VALUE = 7
RIGHT_VALUE = 8
LOOP_LIMIT = 10
OUTSIDE_OFFSET = 0x1000
FUNC_NAME = 'f'
CALLEE_NAME = 'callee'
MODULE_NAME = 'this'
SCRIPT_FUNC_NAME = 'g'
STRINGS = (MODULE_NAME, SCRIPT_FUNC_NAME)
STRING_TERMINATOR = b'\0'
WORD_MASK = 0xFFFFFFFF
RETURN_STRING = '\r'                                # its first byte decodes as RETURN
OFFSET_OPS = {
    'jmp': ED9Opcode.JMP, 'jz': ED9Opcode.POP_JMP_ZERO, 'jnz': ED9Opcode.POP_JMP_NOT_ZERO,
    'frame': ED9Opcode.PUSH_CALLER_FRAME,
}
BYTE_OPERAND_OPS = {'pop': ED9Opcode.POP, 'get_reg': ED9Opcode.GET_REG, 'set_reg': ED9Opcode.SET_REG}
NO_OPERAND_OPS = {'add': ED9Opcode.ADD, 'lt': ED9Opcode.LT, 'ret': ED9Opcode.RETURN}
SCRIPT_CALL_OPS = {'call_script': ED9Opcode.CALL_SCRIPT, 'call_script_no_return': ED9Opcode.CALL_SCRIPT_NO_RETURN}
STACK_SLOT_OPS = {
    'load_stack': ED9Opcode.LOAD_STACK, 'load_stack_deref': ED9Opcode.LOAD_STACK_DEREF,
    'push_stack_offset': ED9Opcode.PUSH_STACK_OFFSET,
    'pop_to': ED9Opcode.POP_TO, 'pop_to_deref': ED9Opcode.POP_TO_DEREF,
}
OTHER_OPS = ('label', 'push_raw', 'push_int', 'push_str', 'set_global', 'call')
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

            case 'push_str':
                return bytes([ED9Opcode.PUSH, WORD_SIZE]) + scp_value(ScpValue.Type.String, string_offset(args[0]))

            case _ if name in STACK_SLOT_OPS:
                return bytes([STACK_SLOT_OPS[name]]) + struct.pack('<i', args[0])

            case 'set_global':
                return bytes([ED9Opcode.SET_GLOBAL]) + word(args[0])

            case 'call':
                return bytes([ED9Opcode.CALL]) + struct.pack('<H', args[0])

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
            entry = Function()
            entry.name = func.name
            entry.offset = len(code)
            entry.is_common_func = False
            entry.params = [FunctionParam(ScpParamFlags(Value32)) for _ in range(func.argc)]
            self.entries.append(entry)
            table_entry = ScpFunctionEntry()
            table_entry.name_offset = ScpValue.Type.String << ScpValue.TYPE_SHIFT | strings[func.name]
            self.function_entries.append(table_entry)
            code += blob

        for name, offset in aliases:
            entry = Function()
            entry.name = name
            entry.offset = offset
            entry.is_common_func = False
            self.entries.append(entry)
            table_entry = ScpFunctionEntry()
            table_entry.name_offset = ScpValue.Type.String << ScpValue.TYPE_SHIFT | strings[name]
            self.function_entries.append(table_entry)

        for text in strings:
            code += text.encode() + STRING_TERMINATOR

        self.code = bytes(code + trailing)

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

    def label(self, name: str, func: str = FUNC_NAME) -> int:
        return self.labels[func][name]


def main_function(asm: Asm) -> Func:
    return Func(FUNC_NAME, 0, asm)


def returning_callee(argc: int = 0) -> Func:
    callee = Asm()
    if argc:
        callee.pop(argc * WORD_SIZE)

    callee.ret()
    return Func(CALLEE_NAME, argc, callee)


def assert_rejected(test: unittest.TestCase, *functions: Func):
    with test.assertRaises(ValueError):
        Program(*functions).disassemble()


def blocks_by_offset_of(entry_block) -> dict:
    return {block.offset: block for block in Formatter.collect_blocks(entry_block)}


def blocks_by_offset(func: Function) -> dict:
    return blocks_by_offset_of(func.entry_block)


def successors(block) -> list[int]:
    return [succ.offset for succ in block.succs]


def lift_all(parser: ScpParser, functions: list[Function]):
    for func in functions:
        ED9VMLifter(parser = parser).lift_function(func)


class TestEdgeStates(unittest.TestCase):
    '''Every edge into a block carries the same stack height'''

    def test_join_with_different_heights_raises(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('right')
        asm.push_int(LEFT_VALUE); asm.jmp('join')
        asm.label('right'); asm.jmp('join')
        asm.label('join'); asm.pop(WORD_SIZE); asm.ret()
        assert_rejected(self, main_function(asm))

    def test_fall_through_with_a_different_height_raises(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('target')
        asm.push_int(LEFT_VALUE)                            # falls through into 'target' one entry higher
        asm.label('target'); asm.ret()
        assert_rejected(self, main_function(asm))

    def test_branch_into_a_decoded_block_with_a_different_height_raises(self):
        asm = Asm()
        asm.get_reg(REG_INDEX)
        asm.label('middle'); asm.set_reg(REG_INDEX); asm.get_reg(REG_INDEX); asm.jz('end')
        asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE); asm.jmp('middle')     # splits the entry block
        asm.label('end'); asm.ret()
        assert_rejected(self, main_function(asm))

    def test_value_carried_across_a_join_is_accepted(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('right')
        asm.push_int(LEFT_VALUE); asm.jmp('join')
        asm.label('right'); asm.push_int(RIGHT_VALUE); asm.jmp('join')
        asm.label('join'); asm.set_global(GLOBAL_INDEX); asm.ret()
        parser, functions = Program(main_function(asm)).disassemble()
        lift_all(parser, functions)

    def test_loop_back_edge_with_the_same_height_is_accepted(self):
        asm = Asm()
        asm.push_int(0); asm.set_reg(REG_INDEX)
        asm.label('head'); asm.get_reg(REG_INDEX); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('end')
        asm.get_reg(REG_INDEX); asm.push_int(1); asm.add(); asm.set_reg(REG_INDEX); asm.jmp('head')
        asm.label('end'); asm.ret()
        parser, functions = Program(main_function(asm)).disassemble()
        lift_all(parser, functions)

    def test_pop_below_the_stack_raises(self):
        asm = Asm()
        asm.pop(WORD_SIZE); asm.ret()
        assert_rejected(self, main_function(asm))

    def test_pop_of_a_partial_slot_raises(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.pop(WORD_SIZE // 2); asm.pop(WORD_SIZE // 2); asm.ret()
        assert_rejected(self, main_function(asm))

    @classmethod
    def disassemble_keeping_context(cls, asm: Asm) -> tuple[Program, Function, ScpDisassemblerContext]:
        '''Disassemble the single function with a context the test keeps, to audit its recorded edges'''
        program = Program(main_function(asm))
        parser = program.parser()
        func = program.entries[0]
        context = parser.disasm_context(CALLER_ID, code_end = None)
        disassembler = Disassembler(ED9_INSTRUCTION_TABLE, context)
        func.entry_block = disassembler.disasm_function(parser.fs, offset = func.offset, name = func.name)
        return program, func, context

    def test_unrecorded_cfg_edge_is_reported(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('end')
        asm.label('end'); asm.ret()
        program, func, context = self.disassemble_keeping_context(asm)
        ScpParser.require_recorded_edges(func, context)     # every edge went through the hooks

        blocks_by_offset(func)[program.label('end')].add_branch(func.entry_block)     # one that did not
        with self.assertRaises(ValueError):
            ScpParser.require_recorded_edges(func, context)

    def test_audit_counts_each_kind_of_edge(self):
        '''A conditional whose true and false targets are one block has two edges there, not one'''
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('same')
        asm.label('same'); asm.ret()
        _, func, context = self.disassemble_keeping_context(asm)
        ScpParser.require_recorded_edges(func, context)

        branch = next(key for key in context.recorded_edges if key[2] == BranchKind.FALSE)
        context.recorded_edges.remove(branch)                    # as if the false edge had bypassed the hook
        with self.assertRaises(ValueError):
            ScpParser.require_recorded_edges(func, context)


class TestInstructionBounds(unittest.TestCase):
    '''No instruction may overlap another, no target may land inside one, and code must end before the string pool'''

    def test_branch_into_the_middle_of_an_instruction_raises(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE)
        asm.jmp(WORD_SIZE // 2)                             # inside the PUSH at 0
        assert_rejected(self, main_function(asm))

    def test_instruction_covering_a_branch_target_raises(self):
        '''The target is recorded first; the instruction that covers it is decoded later'''
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz(0)
        asm.label('push'); asm.push_int(LEFT_VALUE); asm.ret()
        target = Program(main_function(asm)).label('push') + WORD_SIZE // 2      # inside the PUSH

        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz(target)
        asm.push_int(LEFT_VALUE); asm.ret()
        assert_rejected(self, main_function(asm))

    def test_return_into_the_call_itself_raises(self):
        '''The return address is the CALL's own operand byte, which would decode as an overlapping instruction'''
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('call'); caller.label('call'); caller.call(CALLEE_ID); caller.ret()
        program = Program(main_function(caller), returning_callee())
        target = program.label('call') + OPCODE_SIZE

        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw(target); caller.call(CALLEE_ID); caller.ret()
        assert_rejected(self, main_function(caller), returning_callee())

    def test_return_past_the_end_of_the_code_raises(self):
        '''The last function has no next function to bound it: the string pool does'''
        callee_id, last_id = 0, 1
        callee = Asm()
        callee.ret()

        def program_returning_to(target: int) -> Program:
            last = Asm()
            last.push_raw(last_id); last.push_raw(target); last.call(callee_id)
            trailing = bytes([ED9Opcode.RETURN])            # decodes, but lies after the string pool
            return Program(Func(CALLEE_NAME, 0, callee), Func(FUNC_NAME, 0, last), trailing = trailing)

        program = program_returning_to(program_returning_to(0).trailing_offset)
        with self.assertRaises(ValueError):
            program.disassemble()


    def test_function_starting_inside_another_functions_instruction_raises(self):
        '''Each function has its own Disassembler, so this is checked across functions afterwards'''
        asm = Asm()
        asm.push_raw(ED9Opcode.RETURN); asm.pop(WORD_SIZE); asm.ret()
        inside = WORD_SIZE // 2                             # the PUSH's operand, whose first byte decodes as RETURN
        with self.assertRaises(ValueError):
            Program(main_function(asm), aliases = (('inner', inside),)).disassemble()

    def test_function_sharing_another_functions_start_is_accepted(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.pop(WORD_SIZE); asm.ret()
        parser, functions = Program(main_function(asm), aliases = (('alias', 0),)).disassemble()
        lift_all(parser, functions)

    def test_return_into_a_string_only_dead_code_references(self):
        '''The pool is known only from references: kept unreachable code bounds it, undecoded dead code cannot'''
        callee_id, last_id = 0, 1
        pool = (RETURN_STRING, *STRINGS)                    # the pool's first string starts with a RETURN byte
        callee = Asm()
        callee.ret()

        def program_returning_to(target: int) -> Program:
            last = Asm()
            last.push_raw(last_id); last.push_raw(target); last.call(callee_id)
            last.push_str(RETURN_STRING); last.ret()        # dead: the only reference to that string
            return Program(Func(CALLEE_NAME, 0, callee), Func(FUNC_NAME, 0, last), pool = pool)

        target = program_returning_to(0).strings[RETURN_STRING]
        with self.subTest(keep_unreachable_code = True):
            with self.assertRaises(ValueError):
                program_returning_to(target).disassemble(keep_unreachable_code = True)

        with self.subTest(keep_unreachable_code = False):
            program_returning_to(target).disassemble()      # documented gap: the dead reference is never decoded


class TestPlainUses(unittest.TestCase):
    '''A push an ordinary consumer reads or discards on any path cannot be a call setup or caller frame'''

    def test_push_used_plainly_and_as_a_setup_raises_in_either_decode_order(self):
        for plain_arm_first in (True, False):
            with self.subTest(plain_arm_first = plain_arm_first):
                caller = Asm()
                caller.push_raw(CALLER_ID); caller.get_reg(REG_INDEX); caller.jz('second')
                arms = [
                    lambda: (caller.set_global(GLOBAL_INDEX), caller.ret()),
                    lambda: (caller.push_raw('return'), caller.call(CALLEE_ID), caller.label('return'), caller.ret()),
                ]
                if not plain_arm_first:
                    arms.reverse()

                arms[0]()
                caller.label('second'); arms[1]()
                assert_rejected(self, main_function(caller), returning_callee())

    def test_discarded_caller_frame_raises(self):
        caller = Asm()
        caller.frame('return'); caller.pop(CALLER_FRAME_SLOTS * WORD_SIZE); caller.ret()
        caller.label('return'); caller.ret()
        assert_rejected(self, main_function(caller))

    def test_setup_overwritten_on_one_arm_raises(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('return')
        caller.get_reg(REG_INDEX); caller.jz('join')
        caller.push_int(LEFT_VALUE); caller.pop_to(-WORD_SIZE)       # overwrites the return address on this arm
        caller.label('join'); caller.call(CALLEE_ID); caller.label('return'); caller.ret()
        assert_rejected(self, main_function(caller), returning_callee())

    def test_overwritten_caller_frame_raises(self):
        caller = Asm()
        caller.frame('return'); caller.push_int(LEFT_VALUE); caller.pop_to(-WORD_SIZE)    # overwrites a frame slot
        caller.pop(CALLER_FRAME_SLOTS * WORD_SIZE); caller.ret()
        caller.label('return'); caller.ret()
        with self.assertRaisesRegex(ValueError, 'discards caller frame slot'):
            Program(main_function(caller)).disassemble()

    def test_setup_overwritten_on_the_branch_that_does_not_call_raises_in_either_decode_order(self):
        for overwrite_arm_first in (True, False):
            with self.subTest(overwrite_arm_first = overwrite_arm_first):
                caller = Asm()
                caller.push_raw(CALLER_ID); caller.push_raw('return'); caller.get_reg(REG_INDEX); caller.jz('second')
                arms = [
                    lambda: (
                        caller.push_int(LEFT_VALUE), caller.pop_to(-WORD_SIZE),
                        caller.pop(LOCAL_SETUP_SLOTS * WORD_SIZE), caller.ret(),
                    ),
                    lambda: (caller.call(CALLEE_ID), caller.label('return'), caller.ret()),
                ]
                if not overwrite_arm_first:
                    arms.reverse()

                arms[0]()
                caller.label('second'); arms[1]()
                assert_rejected(self, main_function(caller), returning_callee())


class TestLocalCalls(unittest.TestCase):
    '''PUSH(func_id) PUSH(ret_addr) args... CALL'''

    def call_program(self, setup) -> Program:
        caller = Asm()
        setup(caller)
        caller.call(CALLEE_ID); caller.label('return'); caller.ret()
        return Program(main_function(caller), returning_callee())

    def test_setup_is_rewritten_and_the_return_edge_added(self):
        program = self.call_program(lambda asm: (asm.push_raw(CALLER_ID), asm.push_raw('return')))
        parser, functions = program.disassemble()
        func = functions[0]

        mnemonics = [inst.mnemonic for inst in parser.get_instructions(func)]
        self.assertEqual(mnemonics[:LOCAL_SETUP_SLOTS], ['PUSH_CURRENT_FUNC_ID', 'PUSH_RET_ADDR'])
        self.assertIn(program.label('return'), blocks_by_offset(func))
        lift_all(parser, functions)

    def test_call_with_too_few_entries_raises(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('return'); caller.call(CALLEE_ID)    # the callee takes one arg
        caller.label('return'); caller.ret()
        assert_rejected(self, main_function(caller), returning_callee(argc = 1))

    def test_function_id_of_another_function_raises(self):
        with self.assertRaises(ValueError):
            self.call_program(lambda asm: (asm.push_raw(CALLEE_ID), asm.push_raw('return'))).disassemble()

    def test_function_id_that_is_not_a_push_raises(self):
        with self.assertRaises(ValueError):
            self.call_program(lambda asm: (asm.get_reg(REG_INDEX), asm.push_raw('return'))).disassemble()

    def test_typed_return_address_push_raises(self):
        '''Rewriting a PUSH_INT to PUSH_RET_ADDR would change its bytes on recompile'''
        with self.assertRaises(ValueError):
            self.call_program(lambda asm: (asm.push_raw(CALLER_ID), asm.push_int(0))).disassemble()

    def test_overwritten_return_address_raises(self):
        def setup(asm):
            asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.push_int(LEFT_VALUE)
            asm.pop_to(-WORD_SIZE)                          # overwrites the return address

        with self.assertRaises(ValueError):
            self.call_program(setup).disassemble()

    def test_return_address_past_dead_code_is_the_return_edge(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('resume'); caller.call(CALLEE_ID)
        caller.ret()                                        # dead: the callee returns to 'resume'
        caller.label('resume'); caller.ret()
        program = Program(main_function(caller), returning_callee())
        parser, functions = program.disassemble()

        self.assertEqual(successors(functions[0].entry_block), [program.label('resume')])
        lift_all(parser, functions)

    def test_return_address_outside_the_function_raises(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw(OUTSIDE_OFFSET); caller.call(CALLEE_ID); caller.ret()
        assert_rejected(self, main_function(caller), returning_callee())

    def test_equal_setups_on_both_branches_are_rewritten(self):
        caller = Asm()
        caller.get_reg(REG_INDEX); caller.jz('right')
        caller.push_raw(CALLER_ID); caller.push_raw('return'); caller.jmp('join')
        caller.label('right'); caller.push_raw(CALLER_ID); caller.push_raw('return'); caller.jmp('join')
        caller.label('join'); caller.call(CALLEE_ID); caller.label('return'); caller.ret()
        parser, functions = Program(main_function(caller), returning_callee()).disassemble()

        rewritten = [
            inst.mnemonic for inst in parser.get_instructions(functions[0])
            if inst.opcode in (ED9Opcode.PUSH_CURRENT_FUNC_ID, ED9Opcode.PUSH_RET_ADDR)
        ]
        self.assertEqual(rewritten, ['PUSH_CURRENT_FUNC_ID', 'PUSH_RET_ADDR'] * 2)
        lift_all(parser, functions)

    def test_setup_meeting_plain_values_raises_in_either_decode_order(self):
        '''The fall-through arm is decoded first: once the call consumes the setup before the plain values arrive,
        once the plain values meet the call first'''
        for setup_arm_first in (True, False):
            with self.subTest(setup_arm_first = setup_arm_first):
                caller = Asm()
                caller.get_reg(REG_INDEX); caller.jz('second')
                arms = [
                    lambda: (caller.push_raw(CALLER_ID), caller.push_raw('return')),
                    lambda: (caller.push_int(LEFT_VALUE), caller.push_int(RIGHT_VALUE)),
                ]
                if not setup_arm_first:
                    arms.reverse()

                arms[0](); caller.jmp('join')
                caller.label('second'); arms[1](); caller.jmp('join')
                caller.label('join'); caller.call(CALLEE_ID); caller.label('return'); caller.ret()
                assert_rejected(self, main_function(caller), returning_callee())


class TestScriptCalls(unittest.TestCase):
    '''PUSH_CALLER_FRAME(return) args... CALL_SCRIPT'''

    def test_return_edge_leaves_the_call_script_block(self):
        '''A local call among the args ends the frame's block before CALL_SCRIPT'''
        caller = Asm()
        caller.frame('return')
        caller.push_raw(CALLER_ID); caller.push_raw('arg_ready'); caller.call(CALLEE_ID)
        caller.label('arg_ready'); caller.get_reg(REG_INDEX); caller.call_script(1)
        caller.label('return'); caller.ret()
        program = Program(main_function(caller), returning_callee())
        parser, functions = program.disassemble()

        blocks = blocks_by_offset(functions[0])
        self.assertNotIn(program.label('return'), successors(functions[0].entry_block))
        self.assertIn(program.label('return'), successors(blocks[program.label('arg_ready')]))
        lift_all(parser, functions)

    def test_frame_returning_past_dead_code_is_the_return_edge(self):
        caller = Asm()
        caller.frame('resume'); caller.push_int(LEFT_VALUE); caller.call_script(1)
        caller.ret()                                        # dead
        caller.label('resume'); caller.ret()
        program = Program(main_function(caller))
        parser, functions = program.disassemble()

        self.assertEqual(successors(functions[0].entry_block), [program.label('resume')])
        lift_all(parser, functions)

    def test_call_script_without_a_frame_raises(self):
        caller = Asm()
        for _ in range(CALLER_FRAME_SLOTS):
            caller.push_int(LEFT_VALUE)                     # a frame's height, but no frame

        caller.push_int(RIGHT_VALUE); caller.call_script(1); caller.ret()
        assert_rejected(self, main_function(caller))

    def test_pop_reaching_into_the_frame_raises(self):
        caller = Asm()
        caller.frame('return'); caller.push_int(LEFT_VALUE)
        caller.pop(2 * WORD_SIZE)                           # the arg and one frame slot
        caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE); caller.call_script(1)
        caller.label('return'); caller.ret()
        assert_rejected(self, main_function(caller))

    def test_tail_call_leaving_entries_below_its_args_raises(self):
        caller = Asm()
        caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE); caller.call_script_no_return(1)
        assert_rejected(self, main_function(caller))

    def test_plain_disassembler_keeps_the_frame_edge(self):
        '''Without the parser nothing simulates calls, so PUSH_CALLER_FRAME still declares its return block'''
        caller = Asm()
        caller.frame('return'); caller.call_script(0)
        caller.label('return'); caller.ret()
        program = Program(main_function(caller))

        context = DisassemblerContext(create_fallthrough_jump = ed9_create_fallthrough_jump)
        func = program.entries[0]
        func.entry_block = Disassembler(ED9_INSTRUCTION_TABLE, context).disasm_function(program.code, name = FUNC_NAME)

        self.assertIn(program.label('return'), blocks_by_offset(func))
        Formatter(FormatterContext()).format_function(func)


class TestBlockSplits(unittest.TestCase):
    '''A branch into a decoded block splits it; the tail takes the terminator and its edges'''

    def self_split_program(self) -> Program:
        '''A do-while starting inside the entry block: its back edge splits the block being decoded'''
        asm = Asm()
        asm.push_int(0); asm.set_reg(REG_INDEX)
        asm.label('loop'); asm.get_reg(REG_INDEX); asm.push_int(1); asm.add(); asm.set_reg(REG_INDEX)
        asm.get_reg(REG_INDEX); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jnz('loop')
        asm.label('end'); asm.ret()
        return Program(main_function(asm))

    def test_branch_into_the_block_being_decoded_moves_its_edges_to_the_tail(self):
        program = self.self_split_program()
        parser, functions = program.disassemble()
        tail = blocks_by_offset(functions[0])[program.label('loop')]

        self.assertEqual([succ.offset for succ in tail.true_succs], [program.label('loop')])
        self.assertEqual([succ.offset for succ in tail.false_succs], [program.label('end')])
        lift_all(parser, functions)

    def test_plain_backward_frame_target_keeps_the_call_in_the_tail(self):
        '''Plain context: a caller frame returning into its own block splits it while it is decoded; the instructions
        after the split belong to the tail, not after the head's synthetic JMP'''
        caller = Asm()
        caller.push_int(0)
        caller.label('back'); caller.set_reg(REG_INDEX); caller.frame('back'); caller.call_script(0)
        program = Program(main_function(caller))

        context = DisassemblerContext(create_fallthrough_jump = ed9_create_fallthrough_jump)
        entry = Disassembler(ED9_INSTRUCTION_TABLE, context).disasm_function(program.code, name = FUNC_NAME)
        tail = blocks_by_offset_of(entry)[program.label('back')]

        self.assertEqual(entry.instructions[-1].opcode, ED9Opcode.JMP)
        self.assertEqual(tail.instructions[-1].opcode, ED9Opcode.CALL_SCRIPT)

    def test_split_keeps_preds_in_step_with_succs(self):
        parser, functions = self.self_split_program().disassemble()

        for block in Formatter.collect_blocks(functions[0].entry_block):
            for succ in block.succs:
                self.assertIn(block, succ.preds)

            for pred in block.preds:
                self.assertIn(block, pred.succs)


class TestStackLayout(unittest.TestCase):
    '''The layout the parser keeps on each function: the depth before every instruction, and the slot each offset
    opcode addresses with what may stand there at that point'''

    @classmethod
    def layout_of(cls, asm: Asm, argc: int = 0, *others: Func) -> tuple[Program, StackLayout]:
        '''The layout of the function asm assembles, with argc parameters, laid out before the others'''
        program = Program(Func(FUNC_NAME, argc, asm), *others)
        _, functions = program.disassemble()
        return program, functions[0].stack_layout

    def test_offset_opcodes_number_parameters_from_the_highest_slot(self):
        asm = Asm()
        asm.label('read'); asm.load_stack(-WORD_SIZE)                  # sp 3: slot 2
        asm.push_int(LEFT_VALUE)
        asm.label('address'); asm.push_stack_offset(-4 * WORD_SIZE)    # sp 5: slot 1
        asm.label('deref'); asm.load_stack_deref(-6 * WORD_SIZE)       # sp 6: slot 0
        asm.pop((PARAM_COUNT + 4) * WORD_SIZE); asm.ret()              # the parameters and the 4 values pushed
        program, layout = self.layout_of(asm, PARAM_COUNT)

        refs = {name: layout.slot_refs[program.label(name)] for name in ('read', 'address', 'deref')}
        self.assertEqual(refs, {
            'read': SlotRef(2, params = (1,)), 'address': SlotRef(1, params = (2,)), 'deref': SlotRef(0, params = (3,)),
        })

    def test_pop_to_counts_from_sp_after_its_pop(self):
        asm = Asm()
        asm.label('open'); asm.push_raw(0)
        asm.push_int(LEFT_VALUE)
        asm.label('write'); asm.pop_to(-WORD_SIZE)                     # sp 2, 1 after its pop: slot 0
        asm.pop(WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(layout.slot_refs[program.label('write')], SlotRef(0, local = True))
        self.assertEqual(layout.local_slots, {program.label('open'): 0})     # not the PUSH_INT it popped

    def test_parameter_reassigned_by_pop_to_stays_the_parameter_in_either_decode_order(self):
        '''Decoded first, the writing arm leaves its POP_TO in the read's state; decoded second, its POP_TO reaches the
        read through the join's solved block start'''
        for write_arm_first in (True, False):
            with self.subTest(write_arm_first = write_arm_first):
                asm = Asm()
                asm.get_reg(REG_INDEX); asm.jz('second')
                arms = [lambda: (asm.push_int(LEFT_VALUE), asm.pop_to(-WORD_SIZE)), lambda: ()]
                if not write_arm_first:
                    arms.reverse()

                arms[0](); asm.jmp('join')
                asm.label('second'); arms[1](); asm.jmp('join')
                asm.label('join'); asm.load_stack(-WORD_SIZE)
                asm.pop(2 * WORD_SIZE); asm.ret()
                program, layout = self.layout_of(asm, 1)

                self.assertEqual(layout.slot_refs[program.label('join')], SlotRef(0, params = (1,)))
                self.assertEqual(layout.local_slots, {})

    def test_parameter_slot_popped_and_pushed_again_is_a_local(self):
        asm = Asm()
        asm.pop(WORD_SIZE)
        asm.label('open'); asm.push_int(LEFT_VALUE)
        asm.label('read'); asm.load_stack(-WORD_SIZE)
        asm.pop(2 * WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm, 1)

        self.assertEqual(layout.slot_refs[program.label('read')], SlotRef(0, local = True))
        self.assertEqual(layout.local_slots, {program.label('open'): 0})

    def test_writes_on_both_arms_resolve_to_the_one_opening_push(self):
        asm = Asm()
        asm.label('open'); asm.push_raw(0)
        asm.get_reg(REG_INDEX); asm.jz('right')
        asm.push_int(LEFT_VALUE); asm.pop_to(-WORD_SIZE); asm.jmp('join')
        asm.label('right'); asm.push_int(RIGHT_VALUE); asm.pop_to(-WORD_SIZE); asm.jmp('join')
        asm.label('join'); asm.load_stack(-WORD_SIZE)
        asm.pop(2 * WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(set(layout.slot_refs.values()), {SlotRef(0, local = True)})
        self.assertEqual(layout.local_slots, {program.label('open'): 0})

    def test_join_of_two_pushes_keeps_both_openers(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('right')
        asm.label('left'); asm.push_int(LEFT_VALUE); asm.jmp('join')
        asm.label('right'); asm.push_int(RIGHT_VALUE); asm.jmp('join')
        asm.label('join'); asm.load_stack(-WORD_SIZE)
        asm.pop(2 * WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(layout.slot_refs[program.label('join')], SlotRef(0, local = True))
        self.assertEqual(layout.local_slots, {program.label('left'): 0, program.label('right'): 0})

    def test_back_edge_into_a_split_block_brings_its_value(self):
        '''The back edge is recorded before the split it causes, so the loop head's first recorded state is the back
        edge's, while the head's instructions were simulated with the fall-through's'''
        asm = Asm()
        asm.label('open'); asm.push_int(LEFT_VALUE)
        asm.label('head'); asm.load_stack(-WORD_SIZE); asm.pop(WORD_SIZE)
        asm.get_reg(REG_INDEX); asm.jz('end')
        asm.pop(WORD_SIZE); asm.label('new'); asm.push_int(RIGHT_VALUE); asm.jmp('head')
        asm.label('end'); asm.pop(WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(layout.slot_refs[program.label('head')], SlotRef(0, local = True))
        self.assertEqual(layout.local_slots, {program.label('open'): 0, program.label('new'): 0})

    def test_value_meeting_a_slot_at_a_later_join_does_not_count_for_an_earlier_read(self):
        '''The parser's join groups span the whole function; what a read may see is solved per program point'''
        asm = Asm()
        asm.label('open'); asm.push_int(LEFT_VALUE)
        asm.label('read'); asm.load_stack(-WORD_SIZE); asm.pop(WORD_SIZE)
        asm.get_reg(REG_INDEX); asm.jz('replace'); asm.jmp('join')
        asm.label('replace'); asm.pop(WORD_SIZE); asm.push_int(RIGHT_VALUE); asm.jmp('join')    # never addressed
        asm.label('join'); asm.pop(WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(layout.slot_refs[program.label('read')], SlotRef(0, local = True))
        self.assertEqual(layout.local_slots, {program.label('open'): 0})

    def test_pop_to_in_a_loop_resolves_to_the_opening_push(self):
        def while_loop(asm: Asm):
            asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('end')
            asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
            asm.label('end')

        def do_while_loop(asm: Asm):
            asm.label('body'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
            asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jnz('body')    # splits the entry block

        for loop in (while_loop, do_while_loop):
            with self.subTest(loop = loop.__name__):
                asm = Asm()
                asm.label('open'); asm.push_raw(0)
                loop(asm)
                asm.load_stack(-WORD_SIZE); asm.pop(2 * WORD_SIZE); asm.ret()
                program, layout = self.layout_of(asm)

                self.assertEqual(set(layout.slot_refs.values()), {SlotRef(0, local = True)})
                self.assertEqual(layout.local_slots, {program.label('open'): 0})

    def test_pop_to_deref_counts_from_sp_after_its_pop_and_keeps_the_slot(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE)
        asm.label('store'); asm.pop_to_deref(-WORD_SIZE)               # sp 2, 1 after its pop: slot 0
        asm.label('read'); asm.load_stack(-WORD_SIZE)                  # it stored through the pointer, not into slot 0
        asm.pop(2 * WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm, 1)

        refs = [layout.slot_refs[program.label(name)] for name in ('store', 'read')]
        self.assertEqual(refs, [SlotRef(0, params = (1,))] * 2)

    def test_local_put_by_an_instruction_that_is_not_a_push(self):
        asm = Asm()
        asm.label('open'); asm.get_reg(REG_INDEX)
        asm.label('read'); asm.load_stack(-WORD_SIZE)
        asm.pop(2 * WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(layout.slot_refs[program.label('read')], SlotRef(0, local = True))
        self.assertEqual(layout.local_slots, {program.label('open'): 0})

    def test_slot_opened_twice_keeps_both_openers(self):
        asm = Asm()
        asm.label('first'); asm.push_int(LEFT_VALUE); asm.load_stack(-WORD_SIZE); asm.pop(2 * WORD_SIZE)
        asm.label('second'); asm.push_int(RIGHT_VALUE); asm.load_stack(-WORD_SIZE); asm.pop(2 * WORD_SIZE)
        asm.ret()
        program, layout = self.layout_of(asm)

        self.assertEqual(layout.local_slots, {program.label('first'): 0, program.label('second'): 0})

    def test_slots_outside_the_live_stack_are_empty(self):
        asm = Asm()
        asm.label('below'); asm.load_stack(-WORD_SIZE)                 # sp 0: slot -1
        asm.label('at_sp'); asm.load_stack(0)                          # sp 1: slot 1
        asm.label('dead_store'); asm.pop_to(0)                         # sp 2, 1 after its pop: slot 1
        asm.pop(WORD_SIZE); asm.ret()
        program, layout = self.layout_of(asm)

        refs = {name: layout.slot_refs[program.label(name)] for name in ('below', 'at_sp', 'dead_store')}
        self.assertEqual(refs, {'below': SlotRef(-1), 'at_sp': SlotRef(1), 'dead_store': SlotRef(1)})
        self.assertEqual(layout.local_slots, {})

    def test_call_setup_and_caller_frame_slots(self):
        setup = Asm()
        setup.push_raw(CALLER_ID); setup.push_raw('return')
        setup.label('read_id'); setup.load_stack(-2 * WORD_SIZE); setup.pop(WORD_SIZE)      # the function ID
        setup.label('read_return'); setup.load_stack(-WORD_SIZE); setup.pop(WORD_SIZE)      # the return address
        setup.call(CALLEE_ID); setup.label('return'); setup.ret()
        program, layout = self.layout_of(setup, 0, returning_callee())
        refs = [layout.slot_refs[program.label(name)] for name in ('read_id', 'read_return')]
        self.assertEqual(refs, [SlotRef(0, call_setup = True), SlotRef(1, call_setup = True)])

        frame = Asm()
        frame.frame('return')
        frame.label('read'); frame.load_stack(-WORD_SIZE); frame.pop(WORD_SIZE)      # the frame's top slot
        frame.call_script(0); frame.label('return'); frame.ret()
        program, layout = self.layout_of(frame)
        self.assertEqual(layout.slot_refs[program.label('read')], SlotRef(CALLER_FRAME_SLOTS - 1, caller_frame = True))

    def test_depth_before_every_instruction(self):
        '''A label's depth too. The fall-through into 'next' gets a synthetic JMP one byte before the ADD, inside the
        PUSH_INT, with no recorded state: it gets no entry'''
        asm = Asm()
        asm.label('push'); asm.push_int(LEFT_VALUE)
        asm.label('reg'); asm.get_reg(REG_INDEX)
        asm.label('branch'); asm.jz('next')
        asm.label('push_right'); asm.push_int(RIGHT_VALUE)
        asm.label('add'); asm.add()
        asm.label('next'); asm.set_reg(REG_INDEX)
        asm.label('ret'); asm.ret()
        program, layout = self.layout_of(asm)

        depths = {'push': 0, 'reg': 1, 'branch': 2, 'push_right': 1, 'add': 2, 'next': 1, 'ret': 0}
        self.assertEqual(layout.sp_before, {program.label(name): depth for name, depth in depths.items()})


if __name__ == '__main__':
    unittest.main()
