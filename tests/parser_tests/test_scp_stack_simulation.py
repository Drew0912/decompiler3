#!/usr/bin/env python3
'''Unit tests for the parser's disassembly-time stack simulation. Every edge into a
block must carry the same stack height; entries that meet at one position on a join form one group, and a call checks
and rewrites every push of the groups it consumes. Calls declare their own return edges. A push an ordinary consumer
uses or overwrites cannot also be a call setup, no instruction may overlap another (in any function), and code must end
before the string pool. Each function keeps the simulated stack's layout for comments; an unusual slot is logged.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.logging import log
from falcom.ed9.disasm import (
    Disassembler, DisassemblerContext, ED9_INSTRUCTION_TABLE, ED9Opcode, Formatter, FormatterContext,
)
from falcom.ed9.disasm.ed9_optable import ed9_create_fallthrough_jump
from falcom.ed9.disasm.stack_effects import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS
from falcom.ed9.parser.scp import OPCODE_SIZE, ScpDisassemblyError, ScpParser
from falcom.ed9.parser.types_parser import Function, SlotRef, StackLayout
from falcom.ed9.parser.types_scp import ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpValue
from falcom.ed9.ir.llil import ED9VMLifter
from ir.llil.llil import WORD_SIZE
from tests.shared.scp_asm import (
    CALLEE_ID, CALLEE_NAME, CALLER_ID, FUNC_NAME, GLOBAL_INDEX, LEFT_VALUE, PARAM_COUNT, REG_INDEX, RIGHT_VALUE,
    STRINGS, SYSCALL_FUNC, SYSCALL_SUBSYSTEM, Asm, Func, Program, debug_records, main_function, returning_callee,
)

ArgType = ScpFunctionCallDebugInfoArg.Type
CallType = ScpFunctionCallDebugInfo.CallType
LOOP_LIMIT = 10
OUTSIDE_OFFSET = 0x1000
EARLIER_FUNCTION_START = 0                          # the first function's code, before the main one
BACKWARD_RETURN_TEXT = 'at or before the call, so it loops back there (a stale return label?)'
RETURN_STRING = '\r'                                # its first byte decodes as RETURN


def assert_rejected(test: unittest.TestCase, *functions: Func):
    with test.assertRaises(ValueError):
        Program(*functions).disassemble()


def assert_fails_at(test: unittest.TestCase, program: Program, offset: int, mnemonic: str, text: str):
    '''Disassembly fails in the main function at the instruction at offset, with exactly this text'''
    with test.assertRaises(ScpDisassemblyError) as caught:
        program.disassemble()

    error = caught.exception
    test.assertEqual(str(error), f'{FUNC_NAME}: {mnemonic} at 0x{offset:X}: {text}')
    test.assertEqual((error.function, error.offset, error.mnemonic), (FUNC_NAME, offset, mnemonic))


def assert_warns_backward_return(test: unittest.TestCase, program: Program, call: str, mnemonic: str,
                                 target: int) -> tuple[ScpParser, list[Function]]:
    '''Disassembly succeeds, logging exactly the warning for the main function's call at label call returning to
    target; (parser, functions)'''
    with test.assertLogs(log, 'WARNING') as logs:
        parser, functions = program.disassemble()

    test.assertEqual([record.getMessage() for record in logs.records], [
        f'{FUNC_NAME}: {mnemonic} at 0x{program.label(call):X}: returns to 0x{target:X}, {BACKWARD_RETURN_TEXT}'])
    return parser, functions


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
        assert_fails_at(self, Program(main_function(asm)), 0x12, 'JMP',
                        'the stack on the edge 0x12 -> 0x17 is [], but an earlier edge into 0x17 recorded [PUSH_INT@0x7]')

    def test_value_the_first_arm_leaves_is_caught_where_the_arms_meet(self):
        '''The join is decoded after both arms (lowest offset first), so the second arm's edge finds the leftover -
        not the RETURN, after the join's POP took it for the parameter'''
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.jz('else')
        asm.push_int(LEFT_VALUE); asm.jmp('join')         # left on the stack
        asm.label('else'); asm.push_int(RIGHT_VALUE); asm.set_reg(REG_INDEX)
        asm.label('join'); asm.pop(WORD_SIZE); asm.ret()
        assert_fails_at(self, Program(Func(FUNC_NAME, 1, asm)), 0x1B, 'SET_REG',
                        'the stack on the edge 0x1B -> 0x1D is [param_0], but an earlier edge into 0x1D recorded '
                        '[param_0, PUSH_INT@0xA]')

    def test_fall_through_with_a_different_height_raises(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('target')
        asm.push_int(LEFT_VALUE)                            # falls through into 'target' one entry higher
        asm.label('target'); asm.ret()
        assert_fails_at(self, Program(main_function(asm)), 0x7, 'PUSH_INT',
                        'the stack on the edge 0x7 -> 0xD is [PUSH_INT@0x7], but an earlier edge into 0xD recorded []')

    def test_branch_into_a_decoded_block_with_a_different_height_raises(self):
        asm = Asm()
        asm.get_reg(REG_INDEX)
        asm.label('middle'); asm.set_reg(REG_INDEX); asm.get_reg(REG_INDEX); asm.jz('end')
        asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE); asm.jmp('middle')     # splits the entry block
        asm.label('end'); asm.ret()
        assert_fails_at(self, Program(main_function(asm)), 0x17, 'JMP',
                        'the stack on the edge 0x0 -> 0x2 is [GET_REG@0x0], but an earlier edge into 0x2 recorded '
                        '[PUSH_INT@0xB, PUSH_INT@0x11]')

    def test_back_edge_into_the_entry_with_a_different_height_raises(self):
        '''The entry's state is recorded before decoding - only the parameters - so a back edge meets it'''
        asm = Asm()
        asm.label('head'); asm.get_reg(REG_INDEX); asm.jz('end')
        asm.push_int(LEFT_VALUE); asm.jmp('head')
        asm.label('end'); asm.ret()
        assert_fails_at(self, Program(main_function(asm)), 0xD, 'JMP',
                        'the stack on the edge 0xD -> 0x0 is [PUSH_INT@0x7], but an earlier edge into 0x0 recorded []')

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
        assert_fails_at(self, Program(main_function(asm)), 0x0, 'POP', 'pops 1 entries, the stack has 0: []')

    def test_syscall_reading_past_the_stack_raises_in_the_compile_check(self):
        '''With the POP matching the real stack, only the lift noticed. A decompile still parses it - a parse failure
        would lose the whole file, the lift fails the one function'''
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2); asm.pop(WORD_SIZE); asm.ret()
        program = Program(main_function(asm))
        program.disassemble()

        parser = program.parser()
        parser.reject_outside_stack = True
        with self.assertRaises(ScpDisassemblyError) as caught:
            parser.disasm_all_functions()

        self.assertEqual(str(caught.exception),
                         f'{FUNC_NAME}: SYSCALL at 0x6: reads 2 entries, the stack has 1: [PUSH_INT@0x0]')

    def test_pop_of_a_partial_slot_raises(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.pop(WORD_SIZE // 2); asm.pop(WORD_SIZE // 2); asm.ret()
        assert_fails_at(self, Program(main_function(asm)), 0x6, 'POP', 'pops 2 bytes, not whole slots')

    def test_slot_offset_that_is_not_a_whole_slot_raises(self):
        '''Every slot-addressing opcode, before anything rounds the offset down to a slot; a positive offset too, which
        would otherwise be above the stack'''
        pops_a_value = {'LOAD_STACK': False, 'LOAD_STACK_DEREF': False, 'PUSH_STACK_OFFSET': False, 'POP_TO': True,
                        'POP_TO_DEREF': True}
        for mnemonic, pops in pops_a_value.items():
            for offset in (-1, WORD_SIZE // 2):
                with self.subTest(mnemonic, offset = offset):
                    asm = Asm()
                    asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE)
                    if pops:
                        asm.push_int(LEFT_VALUE)

                    asm.label('access'); getattr(asm, mnemonic.lower())(offset)
                    asm.pop(WORD_SIZE * (2 if pops else 3)); asm.ret()          # balanced, as for a whole slot
                    program = Program(main_function(asm))
                    assert_fails_at(self, program, program.label('access'), mnemonic,
                                    f'addresses byte offset {offset}, not a whole slot ({WORD_SIZE} bytes each)')

    def test_return_with_a_value_left_raises(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.ret()
        assert_fails_at(self, Program(main_function(asm)), 0x6, 'RETURN', 'the stack is not empty: [PUSH_INT@0x0]')

    def test_pop_to_below_the_stack_raises(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.pop_to(-2 * WORD_SIZE); asm.ret()   # sp 1, 0 after its pop: slot -2
        assert_fails_at(self, Program(main_function(asm)), 0x6, 'POP_TO', 'writes below the stack')


class TestInstructionBounds(unittest.TestCase):
    '''No instruction may overlap another, no target may land inside one, and code must end before the string pool'''

    def test_branch_into_the_middle_of_an_instruction_raises(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE)
        asm.jmp(WORD_SIZE // 2)                             # inside the PUSH at 0
        with self.assertRaisesRegex(ScpDisassemblyError,
                                    rf'^{FUNC_NAME}: Branch target 0x2 is inside the instruction at 0x0$'):
            Program(main_function(asm)).disassemble()

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
                program = Program(main_function(caller), returning_callee())
                if plain_arm_first:
                    assert_fails_at(self, program, 0x19, 'CALL',
                                    'expects the function ID, but PUSH_RAW@0x0 is also used as a plain value')

                else:
                    assert_fails_at(self, program, 0x17, 'SET_GLOBAL',
                                    'uses PUSH_CURRENT_FUNC_ID@0x0 as a plain value, but a call consumes it as the '
                                    'function ID')

    def test_discarded_caller_frame_raises(self):
        caller = Asm()
        caller.frame('return'); caller.pop(CALLER_FRAME_SLOTS * WORD_SIZE); caller.ret()
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0x5, 'POP',
                        'discards caller frame slot 0 of 0x0 without its CALL_SCRIPT')

    def test_setup_overwritten_on_one_arm_raises(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('return')
        caller.get_reg(REG_INDEX); caller.jz('join')
        caller.push_int(LEFT_VALUE); caller.pop_to(-WORD_SIZE)       # overwrites the return address on this arm
        caller.label('join'); caller.call(CALLEE_ID); caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0x1E, 'CALL',
                        'expects the return address 0x21, but PUSH_RAW@0x6 is also used as a plain value')

    def test_overwritten_caller_frame_raises(self):
        caller = Asm()
        caller.frame('return'); caller.push_int(LEFT_VALUE); caller.pop_to(-WORD_SIZE)    # overwrites a frame slot
        caller.pop(CALLER_FRAME_SLOTS * WORD_SIZE); caller.ret()
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0xB, 'POP_TO',
                        'discards caller frame slot 4 of 0x0 without its CALL_SCRIPT')

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
                program = Program(main_function(caller), returning_callee())
                if overwrite_arm_first:
                    assert_fails_at(self, program, 0x21, 'CALL',
                                    'expects the function ID, but PUSH_RAW@0x0 is also used as a plain value')

                else:
                    assert_fails_at(self, program, 0x1D, 'POP_TO',
                                    'uses PUSH_RET_ADDR@0x6 as a plain value, but a call consumes it as the return '
                                    'address 0x16')


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

    def test_too_few_arguments_names_the_count(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('return'); caller.call(CALLEE_ID)    # the callee takes one arg
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee(argc = 1)), 0xC, 'CALL',
                        f'{CALLEE_NAME} takes 1 argument, found 0 above its call setup [PUSH_RAW@0x0, PUSH_RAW@0x6]')

    def test_wrong_count_with_the_return_label_elsewhere_is_not_a_count(self):
        '''Only a setup returning right after the call is counted from; this one returns past dead code'''
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('resume'); caller.call(CALLEE_ID)    # the callee takes one arg
        caller.ret()                                        # dead
        caller.label('resume'); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee(argc = 1)), 0xC, 'CALL',
                        'pops 2 entries, the stack has 1: [PUSH_RAW@0x0]')

    def test_broken_setup_under_an_outer_calls_setup_is_not_a_count(self):
        '''The outer call's pending setup returns elsewhere, and a plain value isn't a function ID, so the inner call
        isn't counted from either: the message says what stands where the inner setup should be'''
        cases = [
            # (case, the inner setup's return labels, the inner args, the message, the label of the push it names)
            ('function ID forgotten', ['inner'], 1, 'expects the function ID', 'outer_arg'),
            ('setup forgotten', [], 1, 'expects a return address', 'outer_arg'),
            ('function ID forgotten, one argument too many', ['inner'], 2, 'expects a return address', 'inner_arg'),
        ]
        for case, inner_setup, inner_args, message, named in cases:
            with self.subTest(case):
                caller = Asm()
                caller.push_raw(CALLER_ID); caller.push_raw('outer')
                caller.label('outer_arg'); caller.push_int(LEFT_VALUE)
                for target in inner_setup:
                    caller.push_raw(target)

                caller.label('inner_arg')
                for _ in range(inner_args):
                    caller.push_int(RIGHT_VALUE)

                caller.label('call'); caller.call(CALLEE_ID)
                caller.label('inner'); caller.get_reg(REG_INDEX); caller.call(CALLEE_ID)
                caller.label('outer'); caller.ret()
                program = Program(main_function(caller), returning_callee(argc = 1))
                assert_fails_at(self, program, program.label('call'), 'CALL',
                                f'{message}, found PUSH_INT@0x{program.label(named):X}')

    def test_function_id_of_another_function_raises(self):
        program = self.call_program(lambda asm: (asm.push_raw(CALLEE_ID), asm.push_raw('return')))
        assert_fails_at(self, program, 0xC, 'CALL', 'expects the function ID, found PUSH_RAW@0x0')

    def test_function_id_that_is_not_a_push_raises(self):
        program = self.call_program(lambda asm: (asm.get_reg(REG_INDEX), asm.push_raw('return')))
        assert_fails_at(self, program, 0x8, 'CALL', 'expects the function ID, found GET_REG@0x0')

    def test_typed_return_address_push_raises(self):
        '''Rewriting a PUSH_INT to PUSH_RET_ADDR would change its bytes on recompile'''
        program = self.call_program(lambda asm: (asm.push_raw(CALLER_ID), asm.push_int(0)))
        assert_fails_at(self, program, 0xC, 'CALL', 'expects a return address, found PUSH_INT@0x6')

    def test_overwritten_return_address_raises(self):
        def setup(asm):
            asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.push_int(LEFT_VALUE)
            asm.pop_to(-WORD_SIZE)                          # overwrites the return address

        assert_fails_at(self, self.call_program(setup), 0x17, 'CALL', 'expects a return address, found POP_TO@0x12')

    def test_return_address_consumed_again_as_a_function_id_raises(self):
        '''The fall-through arm's call consumes the push as its return address; the other arm's call, one slot higher,
        as its function ID'''
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('first'); caller.get_reg(REG_INDEX); caller.jz('second')
        caller.call(CALLEE_ID); caller.label('first'); caller.ret()
        caller.label('second'); caller.push_raw('resume'); caller.call(CALLEE_ID)
        caller.label('resume'); caller.pop(WORD_SIZE); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0x1D, 'CALL',
                        'PUSH_RET_ADDR@0x6 is consumed as the function ID and as the return address 0x16')

    def test_return_addresses_meeting_at_a_join_must_match(self):
        '''Both arms reach the join before its code is decoded (lowest offset first), so the call finds the second
        arm's value where the return address must be'''
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.get_reg(REG_INDEX); caller.jz('right')
        caller.push_raw('return'); caller.jmp('join')
        caller.label('right'); caller.push_raw('right'); caller.jmp('join')
        caller.label('join'); caller.call(CALLEE_ID); caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0x23, 'CALL',
                        'expects the return address 0x26, found PUSH_RAW@0x18')

    def test_return_label_at_the_end_of_the_function_raises(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('end'); caller.call(CALLEE_ID)
        caller.label('end')                                 # the callee's code starts here
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0xC, 'CALL',
                        'returns to 0xF, past its end (no RETURN after its return label)')

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
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0xC, 'CALL',
                        f'return offset 0x{OUTSIDE_OFFSET:X} is outside the function')

    def test_return_address_in_an_earlier_function_is_outside(self):
        '''The callee laid out first, so the two function IDs swap'''
        caller = Asm()
        caller.push_raw(CALLEE_ID); caller.push_raw(EARLIER_FUNCTION_START)
        caller.label('call'); caller.call(CALLER_ID); caller.ret()
        program = Program(returning_callee(), main_function(caller))
        assert_fails_at(self, program, program.label('call'), 'CALL',
                        f'return offset 0x{EARLIER_FUNCTION_START:X} is outside the function')

    def test_return_label_at_the_function_start_warns(self):
        caller = Asm()
        caller.label('top'); caller.push_raw(CALLER_ID); caller.push_raw('top')
        caller.label('call'); caller.call(CALLEE_ID); caller.ret()
        program = Program(main_function(caller), returning_callee())
        parser, functions = assert_warns_backward_return(self, program, 'call', 'CALL', program.label('top'))

        self.assertEqual(list(functions[0].backward_returns), [program.label('call')])
        lift_all(parser, functions)

    def test_return_label_on_the_call_warns_then_fails(self):
        '''The call pops its setup, so the edge back to itself never matches: the warning, then the stack failure'''
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('call'); caller.label('call'); caller.call(CALLEE_ID); caller.ret()
        program = Program(main_function(caller), returning_callee())
        with self.assertLogs(log, 'WARNING') as logs, self.assertRaises(ScpDisassemblyError):
            program.disassemble()

        call = program.label('call')
        self.assertIn(f'{FUNC_NAME}: CALL at 0x{call:X}: returns to 0x{call:X}, {BACKWARD_RETURN_TEXT}',
                      [record.getMessage() for record in logs.records])

    def test_return_label_on_the_first_setup_push_warns(self):
        caller = Asm()
        caller.get_reg(REG_INDEX); caller.pop(WORD_SIZE)
        caller.label('setup'); caller.push_raw(CALLER_ID); caller.push_raw('setup')
        caller.label('call'); caller.call(CALLEE_ID); caller.ret()
        program = Program(main_function(caller), returning_callee())
        assert_warns_backward_return(self, program, 'call', 'CALL', program.label('setup'))

    def test_copied_call_with_a_stale_return_label_warns(self):
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('first'); caller.call(CALLEE_ID); caller.label('first')
        caller.push_raw(CALLER_ID); caller.push_raw('first')                           # should name 'second'
        caller.label('call'); caller.call(CALLEE_ID); caller.label('second'); caller.ret()
        program = Program(main_function(caller), returning_callee())
        assert_warns_backward_return(self, program, 'call', 'CALL', program.label('first'))

    def test_call_looping_back_with_an_exit_only_warns(self):
        '''while (REG) callee() with the return as the back edge is valid: a warning, not a failure'''
        caller = Asm()
        caller.label('top'); caller.get_reg(REG_INDEX); caller.jz('done')
        caller.label('body'); caller.push_raw(CALLER_ID); caller.push_raw('top'); caller.label('call')
        caller.call(CALLEE_ID)
        caller.label('done'); caller.ret()
        program = Program(main_function(caller), returning_callee())
        parser, functions = assert_warns_backward_return(self, program, 'call', 'CALL', program.label('top'))

        call_block = blocks_by_offset(functions[0])[program.label('body')]
        self.assertEqual(successors(call_block), [program.label('top')])
        lift_all(parser, functions)

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
        '''Both arms reach the join before its call is decoded, so the call fails on whichever arm brings the plain
        values'''
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
                program = Program(main_function(caller), returning_callee())
                if setup_arm_first:
                    assert_fails_at(self, program, 0x29, 'CALL', 'expects the function ID, found PUSH_INT@0x18')

                else:
                    assert_fails_at(self, program, 0x29, 'CALL', 'expects a return address, found PUSH_INT@0xD')


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

    def test_frame_returning_before_itself_warns(self):
        caller = Asm()
        caller.label('top'); caller.frame('top'); caller.push_int(LEFT_VALUE)
        caller.label('call'); caller.call_script(1); caller.ret()
        program = Program(main_function(caller))
        assert_warns_backward_return(self, program, 'call', 'CALL_SCRIPT', program.label('top'))

    def test_call_script_without_a_frame_raises(self):
        caller = Asm()
        for _ in range(CALLER_FRAME_SLOTS):
            caller.push_int(LEFT_VALUE)                     # a frame's height, but no frame

        caller.push_int(RIGHT_VALUE); caller.call_script(1); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0x24, 'CALL_SCRIPT',
                        'expects a return address, found PUSH_INT@0x0')

    def test_one_argument_more_than_its_count_raises(self):
        '''The extra argument shifts the frame down a slot: the call finds the wrong frame slot where it expects one'''
        caller = Asm()
        caller.frame('return'); caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE); caller.call_script(1)
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0x11, 'CALL_SCRIPT',
                        'expects caller frame slot 0 returning to 0x1B, found frame_1@0x0')

    def test_frames_meeting_other_values_at_a_join_raises(self):
        '''Both arms reach the join before its code is decoded, so CALL_SCRIPT finds the second arm's plain values
        where the frame must be'''
        caller = Asm()
        caller.get_reg(REG_INDEX); caller.jz('right')
        caller.frame('return'); caller.jmp('join')
        caller.label('right')
        for _ in range(CALLER_FRAME_SLOTS):
            caller.push_int(LEFT_VALUE)

        caller.jmp('join')
        caller.label('join'); caller.call_script(0); caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0x34, 'CALL_SCRIPT',
                        'expects caller frame slot 0 returning to 0x3E, found PUSH_INT@0x11')

    def test_pop_reaching_into_the_frame_raises(self):
        caller = Asm()
        caller.frame('return'); caller.push_int(LEFT_VALUE)
        caller.pop(2 * WORD_SIZE)                           # the arg and one frame slot
        caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE); caller.call_script(1)
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0xB, 'POP',
                        'discards caller frame slot 4 of 0x0 without its CALL_SCRIPT')

    def test_tail_call_leaving_entries_below_its_args_raises(self):
        caller = Asm()
        caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE); caller.call_script_no_return(1)
        assert_fails_at(self, Program(main_function(caller)), 0xC, 'CALL_SCRIPT_NO_RETURN',
                        'leaves [PUSH_INT@0x0] below its args')

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

    def test_call_script_with_too_few_arguments_names_the_frame_slot_it_found(self):
        '''Four pushes stand above the frame: the call takes the frame's last slot and the four pushes as its frame. Its
        first entry is a frame slot of the right frame, so the error is the wrong slot, not a missing return address'''
        caller = Asm()
        caller.frame('return')
        for _ in range(CALLER_FRAME_SLOTS - 1):
            caller.push_int(LEFT_VALUE)

        caller.label('call'); caller.call_script(0); caller.label('return'); caller.ret()
        program = Program(main_function(caller))
        assert_fails_at(self, program, program.label('call'), 'CALL_SCRIPT',
                        f'expects caller frame slot 0 returning to 0x{program.label("return"):X}, found frame_4@0x0')


class TestCheckOrder(unittest.TestCase):
    '''An instruction that breaks two rules is reported by the check the parser makes first'''

    def test_call_checks_the_return_address_before_the_function_id(self):
        caller = Asm()
        caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE); caller.call(CALLEE_ID); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0xC, 'CALL',
                        'expects a return address, found PUSH_INT@0x6')

    def test_call_checks_its_argument_count_first(self):
        '''One argument too many: counted from the setup returning right after the call, before the entry where the
        setup should be is checked'''
        caller = Asm()
        caller.push_raw(CALLER_ID); caller.push_raw('return'); caller.push_int(LEFT_VALUE); caller.call(CALLEE_ID)
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller), returning_callee()), 0x12, 'CALL',
                        f'{CALLEE_NAME} takes 0 arguments, found 1 above its call setup [PUSH_RAW@0x0, PUSH_RAW@0x6]')

    def test_call_checks_its_arguments_before_its_setup(self):
        '''With no setup returning here, the args are popped first'''
        caller = Asm()
        caller.push_int(LEFT_VALUE); caller.call(CALLEE_ID); caller.ret()               # no setup, the callee takes 3
        assert_fails_at(self, Program(main_function(caller), returning_callee(argc = PARAM_COUNT)), 0x6, 'CALL',
                        'pops 3 entries, the stack has 1: [PUSH_INT@0x0]')

    def test_call_script_checks_its_arguments_before_its_frame(self):
        caller = Asm()
        caller.push_int(LEFT_VALUE); caller.call_script(2); caller.ret()                 # no frame, one arg of 2
        assert_fails_at(self, Program(main_function(caller)), 0x6, 'CALL_SCRIPT',
                        'pops 2 entries, the stack has 1: [PUSH_INT@0x0]')

    def test_tail_call_checks_its_arguments_before_what_lies_below_them(self):
        caller = Asm()
        caller.frame('return'); caller.call_script_no_return(1)                         # its arg is a frame slot
        caller.label('return'); caller.ret()
        assert_fails_at(self, Program(main_function(caller)), 0x5, 'CALL_SCRIPT_NO_RETURN',
                        'discards caller frame slot 4 of 0x0 without its CALL_SCRIPT')

    def test_pop_checks_whole_slots_before_the_stack(self):
        asm = Asm()
        asm.pop(WORD_SIZE + WORD_SIZE // 2); asm.ret()                                   # on an empty stack
        assert_fails_at(self, Program(main_function(asm)), 0x0, 'POP', 'pops 6 bytes, not whole slots')

    def test_pop_to_checks_whole_slots_before_it_pops(self):
        asm = Asm()
        asm.pop_to(-1); asm.ret()                                                        # on an empty stack
        assert_fails_at(self, Program(main_function(asm)), 0x0, 'POP_TO',
                        f'addresses byte offset -1, not a whole slot ({WORD_SIZE} bytes each)')

    def test_pop_to_pops_before_it_writes(self):
        asm = Asm()
        asm.pop_to(-2 * WORD_SIZE); asm.ret()                                            # nothing to pop, slot -2
        assert_fails_at(self, Program(main_function(asm)), 0x0, 'POP_TO', 'pops 1 entries, the stack has 0: []')


class TestErrorWrapping(unittest.TestCase):
    def test_a_rejection_the_parser_words_itself_is_not_chained_to_itself(self):
        '''disasm_all_functions wraps other errors in ScpDisassemblyError, but re-raises its own as they are'''
        asm = Asm()
        asm.pop(WORD_SIZE); asm.ret()
        with self.assertRaises(ScpDisassemblyError) as caught:
            Program(main_function(asm)).disassemble()

        self.assertIsNone(caught.exception.__cause__)


def call_offsets(parser: ScpParser, func: Function) -> list[int]:
    '''Its CALLs' offsets, reachable and decoded dead code, in address order'''
    return [inst.offset for inst in parser.code_instructions(func) if inst.opcode == ED9Opcode.CALL]


def constants(*values) -> list:
    return [(ArgType.Constant, value) for value in values]


class TestDebugArgcRecovery(unittest.TestCase):
    '''round_trip: a paired local CALL's recorded arg count by its offset (call_written_argc); the .py writes it on the
    CALL (call_debug_argc) only where it isn't the compiler's rule - trailing constants equal to the callee's defaults
    dropped. The call is callee(RIGHT_VALUE, LEFT_VALUE).'''

    @classmethod
    def program(cls, last_default: int | None = None, dead_call: bool = False) -> Program:
        '''Main calls the callee; dead_call: and again after its RETURN, as the compiler leaves dead code'''
        callee = returning_callee(argc = 2)
        caller = Asm()
        caller.debug_set_lineno(1)
        for ret in ('ret', 'dead_ret') if dead_call else ('ret',):
            caller.push_raw(CALLER_ID); caller.push_raw(ret)
            caller.push_int(LEFT_VALUE); caller.push_int(RIGHT_VALUE)
            caller.call(CALLEE_ID); caller.label(ret); caller.ret()

        program = Program(main_function(caller), callee)
        if last_default is not None:
            program.entries[CALLEE_ID].params[-1].default_value = ScpValue(last_default)

        return program

    @classmethod
    def parser(cls, program: Program, *counts: int, keep_unreachable_code: bool = False) -> ScpParser:
        '''A round_trip parser of program, main's records keeping counts args of the callee's'''
        data, records = debug_records(*[(CallType.Local, CALLEE_ID, constants(RIGHT_VALUE, LEFT_VALUE)[:count])
                                        for count in counts])
        program.entries[0].debug_info = records
        parser = program.parser(keep_unreachable_code)
        parser.round_trip = True
        parser.data = data
        return parser

    def test_counts_by_call_offset(self):
        '''(recorded args, the callee's last default) -> whether the .py writes the count'''
        cases = {
            'fewer than the parameters, no default': (1, None, True),
            'all, no default': (2, None, False),
            'the default left out': (1, LEFT_VALUE, False),
            'the default written out': (2, LEFT_VALUE, True),
            'all, another default': (2, RIGHT_VALUE, False),
        }
        for case, (explicit_args, last_default, written_on_the_call) in cases.items():
            with self.subTest(case):
                parser = self.parser(self.program(last_default), explicit_args)
                func = parser.disasm_all_functions()[0]
                [offset] = call_offsets(parser, func)

                self.assertEqual(func.call_written_argc, {offset: explicit_args})
                self.assertEqual(func.call_debug_argc, {offset: explicit_args} if written_on_the_call else {})


class TestDeadCodeRecords(unittest.TestCase):
    '''A call after an early RETURN has its record too: the parser pairs the records over the code the .py prints,
    reachable and decoded dead code, after the dead-code pass. Main's live call keeps the rule's 1 arg, its dead call
    both (the callee's last parameter defaults to LEFT_VALUE).'''

    def load(self, keep_unreachable_code: bool = True, filter_func = None) -> tuple[ScpParser, list[Function]]:
        program = TestDebugArgcRecovery.program(last_default = LEFT_VALUE, dead_call = True)
        parser = TestDebugArgcRecovery.parser(program, 1, 2, keep_unreachable_code = keep_unreachable_code)
        return parser, parser.disasm_all_functions(filter_func = filter_func)

    def test_a_dead_call_gets_its_count(self):
        parser, functions = self.load()
        main = functions[0]
        live, dead = call_offsets(parser, main)
        self.assertEqual([inst.offset for inst in parser.unreachable_instructions(main) if inst.opcode == ED9Opcode.CALL],
                         [dead])

        self.assertEqual(main.call_written_argc, {live: 1, dead: 2})
        self.assertEqual(main.call_debug_argc, {dead: 2})

    def test_without_the_dead_code_the_function_is_not_paired(self):
        '''It has more records than calls: no counts, and a warning'''
        with self.assertLogs(log, 'WARNING') as logs:
            _, functions = self.load(keep_unreachable_code = False)

        self.assertEqual((functions[0].call_written_argc, functions[0].call_debug_argc), ({}, {}))
        self.assertIn(f'{FUNC_NAME}: records not paired: 1 calls, 2 records; the .py writes no debug_argc',
                      [record.getMessage() for record in logs.records])

    def test_without_round_trip_nothing_is_paired(self):
        for keep_unreachable_code in (True, False):
            with self.subTest(keep_unreachable_code = keep_unreachable_code):
                program = TestDebugArgcRecovery.program(LEFT_VALUE, dead_call = True)
                main = program.parser(keep_unreachable_code).disasm_all_functions()[0]
                self.assertEqual((main.call_written_argc, main.call_debug_argc), ({}, {}))

    def test_a_filtered_function_is_not_paired(self):
        '''Pairing runs over the disassembled functions only: the filtered-out one gets no counts and no warning'''
        with self.assertNoLogs(log, 'WARNING'):
            parser, functions = self.load(filter_func = lambda func: func.name != FUNC_NAME)

        self.assertEqual([func.name for func in functions], [CALLEE_NAME])
        filtered = parser.get_func_by_name(FUNC_NAME)
        self.assertTrue(filtered.debug_info)
        self.assertEqual((filtered.call_written_argc, filtered.call_debug_argc, filtered.call_unrecorded), ({}, {}, set()))


class TestDebugArgcFormatting(unittest.TestCase):
    '''The .py writes a count on its CALL line, inside the parentheses; the decorator is always plain'''

    def disassemble(self) -> tuple[Function, int]:
        '''The main function of TestDebugArgcRecovery's program and its CALL's offset'''
        parser = TestDebugArgcRecovery.program().parser()
        func = parser.disasm_all_functions()[0]
        [offset] = call_offsets(parser, func)
        return func, offset

    def test_count_on_its_call_line(self):
        func, offset = self.disassemble()
        func.call_debug_argc = {offset: 1}
        lines = [line.strip() for line in Formatter(FormatterContext()).format_function(func)]

        self.assertIn('@scena.LLILCode()', lines)
        [call] = [line for line in lines if line.startswith('CALL(')]
        self.assertTrue(call.endswith(', debug_argc = 1)'), call)

    def test_a_reused_formatter_keeps_no_count(self):
        '''A later function with a CALL at the same offset, and a block formatted on its own'''
        annotated, offset = self.disassemble()
        annotated.call_debug_argc = {offset: 1}
        plain, same_offset = self.disassemble()
        self.assertEqual(same_offset, offset)
        formatter = Formatter(FormatterContext())
        formatter.format_function(annotated)

        for case, lines in (('function', formatter.format_function(plain)),
                            ('block', formatter.format_entry_block(plain.entry_block))):
            with self.subTest(case):
                self.assertNotIn('debug_argc', '\n'.join(lines))


class TestDebugArgcRecoveryOrder(unittest.TestCase):
    '''round_trip: each record pairs with its own call in the compiler's record order - nested calls in parameter order,
    a tail call's argument parked in a register after the previous statement's call - so a trimmed count reaches the
    call it belongs to. The records are written here in the compiler's order, not by the tracker under test.'''
    OUTER_ID = 1
    INNER_ID = 2
    CALLEE_ARGC = 2
    TAIL_VALUE = 9
    TAIL_REG = 1
    TAIL_NAME = '.'.join(STRINGS)

    @classmethod
    def call_debug_argc(cls, caller: Asm, *records: tuple) -> tuple[dict, list[int]]:
        '''Main's call_debug_argc and its CALL offsets in address order'''
        callee = returning_callee(argc = cls.CALLEE_ARGC)
        program = Program(main_function(caller), callee._replace(name = 'outer'), callee._replace(name = 'inner'))
        parser = program.parser()
        parser.data, program.entries[0].debug_info = debug_records(*records)
        parser.round_trip = True
        func = parser.disasm_all_functions()[0]
        return func.call_debug_argc, call_offsets(parser, func)

    @classmethod
    def push_inner_call(cls, caller: Asm, ret: str):
        caller.push_raw(CALLER_ID); caller.push_raw(ret)
        caller.push_int(RIGHT_VALUE); caller.push_int(LEFT_VALUE)
        caller.call(cls.INNER_ID); caller.label(ret)

    def test_nested_calls_pair_in_parameter_order(self):
        '''outer(inner(..), inner(..)): arguments are pushed last first, so the second argument's call runs first; the
        first argument's call keeps one argument'''
        caller = Asm()
        caller.debug_set_lineno(1)
        caller.push_raw(CALLER_ID); caller.push_raw('outer')
        for ret in ('second', 'first'):
            self.push_inner_call(caller, ret)
            caller.get_reg(REG_INDEX)

        caller.call(self.OUTER_ID); caller.label('outer'); caller.ret()
        call_result = (ArgType.CallResult, ScpFunctionCallDebugInfoArg.NON_CONSTANT_VALUE)
        debug_argc, [_, first, _] = self.call_debug_argc(       # address order: second, first, outer
            caller, (CallType.Local, self.OUTER_ID, [call_result, call_result]),
            (CallType.Local, self.INNER_ID, constants(LEFT_VALUE)),
            (CallType.Local, self.INNER_ID, constants(LEFT_VALUE, RIGHT_VALUE)))
        self.assertEqual(debug_argc, {first: 1})

    def test_register_carried_tail_argument_pairs_after_the_previous_call(self):
        '''inner(..) keeping one argument, then a tail call whose constant argument waits in a register'''
        caller = Asm()
        caller.debug_set_lineno(1)
        self.push_inner_call(caller, 'ret')
        caller.debug_set_lineno(2)
        caller.push_int(self.TAIL_VALUE); caller.set_reg(self.TAIL_REG); caller.get_reg(self.TAIL_REG)
        caller.call_script_no_return(1)
        debug_argc, [inner] = self.call_debug_argc(
            caller, (CallType.Local, self.INNER_ID, constants(LEFT_VALUE)),
            (CallType.ScriptNoReturn, ScpFunctionCallDebugInfo.NO_FUNC_ID, constants(self.TAIL_NAME, self.TAIL_VALUE)))
        self.assertEqual(debug_argc, {inner: 1})


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

    def layout_warning(self, expected: tuple[tuple[str, str, str], ...], asm: Asm, argc: int = 0, *others: Func) -> tuple[Program, StackLayout]:
        '''layout_of, which must log exactly the expected warnings: (label, mnemonic, slot text) each'''
        with self.assertLogs(log, 'WARNING') as logs:
            program, layout = self.layout_of(asm, argc, *others)

        self.assertCountEqual([record.getMessage() for record in logs.records], [
            f'{FUNC_NAME}: {mnemonic} at 0x{program.label(name):X} addresses {text}' for name, mnemonic, text in expected
        ])
        return program, layout

    def test_offset_opcodes_number_parameters_from_the_highest_slot(self):
        asm = Asm()
        asm.label('read'); asm.load_stack(-WORD_SIZE)                  # sp 3: slot 2
        asm.push_int(LEFT_VALUE)
        asm.label('address'); asm.push_stack_offset(-4 * WORD_SIZE)    # sp 5: slot 1
        asm.label('deref'); asm.load_stack_deref(-6 * WORD_SIZE)       # sp 6: slot 0
        asm.pop((PARAM_COUNT + 4) * WORD_SIZE); asm.ret()              # the parameters and the 4 values pushed
        with self.assertNoLogs(log, 'WARNING'):
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
        program, layout = self.layout_warning((
            ('below', 'LOAD_STACK', 'slot -1 (below the stack)'), ('at_sp', 'LOAD_STACK', 'slot 1 (above the stack)'),
            ('dead_store', 'POP_TO', 'slot 1 (above the stack)'),
        ), asm)

        refs = {name: layout.slot_refs[program.label(name)] for name in ('below', 'at_sp', 'dead_store')}
        self.assertEqual(refs, {'below': SlotRef(-1), 'at_sp': SlotRef(1), 'dead_store': SlotRef(1)})
        self.assertEqual(layout.local_slots, {})

    def test_call_setup_and_caller_frame_slots(self):
        setup = Asm()
        setup.push_raw(CALLER_ID); setup.push_raw('return')
        setup.label('read_id'); setup.load_stack(-2 * WORD_SIZE); setup.pop(WORD_SIZE)      # the function ID
        setup.label('read_return'); setup.load_stack(-WORD_SIZE); setup.pop(WORD_SIZE)      # the return address
        setup.call(CALLEE_ID); setup.label('return'); setup.ret()
        program, layout = self.layout_warning((
            ('read_id', 'LOAD_STACK', 'slot 0 = call setup'), ('read_return', 'LOAD_STACK', 'slot 1 = call setup'),
        ), setup, 0, returning_callee())
        refs = [layout.slot_refs[program.label(name)] for name in ('read_id', 'read_return')]
        self.assertEqual(refs, [SlotRef(0, call_setup = True), SlotRef(1, call_setup = True)])

        frame = Asm()
        frame.frame('return')
        frame.label('read'); frame.load_stack(-WORD_SIZE); frame.pop(WORD_SIZE)      # the frame's top slot
        frame.call_script(0); frame.label('return'); frame.ret()
        program, layout = self.layout_warning((('read', 'LOAD_STACK', f'slot {CALLER_FRAME_SLOTS - 1} = caller frame'),), frame)
        self.assertEqual(layout.slot_refs[program.label('read')], SlotRef(CALLER_FRAME_SLOTS - 1, caller_frame = True))

    def test_slot_that_may_hold_a_parameter_or_a_local(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('join')
        asm.pop(WORD_SIZE); asm.push_int(LEFT_VALUE)                   # this arm replaces the parameter
        asm.label('join'); asm.load_stack(-WORD_SIZE)
        asm.pop(2 * WORD_SIZE); asm.ret()
        program, layout = self.layout_warning((('join', 'LOAD_STACK', 'slot 0 = arg1 or local'),), asm, 1)
        self.assertEqual(layout.slot_refs[program.label('join')], SlotRef(0, params = (1,), local = True))

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

    def test_arguments_of_every_kind_of_call_are_numbered(self):
        '''arg1 is a call's last push: a local call, a script call, a SYSCALL (whose arguments a POP removes later) and a
        tail call; a POP or DEBUG_LOG numbers nothing'''
        asm = Asm()
        asm.push_raw(CALLER_ID); asm.push_raw('local_return')
        asm.label('local_arg'); asm.push_int(LEFT_VALUE); asm.call(CALLEE_ID)
        asm.label('local_return'); asm.frame('script_return')
        asm.label('script_arg'); asm.push_int(LEFT_VALUE); asm.call_script(1)
        asm.label('script_return'); asm.label('syscall_arg2'); asm.push_int(LEFT_VALUE)
        asm.label('syscall_arg1'); asm.push_int(RIGHT_VALUE)
        asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2); asm.pop(2 * WORD_SIZE)
        asm.push_int(LEFT_VALUE); asm.debug_log(1)
        asm.label('tail_arg'); asm.push_int(LEFT_VALUE); asm.call_script_no_return(1)
        program, layout = self.layout_of(asm, 0, returning_callee(argc = 1))

        numbers = {'local_arg': (1,), 'script_arg': (1,), 'syscall_arg2': (2,), 'syscall_arg1': (1,), 'tail_arg': (1,)}
        self.assertEqual(layout.arg_numbers, {program.label(name): number for name, number in numbers.items()})


if __name__ == '__main__':
    unittest.main()
