#!/usr/bin/env python3
'''Unit tests for the LLIL DSL's comments: the slot each offset opcode addresses and what it holds, the depth at labels
and POP's slot count, read from the parser's StackLayout and aligned in one column with the other trailing comments;
and the opt-in kinds - the argument each push becomes, PUSH_FLOAT's bits, each function's table index and offset.'''

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from common.utils import display_width
from falcom.ed9.disasm import CommentOptions, Formatter, FormatterContext
from falcom.ed9.disasm.llil_dsl_comments import COMMENT_COLUMN, MIN_COMMENT_GAP, append_comment
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.parser.types_parser import SlotRef
from falcom.ed9.parser.types_scp import ScpValue
from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_writer_helper import RETURN, create_scp_writer
from ir.llil.llil import WORD_SIZE
from scp_writer_test_utils import fresh_writer
from test_scp_stack_simulation import (
    Asm, Func, Program, CALLEE_ID, CALLER_ID, FLOAT_VALUE, FUNC_NAME, GLOBAL_INDEX, LEFT_VALUE, PARAM_COUNT,
    REG_INDEX, RIGHT_VALUE, main_function, returning_callee,
)

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'
CHECK_ALGO_USE_FILE = SORA2_DIR / 'ai' / 'ai_chr5122_e00.dat'
SYSCALL_SUBSYSTEM = 1
SYSCALL_FUNC = 0x2F
FLOAT_BITS = 'f32 0x3E999998, raw 0x8FA66666'      # FLOAT_VALUE's float32 bits and stored word
ARGUMENTS_ONLY = CommentOptions(stack_slots = False, call_args = True)
ALL_COMMENTS = CommentOptions(float_bits = True, function_ids = True, call_args = True)


def function_lines(asm: Asm, argc: int = 0, comments: CommentOptions = CommentOptions()) -> list[str]:
    '''The .py body of the one function asm assembles, without its indent'''
    parser, functions = Program(Func(FUNC_NAME, argc, asm)).disassemble()
    return [line.strip() for line in parser.format_function(functions[0], comments)[2:]]


def commented_lines(program: Program, comments: CommentOptions) -> list[str]:
    '''The lines of the program's first function that carry a comment, without their indent'''
    parser, functions = program.disassemble()
    return [line.strip() for line in parser.format_function(functions[0], comments) if '#' in line]


class TestAppendComment(unittest.TestCase):
    def test_code_reaching_the_column_keeps_a_gap(self):
        code = 'X' * COMMENT_COLUMN
        self.assertEqual(append_comment(code, ['sp = 3']), code + ' ' * MIN_COMMENT_GAP + '# sp = 3')

    def test_cjk_characters_take_two_columns(self):
        self.assertEqual(display_width('◆通常攻撃'), 9)        # '◆' is drawn narrow
        self.assertEqual(append_comment('PUSH_STR("◆通常攻撃")', ['arg35']), 'PUSH_STR("◆通常攻撃")' + ' ' * 11 + '# arg35')


class TestSlotText(unittest.TestCase):
    def test_each_kind(self):
        cases = {
            SlotRef(2, params = (1,))                   : ('slot 2 = arg1', False),
            SlotRef(3, local = True)                    : ('slot 3', False),
            SlotRef(2, params = (1,), local = True)     : ('slot 2 = arg1 or local', True),
            SlotRef(1, caller_frame = True)             : ('slot 1 = caller frame', True),
            SlotRef(1, (1,), caller_frame = True)       : ('slot 1 = arg1 or caller frame', True),
            SlotRef(0, call_setup = True)               : ('slot 0 = call setup', True),
            SlotRef(-1)                                 : ('slot -1 (below the stack)', True),
            SlotRef(5)                                  : ('slot 5 (above the stack)', True),
        }
        for ref, (text, unusual) in cases.items():
            with self.subTest(ref = ref):
                self.assertEqual((str(ref), ref.unusual), (text, unusual))


class TestFunctionComments(unittest.TestCase):
    def test_parameters_locals_and_pops(self):
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.pop(WORD_SIZE)                  # sp 3: slot 2
        asm.push_raw(0)                                                 # opens slot 3
        asm.push_int(LEFT_VALUE); asm.pop_to(-WORD_SIZE)                # sp 5, 4 after its pop: slot 3
        asm.load_stack(-4 * WORD_SIZE)                                  # sp 4: slot 0
        asm.pop(5 * WORD_SIZE); asm.ret()
        self.assertEqual(function_lines(asm, PARAM_COUNT), [
            'LOAD_STACK(-4)                  # slot 2 = arg1',
            'POP(4)                          # 1 slot',
            'PUSH_RAW(RawInt(0x00000000))    # slot 3 (local)',
            f'PUSH_INT({LEFT_VALUE})',
            'POP_TO(-4)                      # slot 3',
            'LOAD_STACK(-16)                 # slot 0 = arg3',
            'POP(20)                         # 5 slots',
            'RETURN()',
        ])

    def test_dereferences_and_addresses(self):
        asm = Asm()
        asm.push_stack_offset(-WORD_SIZE); asm.pop(WORD_SIZE)          # sp 1: slot 0
        asm.load_stack_deref(-WORD_SIZE)                                # sp 1: slot 0
        asm.pop_to_deref(-WORD_SIZE)                                    # sp 2, 1 after its pop: slot 0
        asm.pop(WORD_SIZE); asm.ret()
        self.assertEqual(function_lines(asm, 1), [
            'PUSH_STACK_OFFSET(-4)           # &slot 0 = arg1',
            'POP(4)                          # 1 slot',
            'LOAD_STACK_DEREF(-4)            # *slot 0 = arg1',
            'POP_TO_DEREF(-4)                # *slot 0 = arg1',
            'POP(4)                          # 1 slot',
            'RETURN()',
        ])

    def test_labels_get_the_depth(self):
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('next')
        asm.push_int(LEFT_VALUE); asm.pop(WORD_SIZE)
        asm.label('next'); asm.pop(WORD_SIZE); asm.ret()
        program = Program(Func(FUNC_NAME, 1, asm))
        parser, functions = program.disassemble()
        label = f"label('loc_{program.label('next'):X}')"
        self.assertIn(f'    {append_comment(label, ["sp = 1"])}', parser.format_function(functions[0]))

    def test_global_var_comment_comes_first_and_stays_when_turned_off(self):
        asm = Asm()
        asm.load_global(GLOBAL_INDEX); asm.load_stack(-WORD_SIZE)      # the global opens slot 0
        asm.set_global(GLOBAL_INDEX); asm.pop(WORD_SIZE); asm.ret()
        self.assertEqual(function_lines(asm), [
            'LOAD_GLOBAL(0)                  # global var 0, slot 0 (local)',
            'LOAD_STACK(-4)                  # slot 0',
            'SET_GLOBAL(0)                   # global var 0',
            'POP(4)                          # 1 slot',
            'RETURN()',
        ])
        self.assertEqual(function_lines(asm, comments = CommentOptions(stack_slots = False)), [
            'LOAD_GLOBAL(0)                  # global var 0',
            'LOAD_STACK(-4)',
            'SET_GLOBAL(0)                   # global var 0',
            'POP(4)',
            'RETURN()',
        ])

    def test_unreachable_code_gets_no_stack_comments(self):
        '''Fidelity mode keeps the code after RETURN; it jumps into the reachable code, whose label says so, and into
        itself, whose label stays bare'''
        asm = Asm()
        asm.push_int(LEFT_VALUE)
        asm.label('target'); asm.pop(WORD_SIZE); asm.ret()
        asm.label('dead'); asm.push_int(RIGHT_VALUE); asm.pop(WORD_SIZE); asm.jmp('target'); asm.jmp('dead')
        program = Program(Func(FUNC_NAME, 0, asm), pool = ())     # the code runs up to the function names
        parser, functions = program.disassemble(keep_unreachable_code = True)
        target, dead = (f"loc_{program.label(name):X}" for name in ('target', 'dead'))
        lines = [line.strip() for line in parser.format_function(functions[0])[2:]]
        self.assertEqual(lines, [
            f'PUSH_INT({LEFT_VALUE})',
            f'def _{target}(): pass',
            append_comment(f"label('{target}')", ['sp = 1', 'jumped to by unreachable code']),
            '',
            'POP(4)                          # 1 slot',
            'RETURN()',
            '',
            '# --- unreachable code ---',
            f'def _{dead}(): pass',
            f"label('{dead}')",
            '',
            f'PUSH_INT({RIGHT_VALUE})',
            'POP(4)',
            f"JMP('{target}')",
            f"JMP('{dead}')",
            '# --- end unreachable code ---',
        ])

    def test_blocks_formatted_without_a_layout_get_none(self):
        '''Even on a formatter that just formatted a function with one'''
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.pop(2 * WORD_SIZE); asm.ret()
        _, functions = Program(Func(FUNC_NAME, 1, asm)).disassemble()
        formatter = Formatter(FormatterContext())
        formatter.format_function(functions[0])
        self.assertEqual([line.strip() for line in formatter.format_entry_block(functions[0].entry_block)],
                         ['LOAD_STACK(-4)', 'POP(8)', 'RETURN()'])


class TestCallArguments(unittest.TestCase):
    def test_local_call_numbers_its_arguments_from_the_last_push(self):
        '''After a slot comment the number reads "passed as"; without stack comments it stands alone'''
        asm = Asm()
        asm.push_raw(0)                                                 # opens slot 1
        asm.push_raw(CALLER_ID); asm.push_raw('return')
        asm.load_stack(-4 * WORD_SIZE)                                  # sp 4: slot 0
        asm.load_stack(-4 * WORD_SIZE)                                  # sp 5: slot 1
        asm.push_int(LEFT_VALUE)
        asm.call(CALLEE_ID); asm.label('return')
        asm.pop(2 * WORD_SIZE); asm.ret()
        program = Program(Func(FUNC_NAME, 1, asm), returning_callee(3))
        label = f"label('loc_{program.label('return'):X}')"
        self.assertEqual(commented_lines(program, CommentOptions(call_args = True)), [
            'PUSH_RAW(RawInt(0x00000000))    # slot 1 (local)',
            'LOAD_STACK(-16)                 # slot 0 = arg1, passed as arg3',
            'LOAD_STACK(-16)                 # slot 1, passed as arg2',
            append_comment(f'PUSH_INT({LEFT_VALUE})', ['arg1']),
            append_comment(label, ['sp = 2']),
            'POP(8)                          # 2 slots',
        ])
        self.assertEqual(commented_lines(program, ARGUMENTS_ONLY), [
            'LOAD_STACK(-16)                 # arg3',
            'LOAD_STACK(-16)                 # arg2',
            append_comment(f'PUSH_INT({LEFT_VALUE})', ['arg1']),
        ])

    def test_zero_argument_call_numbers_nothing_below_it(self):
        asm = Asm()
        asm.push_int(LEFT_VALUE)                                        # stays below the call
        asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.call(CALLEE_ID); asm.label('return')
        asm.pop(WORD_SIZE); asm.ret()
        self.assertEqual(commented_lines(Program(main_function(asm), returning_callee()), ARGUMENTS_ONLY), [])

    def test_syscall_leaves_its_arguments_for_the_next_one(self):
        '''SYSCALL doesn't pop: a push a later SYSCALL reads again gets both numbers, in call order'''
        asm = Asm()
        asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2)
        asm.pop(WORD_SIZE); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 1)
        asm.pop(WORD_SIZE); asm.ret()
        self.assertEqual(commented_lines(Program(main_function(asm)), ARGUMENTS_ONLY), [
            append_comment(f'PUSH_INT({LEFT_VALUE})', ['arg2', 'arg1']),
            append_comment(f'PUSH_INT({RIGHT_VALUE})', ['arg1']),
        ])

    def test_script_call_arguments(self):
        asm = Asm()
        asm.frame('return'); asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE)
        asm.call_script(2); asm.label('return')
        asm.push_int(LEFT_VALUE); asm.call_script_no_return(1)
        self.assertEqual(commented_lines(Program(main_function(asm)), ARGUMENTS_ONLY), [
            append_comment(f'PUSH_INT({LEFT_VALUE})', ['arg2']),
            append_comment(f'PUSH_INT({RIGHT_VALUE})', ['arg1']),
            append_comment(f'PUSH_INT({LEFT_VALUE})', ['arg1']),
        ])

    def test_argument_joined_from_two_branches_numbers_both_pushes(self):
        asm = Asm()
        asm.push_raw(CALLER_ID); asm.push_raw('return')
        asm.get_reg(REG_INDEX); asm.jz('right')
        asm.push_int(LEFT_VALUE); asm.jmp('call')
        asm.label('right'); asm.push_int(RIGHT_VALUE)
        asm.label('call'); asm.call(CALLEE_ID); asm.label('return'); asm.ret()
        self.assertEqual(commented_lines(Program(main_function(asm), returning_callee(1)), ARGUMENTS_ONLY), [
            append_comment(f'PUSH_INT({LEFT_VALUE})', ['arg1']),
            append_comment(f'PUSH_INT({RIGHT_VALUE})', ['arg1']),
        ])


class TestFloatBitsAndFunctionIds(unittest.TestCase):
    def test_push_float_gets_its_bits_after_its_argument_and_a_float_default_none(self):
        asm = Asm()
        asm.push_float(FLOAT_VALUE); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 1); asm.pop(2 * WORD_SIZE); asm.ret()
        program = Program(Func(FUNC_NAME, 1, asm))
        program.entries[0].params[0].default_value = ScpValue(FLOAT_VALUE)
        parser, functions = program.disassemble()
        comments = CommentOptions(stack_slots = False, float_bits = True, call_args = True)
        lines = parser.format_function(functions[0], comments)
        self.assertNotIn('#', lines[1])
        self.assertEqual(lines[2].strip(), append_comment(f'PUSH_FLOAT({FLOAT_VALUE})', ['arg1', FLOAT_BITS]))

    def test_unreachable_code_keeps_the_global_var_and_float_bits(self):
        '''Neither needs the simulated stack, which unreachable code doesn't have'''
        asm = Asm()
        asm.ret()
        asm.label('dead'); asm.push_float(FLOAT_VALUE); asm.set_global(GLOBAL_INDEX); asm.jmp('dead')
        parser, functions = Program(main_function(asm), pool = ()).disassemble(keep_unreachable_code = True)
        for comments in (CommentOptions(), CommentOptions(stack_slots = False), ALL_COMMENTS):
            with self.subTest(comments = comments):
                lines = [line.strip() for line in parser.format_function(functions[0], comments)]
                bits = [FLOAT_BITS] if comments.float_bits else []
                self.assertIn(append_comment(f'PUSH_FLOAT({FLOAT_VALUE})', bits), lines)
                self.assertIn(append_comment(f'SET_GLOBAL({GLOBAL_INDEX})', [f'global var {GLOBAL_INDEX}']), lines)

    def test_function_id_line_above_the_decorator(self):
        asm = Asm()
        asm.ret()
        parser, functions = Program(main_function(asm), returning_callee()).disassemble()
        callee = functions[1]
        self.assertEqual(parser.format_function(callee, CommentOptions(function_ids = True))[:2],
                         [f'# id: 0x0001 offset: 0x{callee.offset:X}', '@scena.LLILCode()'])
        self.assertEqual(parser.format_function(callee)[0], '@scena.LLILCode()')

        callee.index = None                                             # a hand-built function has no table index
        self.assertEqual(parser.format_function(callee, CommentOptions(function_ids = True))[0], '@scena.LLILCode()')

    def test_index_is_the_table_position_not_the_code_order(self):
        '''The writer sorts the table by name and lays code out in source order, so Second comes first in the code'''
        with tempfile.TemporaryDirectory() as tmp_dir:
            dat = Path(tmp_dir) / 'test.dat'
            fresh_writer()
            writer = create_scp_writer(str(dat))

            @writer.LLILCode()
            def Second():
                RETURN()

            @writer.LLILCode()
            def First():
                RETURN()

            writer.run({})
            parser, functions = ScpParser.load(dat, round_trip = False, keep_unreachable_code = False)

        self.assertEqual([(func.name, func.index) for func in functions], [('Second', 1), ('First', 0)])
        self.assertEqual(parser.format_function(functions[0], CommentOptions(function_ids = True))[0],
                         f'# id: 0x0001 offset: 0x{functions[0].offset:X}')

    def test_opt_in_comments_are_off_by_default(self):
        config = ScenaDecompileConfig()
        self.assertEqual(CommentOptions(), CommentOptions(stack_slots = True, float_bits = False, function_ids = False,
                                                          call_args = False))
        self.assertEqual((config.stack_slot_comments, config.float_bits_comments, config.function_id_comments,
                          config.call_arg_comments), (True, False, False, False))


@unittest.skipUnless(CHECK_ALGO_USE_FILE.exists(), 'needs the sora2_1.0 corpus')
class TestRealScript(unittest.TestCase):
    def test_check_algo_use(self):
        '''The listing docs/FUTURE_WORK_LLIL.md item 8 shows'''
        parser, functions = ScpParser.load(CHECK_ALGO_USE_FILE, round_trip = False, keep_unreachable_code = False)
        lines = parser.gen_python_script(functions).split('\n')
        start = lines.index('def CheckAlgoUse(arg1: Value32, arg2: Value32, arg3: Value32):')
        expected = [
            '    DEBUG_SET_LINENO(161)',
            '    LOAD_STACK(-4)                  # slot 2 = arg1',
            '    PUSH_INT(1120)',
            '    EQ()',
            "    POP_JMP_ZERO('loc_3444')",
            '',
            '    DEBUG_SET_LINENO(162)',
            '    PUSH_CURRENT_FUNC_ID()',
            "    PUSH_RET_ADDR('loc_342F')",
            '    LOAD_STACK(-16)                 # slot 1 = arg2',
            '    LOAD_STACK(-24)                 # slot 0 = arg3',
            '    CALL(CheckSBreak)',
            '',
            '    def _loc_342F(): pass',
            "    label('loc_342F')               # sp = 3",
            '',
            '    GET_REG(0)',
            "    POP_JMP_ZERO('loc_3444')",
            '',
            '    DEBUG_SET_LINENO(163)',
            '    PUSH_INT(1)',
            '    SET_REG(0)',
            '    POP(12)                         # 3 slots',
            '    RETURN()',
            '',
            '    def _loc_3444(): pass',
            "    label('loc_3444')               # sp = 3",
            '',
            '    DEBUG_SET_LINENO(167)',
            '    PUSH_RAW(RawInt(0x00000000))    # slot 3 (local)',
            '    PUSH_INT(65535)',
            '    POP_TO(-4)                      # slot 3',
            '    DEBUG_SET_LINENO(168)',
            '    LOAD_STACK(-16)                 # slot 0 = arg3',
            '    PUSH_INT(2)',
        ]
        self.assertEqual(lines[start + 1:start + 1 + len(expected)], expected)

    def test_check_algo_use_with_every_opt_in_comment(self):
        '''First in the table, which is sorted by name, but not in the code; its local call passes two parameters'''
        parser, functions = ScpParser.load(CHECK_ALGO_USE_FILE, round_trip = False, keep_unreachable_code = False)
        self.assertEqual([func.index for func in parser.functions], list(range(len(parser.functions))))
        lines = parser.format_function(parser.get_func_by_name('CheckAlgoUse'), ALL_COMMENTS)
        self.assertEqual(lines[:3], [
            '# id: 0x0000 offset: 0x33FF',
            '@scena.LLILCode()',
            'def CheckAlgoUse(arg1: Value32, arg2: Value32, arg3: Value32):',
        ])
        self.assertIn('    LOAD_STACK(-16)                 # slot 1 = arg2, passed as arg2', lines)
        self.assertIn('    LOAD_STACK(-24)                 # slot 0 = arg3, passed as arg1', lines)

    def test_scena2py_flags(self):
        '''The defaults, then each flag the other way on its own'''
        markers = {
            'stack_slot_comments'   : '# slot 2 = arg1',
            'float_bits_comments'   : 'f32 0x',
            'function_id_comments'  : '# id: 0x0000 offset: 0x33FF',
            'call_arg_comments'     : '# arg1',
        }
        for flipped in (None, *markers):
            with self.subTest(flipped = flipped), tempfile.TemporaryDirectory() as tmp_dir:
                config = ScenaDecompileConfig()
                config.output_dir = Path(tmp_dir)
                config.write_ts = config.write_mlil_asm = False
                if flipped is not None:
                    setattr(config, flipped, not getattr(config, flipped))

                process_file(CHECK_ALGO_USE_FILE, config)
                text = (Path(tmp_dir) / CHECK_ALGO_USE_FILE.stem / f'{CHECK_ALGO_USE_FILE.stem}.py').read_text(encoding = 'utf-8')
                self.assertEqual({flag: marker in text for flag, marker in markers.items()},
                                 {flag: getattr(config, flag) for flag in markers})


if __name__ == '__main__':
    unittest.main()
