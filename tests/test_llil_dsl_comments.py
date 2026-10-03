#!/usr/bin/env python3
'''Unit tests for the LLIL DSL's stack comments: the slot each offset opcode addresses and what it holds, the depth at
labels and POP's slot count, read from the parser's StackLayout and aligned in one column with the other trailing
comments.'''

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
from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from ir.llil.llil import WORD_SIZE
from test_scp_stack_simulation import (
    Asm, Func, Program, FUNC_NAME, GLOBAL_INDEX, LEFT_VALUE, PARAM_COUNT, REG_INDEX, RIGHT_VALUE,
)

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'
CHECK_ALGO_USE_FILE = SORA2_DIR / 'ai' / 'ai_chr5122_e00.dat'


def function_lines(asm: Asm, argc: int = 0, comments: CommentOptions = CommentOptions()) -> list[str]:
    '''The .py body of the one function asm assembles, without its indent'''
    parser, functions = Program(Func(FUNC_NAME, argc, asm)).disassemble()
    return [line.strip() for line in parser.format_function(functions[0], comments)[2:]]


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

    def test_scena2py_flag(self):
        for stack_slots in (True, False):
            with self.subTest(stack_slots = stack_slots), tempfile.TemporaryDirectory() as tmp_dir:
                config = ScenaDecompileConfig()
                config.output_dir = Path(tmp_dir)
                config.write_ts = config.write_mlil_asm = False
                config.stack_slot_comments = stack_slots
                process_file(CHECK_ALGO_USE_FILE, config)
                text = (Path(tmp_dir) / CHECK_ALGO_USE_FILE.stem / f'{CHECK_ALGO_USE_FILE.stem}.py').read_text(encoding = 'utf-8')
                self.assertEqual('# slot 2 = arg1' in text and '# sp = 3' in text, stack_slots)


if __name__ == '__main__':
    unittest.main()
