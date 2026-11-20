#!/usr/bin/env python3
"""The HLIL DSL's formatters and exact check (falcom/ed9/formatter/hlil_dsl/): assembled bytecode through the
decompiler's own steps (lifted, converted, printed, the text checked), each form printed as the DSL writes it and found
exact - a literal Python would fold, mirror or format wrapped, Python's precedence kept; each fallback with its
reason"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.assembler.vm import WORD_SIZE
from falcom.ed9.formatter.hlil_dsl.function_formatter import INDENT
from falcom.ed9.formatter.hlil_dsl.script_formatter import HLILScriptFormatter
from falcom.ed9.ir.hlil.hlil_converter import hlil_for_dsl
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_ed9_llil_to_mlil_stack
from falcom.ed9.structs.scp_types import ScpGlobalVar
from tests.shared.scp_asm import (CALLEE_ID, CALLEE_NAME, CALLER_ID, FUNC_NAME, SYSCALL_FUNC as CMD,
                                  SYSCALL_SUBSYSTEM as SUBSYSTEM, Asm, Func, Program, returning_callee)

GAME = 'sora2'


def dsl_part(*functions: Func, global_names: tuple[str, ...] = ()) -> HLILScriptFormatter:
    """The script's DSL part, each function handed its HLIL as the decompiler makes it"""
    parser, disassembled = Program(*functions).disassemble()
    parser.game = GAME      # a mixed script always has one: its DSL names come from the game's helper
    parser.global_vars = [ScpGlobalVar(name, ScpGlobalVar.Type.Integer) for name in global_names]
    dsl = HLILScriptFormatter(parser)
    lifter = ED9VMLifter(parser=parser)
    for func in disassembled:
        dsl.add(func, hlil_for_dsl(convert_ed9_llil_to_mlil_stack(lifter.lift_function(func))))

    return dsl


def returned(asm: Asm, argc: int = 0):
    """The compiler's return of nothing: a Raw 0 in the result register, the parameters popped"""
    asm.push_raw(0)
    asm.set_reg(0)
    if argc:
        asm.pop(argc * WORD_SIZE)

    asm.ret()


def syscall(asm: Asm, argc: int):
    asm.syscall(SUBSYSTEM, CMD, argc)
    asm.pop(argc * WORD_SIZE)


def local_call(asm: Asm, label: str, *args_last_first):
    asm.push_raw(CALLER_ID)
    asm.push_raw(label)
    for value in args_last_first:
        asm.push_int(value)

    asm.call(CALLEE_ID)
    asm.label(label)


class PrinterTestCase(unittest.TestCase):
    def assert_printed(self, asm: Asm, body: list[str], argc: int = 0, callee_argc: int = 0,
                       global_names: tuple[str, ...] = ()):
        """f prints as body, its lines after the def, and its text is exact"""
        dsl = dsl_part(Func(FUNC_NAME, argc, asm), returning_callee(callee_argc), global_names=global_names)
        self.assertIsNone(dsl.reasons.get(FUNC_NAME))
        self.assertEqual(dsl.lines[FUNC_NAME][2:], [f'{INDENT}{line}' for line in body])

    def assert_llil(self, asm: Asm, reason: str, argc: int = 0, callee: Func = returning_callee(),
                    global_names: tuple[str, ...] = ()):
        """f stays LLIL for reason"""
        dsl = dsl_part(Func(FUNC_NAME, argc, asm), callee, global_names=global_names)
        self.assertNotIn(FUNC_NAME, dsl.lines)
        self.assertEqual(dsl.reasons[FUNC_NAME], reason)


class TestForms(PrinterTestCase):
    def test_the_definition(self):
        asm = Asm()
        returned(asm, argc=1)
        dsl = dsl_part(Func(FUNC_NAME, 1, asm), returning_callee())
        self.assertEqual(dsl.lines[FUNC_NAME], ['@scena.HLILCode()', f'def {FUNC_NAME}(arg1: Value32):',
                                                f'{INDENT}Return()'])

    def test_constants(self):
        asm = Asm()
        asm.push_raw(7); asm.push_str('this'); asm.push_float(0.3); asm.push_int(-5)
        syscall(asm, 4)
        returned(asm)
        self.assert_printed(asm, [f'Syscall({SUBSYSTEM}, {CMD}, -5, 0.3, "this", Raw(7))', 'Return()'])

    def test_literals_python_would_fold_mirror_or_format(self):
        asm = Asm()
        asm.push_float(0.3); asm.push_int(2); asm.mul()             # two literals
        syscall(asm, 1)
        asm.push_int(8); asm.not_()                                 # a unary operator on one
        syscall(asm, 1)
        asm.push_int(9); asm.load_stack(-2 * WORD_SIZE); asm.lt()   # one left of a comparison
        syscall(asm, 1)
        asm.push_str('this'); asm.load_stack(-2 * WORD_SIZE); asm.mod()     # a string left of %
        syscall(asm, 1)
        returned(asm, argc=1)
        self.assert_printed(asm, [f'Syscall({SUBSYSTEM}, {CMD}, Float(0.3) * 2)',
                                  f'Syscall({SUBSYSTEM}, {CMD}, ~Int(8))',
                                  f'Syscall({SUBSYSTEM}, {CMD}, Int(9) < arg1)',
                                  f'Syscall({SUBSYSTEM}, {CMD}, Str("this") % arg1)',
                                  'Return()'], argc=1)

    def test_python_precedence(self):
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.push_int(4); asm.bitwise_and(); asm.push_int(0); asm.eq()
        syscall(asm, 1)
        asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.push_int(2); asm.mul()
        syscall(asm, 1)
        asm.load_stack(-WORD_SIZE); asm.push_int(2); asm.load_stack(-3 * WORD_SIZE); asm.sub(); asm.sub()
        syscall(asm, 1)
        asm.load_stack(-WORD_SIZE); asm.push_int(2); asm.lt(); asm.push_int(1); asm.eq()
        syscall(asm, 1)
        returned(asm, argc=1)
        self.assert_printed(asm, [f'Syscall({SUBSYSTEM}, {CMD}, (arg1 & 4) == 0)',
                                  f'Syscall({SUBSYSTEM}, {CMD}, (arg1 + 1) * 2)',
                                  f'Syscall({SUBSYSTEM}, {CMD}, arg1 - (2 - arg1))',
                                  f'Syscall({SUBSYSTEM}, {CMD}, (arg1 < 2) == 1)',
                                  'Return()'], argc=1)

    def test_eager_logic(self):
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.logical_and(); asm.push_int(2); asm.logical_and()
        syscall(asm, 1)
        asm.load_stack(-WORD_SIZE); asm.push_int(3); asm.logical_or()
        syscall(asm, 1)
        returned(asm, argc=1)
        self.assert_printed(asm, [f'Syscall({SUBSYSTEM}, {CMD}, And(arg1, 1, 2))',
                                  f'Syscall({SUBSYSTEM}, {CMD}, Or(arg1, 3))',
                                  'Return()'], argc=1)

    def test_stores_a_local_and_a_value_returned(self):
        asm = Asm()
        asm.push_int(5); asm.set_global(0)
        asm.load_stack(-WORD_SIZE); asm.set_reg(1)
        asm.push_int(3); asm.pop_to(-WORD_SIZE)
        asm.push_raw(0); asm.push_int(6); asm.pop_to(-WORD_SIZE)
        asm.load_stack(-WORD_SIZE); asm.set_reg(0); asm.pop(2 * WORD_SIZE); asm.ret()
        self.assert_printed(asm, ["var_s1 = Local('var_s1')",
                                  'Set(this.flag, 5)',
                                  'Set(REGS[1], arg1)',
                                  'Set(arg1, 3)',
                                  'Let(var_s1, 6)',
                                  'Return(var_s1)'], argc=1, global_names=('flag',))

    def test_calls(self):
        asm = Asm()
        local_call(asm, 'first', 2, 1)
        local_call(asm, 'second', 4, 3); asm.get_reg(0); asm.set_reg(2)
        asm.frame('third'); asm.push_int(5); asm.call_script(1); asm.label('third')
        returned(asm)
        self.assert_printed(asm, [f'{CALLEE_NAME}(1, 2)',
                                  f'Set(REGS[2], {CALLEE_NAME}(3, 4))',
                                  'script.this.g(5)',
                                  'Return()'], callee_argc=2)

    def test_intrinsics(self):
        asm = Asm()
        asm.push_str('this'); asm.push_int(5); asm.popn(2)
        asm.debug_int(3)
        returned(asm)
        self.assert_printed(asm, ['PopN(5, "this")', 'DebugInt(3)', 'Return()'])


class TestControlFlow(PrinterTestCase):
    def test_an_if_its_else_and_a_local_in_a_block(self):
        """The bare test (the jump's own != 0 left out); the local declared in the block and popped at its end"""
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.jz('else')
        asm.push_raw(0); asm.push_int(5); asm.pop_to(-WORD_SIZE)
        asm.load_stack(-WORD_SIZE)
        syscall(asm, 1)
        asm.pop(WORD_SIZE)
        asm.jmp('end')
        asm.label('else')
        asm.push_int(7)
        syscall(asm, 1)
        asm.label('end')
        returned(asm, argc=1)
        self.assert_printed(asm, ["var_s1 = Local('var_s1')",
                                  'If(arg1, [',
                                  f'{INDENT}Let(var_s1, 5),',
                                  f'{INDENT}Syscall({SUBSYSTEM}, {CMD}, var_s1),',
                                  ']).Else([',
                                  f'{INDENT}Syscall({SUBSYSTEM}, {CMD}, 7),',
                                  '])',
                                  'Return()'], argc=1)

    def test_an_else_holding_one_if_is_an_else_if(self):
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.eq(); asm.jz('second')
        asm.push_int(10)
        syscall(asm, 1)
        asm.jmp('end')
        asm.label('second')
        asm.load_stack(-WORD_SIZE); asm.push_int(2); asm.eq(); asm.jz('third')
        asm.push_int(20)
        syscall(asm, 1)
        asm.jmp('end')
        asm.label('third')
        asm.push_int(30)
        syscall(asm, 1)
        asm.label('end')
        returned(asm, argc=1)
        self.assert_printed(asm, ['If(arg1 == 1, [',
                                  f'{INDENT}Syscall({SUBSYSTEM}, {CMD}, 10),',
                                  ']).ElseIf(arg1 == 2, [',
                                  f'{INDENT}Syscall({SUBSYSTEM}, {CMD}, 20),',
                                  ']).Else([',
                                  f'{INDENT}Syscall({SUBSYSTEM}, {CMD}, 30),',
                                  '])',
                                  'Return()'], argc=1)

    def test_an_arm_that_returns(self):
        """An early return: the code after it is the If's other path"""
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.jz('other')
        asm.push_int(1); asm.set_reg(0); asm.pop(WORD_SIZE); asm.ret()
        asm.label('other')
        asm.push_int(2); asm.set_reg(0); asm.pop(WORD_SIZE); asm.ret()
        self.assert_printed(asm, ['If(arg1, [',
                                  f'{INDENT}Return(1),',
                                  '])',
                                  'Return(2)'], argc=1)

    def test_an_empty_arm(self):
        """The code's if (arg1) {} else {...}, which HLIL shows as if (arg1 == 0) {...}"""
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.jz('else')
        asm.jmp('end')
        asm.label('else')
        asm.push_int(7)
        syscall(asm, 1)
        asm.label('end')
        returned(asm, argc=1)
        self.assert_printed(asm, ['If(arg1, []).Else([',
                                  f'{INDENT}Syscall({SUBSYSTEM}, {CMD}, 7),',
                                  '])',
                                  'Return()'], argc=1)

    def test_a_loop_its_local_and_a_break(self):
        """The test at the head, the body's local popped before the jump back, a Break popping it before the jump past
        the loop. HLIL holds the code after the ending arm as its else, ending in a continue: printed so (the tidying
        is later)"""
        asm = Asm()
        asm.label('head')
        asm.load_stack(-WORD_SIZE); asm.jz('end')
        asm.push_raw(0); asm.push_int(5); asm.pop_to(-WORD_SIZE)
        asm.load_stack(-WORD_SIZE); asm.jz('next')
        asm.pop(WORD_SIZE); asm.jmp('end')
        asm.label('next')
        asm.load_stack(-WORD_SIZE)
        syscall(asm, 1)
        asm.pop(WORD_SIZE); asm.jmp('head')
        asm.label('end')
        returned(asm, argc=1)
        self.assert_printed(asm, ["var_s1 = Local('var_s1')",
                                  'While(arg1, [',
                                  f'{INDENT}Let(var_s1, 5),',
                                  f'{INDENT}If(var_s1, [',
                                  f'{INDENT}{INDENT}Break(),',
                                  f'{INDENT}]).Else([',
                                  f'{INDENT}{INDENT}Syscall({SUBSYSTEM}, {CMD}, var_s1),',
                                  f'{INDENT}{INDENT}Continue(),',
                                  f'{INDENT}]),',
                                  '])',
                                  'Return()'], argc=1)

    def test_an_endless_loop_its_arms_leave(self):
        """while (1) is a real test; a body whose every path leaves has no jump back of its own"""
        asm = Asm()
        asm.label('head')
        asm.push_int(1); asm.jz('end')
        asm.load_stack(-WORD_SIZE); asm.jz('else')
        asm.push_int(10)
        syscall(asm, 1)
        asm.jmp('end')
        asm.label('else')
        asm.push_int(20)
        syscall(asm, 1)
        asm.jmp('head')
        asm.label('end')
        returned(asm, argc=1)
        self.assert_printed(asm, ['While(1, [',
                                  f'{INDENT}If(arg1, [',
                                  f'{INDENT}{INDENT}Syscall({SUBSYSTEM}, {CMD}, 10),',
                                  f'{INDENT}{INDENT}Break(),',
                                  f'{INDENT}]).Else([',
                                  f'{INDENT}{INDENT}Syscall({SUBSYSTEM}, {CMD}, 20),',
                                  f'{INDENT}{INDENT}Continue(),',
                                  f'{INDENT}]),',
                                  '])',
                                  'Return()'], argc=1)


class TestFallbacks(PrinterTestCase):
    def test_a_logical_not_is_not_exact_yet(self):
        """HLIL reads EZ as == 0 (the EZ mark is a later slice's), which lowers to EQ: the reason names the first
        opcode the lowering misses"""
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.ez()
        syscall(asm, 1)
        returned(asm, argc=1)
        self.assert_llil(asm, 'not exact: opcode 1, expected EZ, got PUSH_INT 0', argc=1)

    def test_a_jump_if_not_zero(self):
        """HLIL shows its test as == 0; with an else, no form lowers to it; without one, the empty-arm form is tried
        and the check refuses it"""
        with_else = Asm()
        with_else.load_stack(-WORD_SIZE); with_else.jnz('else')
        with_else.push_int(10)
        syscall(with_else, 1)
        with_else.jmp('end')
        with_else.label('else')
        with_else.push_int(20)
        syscall(with_else, 1)
        with_else.label('end')
        returned(with_else, argc=1)
        self.assert_llil(with_else, 'negated test', argc=1)

        alone = Asm()
        alone.load_stack(-WORD_SIZE); alone.jnz('end')
        alone.push_int(10)
        syscall(alone, 1)
        alone.label('end')
        returned(alone, argc=1)
        self.assert_llil(alone, 'not exact: opcode 1, expected POP_JMP_NOT_ZERO 5, got POP_JMP_ZERO 3', argc=1)

    def test_loops_the_dsl_has_no_form_for(self):
        """A loop tested at its end (do-while), and a jump from an inner loop past the outer one (a labelled break)"""
        tested_last = Asm()
        tested_last.label('head')
        tested_last.push_int(10)
        syscall(tested_last, 1)
        tested_last.load_stack(-WORD_SIZE); tested_last.jz('end')
        tested_last.jmp('head')
        tested_last.label('end')
        returned(tested_last, argc=1)
        self.assert_llil(tested_last, 'do-while', argc=1)

        leaving_two = Asm()
        leaving_two.label('outer')
        leaving_two.load_stack(-WORD_SIZE); leaving_two.jz('end')
        leaving_two.label('inner')
        leaving_two.push_int(1); leaving_two.jz('inner_end')
        leaving_two.load_stack(-WORD_SIZE); leaving_two.jz('stay')
        leaving_two.jmp('end')
        leaving_two.label('stay')
        leaving_two.push_int(10)
        syscall(leaving_two, 1)
        leaving_two.jmp('inner')
        leaving_two.label('inner_end')
        leaving_two.push_int(20)
        syscall(leaving_two, 1)
        leaving_two.jmp('outer')
        leaving_two.label('end')
        returned(leaving_two, argc=1)
        self.assert_llil(leaving_two, 'labelled loop', argc=1)

    def test_an_address_taken(self):
        asm = Asm()
        asm.push_raw(0)
        asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
        asm.label('back')
        asm.pop(WORD_SIZE)
        returned(asm)
        self.assert_llil(asm, 'address taken', callee=returning_callee(1))

    def test_globals_the_text_cannot_name(self):
        asm = Asm()
        asm.push_int(5); asm.set_global(0)
        returned(asm)
        self.assert_llil(asm, 'unnamed global')
        self.assert_llil(asm, 'global name', global_names=('my-flag',))

    def test_a_callee_named_as_a_parameter(self):
        asm = Asm()
        local_call(asm, 'back')
        returned(asm, argc=1)
        self.assert_llil(asm, 'callee name clash', argc=1, callee=returning_callee()._replace(name='arg1'))

    def test_a_function_named_as_a_dsl_name_leaves_every_function_llil(self):
        asm = Asm()
        returned(asm)
        dsl = dsl_part(Func(FUNC_NAME, 0, asm), returning_callee()._replace(name='Set'))
        self.assertEqual(dsl.lines, {})
        self.assertEqual(dsl.reasons, {FUNC_NAME: 'functions named as DSL names: Set',
                                       'Set': 'functions named as DSL names: Set'})


if __name__ == '__main__':
    unittest.main()
