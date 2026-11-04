#!/usr/bin/env python3
"""CallResultPass (ir/mlil/passes/pass_call_result.py) on assembled functions through the decompile path whole
(convert_falcom_llil_to_mlil_stack) and the shared checks (tests/shared/stack_translator_checks.py): reads of the
result register forwarded to the call's temporary, dead result stores dropped and unread outputs cleared, the
translator's copies becoming the call's output; and where it must leave a store: live into another block, an author's
own"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from ir.llil.llil import WORD_SIZE
from ir.mlil import CallResultPass
from ir.mlil.mlil import MediumLevelILCall, MLILCallScript
from tests.shared.llil_utils import lift_asm
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, MESSAGE, call, optional_call_result_function, return_nothing,
)
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee
from tests.shared.stack_translator_checks import StackTranslationTestCase, statements, translated

SUBSYSTEM, COMMAND = 1, 2
LINE = 5
RETURNED = ['return 0']                         # return_nothing's, through ReturnValuePass


class CallResultTestCase(StackTranslationTestCase):
    def convert(self, asm: Asm, callee_argc: int = 0):
        """asm's MLIL through the decompile path, after the shared checks"""
        _, llil = lift_asm(asm, others=(returning_callee(callee_argc),))
        return self.checked_translation(llil, convert_falcom_llil_to_mlil_stack)

    def calls(self, mlil) -> list[MediumLevelILCall]:
        return [inst for inst in mlil.iter_instructions() if isinstance(inst, MediumLevelILCall)]


class TestDroppedStores(CallResultTestCase):
    def test_a_result_nothing_reads(self):
        """Its store dropped, the call kept with no output, its temporary gone"""
        asm = Asm()
        call(asm, 'after', 7)
        return_nothing(asm)
        mlil = self.convert(asm, callee_argc=1)

        self.assertEqual(statements(mlil), ['callee(7)', *RETURNED])
        self.assertIsNone(self.calls(mlil)[0].output)
        self.assertNotIn('t1', mlil.locals)

    def test_a_result_read_in_the_calls_block(self):
        asm = Asm()
        call(asm, 'after', 7); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm, callee_argc=1)

        self.assertEqual(statements(mlil), ['t1 = callee(7)', f'GLOBAL[{GLOBAL_A}] = t1', *RETURNED])

    def test_a_result_read_by_a_condition(self):
        asm = Asm()
        call(asm, 'after'); asm.get_reg(0); asm.jz('skip')
        asm.push_int(1); asm.set_global(GLOBAL_A)
        asm.label('skip'); return_nothing(asm)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil)[:2][0], 't1 = callee()')
        self.assertTrue(statements(mlil)[1].startswith('if ((t1 == 0))'), statements(mlil))

    def test_a_result_read_by_the_next_calls_argument(self):
        asm = Asm()
        asm.push_raw(CALLER_ID); asm.push_raw('second')
        call(asm, 'first', 5); asm.get_reg(0)
        asm.call(CALLEE_ID); asm.label('second')
        return_nothing(asm)
        mlil = self.convert(asm, callee_argc=1)

        self.assertEqual(statements(mlil), ['t1 = callee(5)', 'callee(t1)', *RETURNED])

    def test_a_syscall_and_a_script_call_alike(self):
        def syscall(asm: Asm, _: str):
            asm.syscall(SUBSYSTEM, COMMAND, 0)

        def script_call(asm: Asm, back: str):
            asm.frame(back); asm.call_script(0); asm.label(back)

        for make in (syscall, script_call):
            with self.subTest(make.__name__):
                asm = Asm()
                make(asm, 'first'); asm.get_reg(0); asm.set_global(GLOBAL_A)
                make(asm, 'second')
                return_nothing(asm)
                mlil = self.convert(asm)

                self.assertEqual(statements(mlil)[1], f'GLOBAL[{GLOBAL_A}] = t1')
                self.assertEqual([call.output for call in self.calls(mlil)][1:], [None])


class TestForwarding(CallResultTestCase):
    def test_through_a_popn(self):
        """POPN writes no register"""
        asm = Asm()
        call(asm, 'after'); asm.push_str(MESSAGE); asm.popn(1); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil)[:3], ['t1 = callee()', f'POPN("{MESSAGE}")', f'GLOBAL[{GLOBAL_A}] = t1'])

    def test_stopped_by_a_store_to_the_register(self):
        asm = Asm()
        call(asm, 'after'); asm.push_int(5); asm.set_reg(0); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil), ['callee()', 'REG[0] = 5', f'GLOBAL[{GLOBAL_A}] = REG[0]', *RETURNED])

    def test_stopped_by_the_next_call(self):
        """A read after two calls reads the second's temporary"""
        asm = Asm()
        call(asm, 'first'); call(asm, 'second'); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil), ['callee()', 't2 = callee()', f'GLOBAL[{GLOBAL_A}] = t2', *RETURNED])

    def test_a_tail_call_returns_its_temporary(self):
        asm = Asm()
        asm.push_int(3); asm.push_int(4); asm.set_reg(1); asm.get_reg(1)
        asm.call_script_no_return(2)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil), ['REG[1] = 4', 't1 = this.g(REG[1], 3)', 'return t1'])
        call_node = next(inst for inst in mlil.iter_instructions() if isinstance(inst, MLILCallScript))
        self.assertTrue(call_node.tail_call)


class TestKeptStores(CallResultTestCase):
    def test_a_result_read_in_another_block(self):
        """The store kept, the read there the register's"""
        def after_a_join() -> Asm:
            asm, _ = optional_call_result_function()
            return asm

        def after_a_loop() -> Asm:
            asm = Asm()
            asm.push_int(0)
            asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(3); asm.lt(); asm.jz('done')
            call(asm, 'back')
            asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
            asm.jmp('head')
            asm.label('done'); asm.get_reg(0); asm.set_global(GLOBAL_A); asm.pop(WORD_SIZE)
            return_nothing(asm)
            return asm

        for build in (after_a_join, after_a_loop):
            with self.subTest(build.__name__):
                mlil = self.convert(build())

                self.assertIn('REG[0] = t1', statements(mlil))
                self.assertIn(f'GLOBAL[{GLOBAL_A}] = REG[0]', statements(mlil))

    def test_a_result_read_by_a_call_argument_in_another_block(self):
        """The argument is read before the call writes the register"""
        asm = Asm()
        asm.load_global(0); asm.jz('join')
        call(asm, 'after', 5)
        asm.label('join'); asm.push_raw(CALLER_ID); asm.push_raw('last'); asm.get_reg(0); asm.call(CALLEE_ID)
        asm.label('last'); return_nothing(asm)
        mlil = self.convert(asm, callee_argc=1)

        self.assertIn('REG[0] = t1', statements(mlil))
        self.assertIn('callee(REG[0])', statements(mlil))

    def test_an_authors_store_after_the_call(self):
        """GET_REG 0; SET_REG 0 after a call is the script's own store: kept, reading the temporary, dead or not (a
        global store before the return, so ReturnValuePass leaves the live one)"""
        live = Asm()
        live.frame('back'); live.push_int(3); live.call_script(1); live.label('back')
        live.get_reg(0); live.set_reg(0); live.push_int(5); live.set_global(GLOBAL_A); live.ret()
        dead = Asm()
        call(dead, 'first'); dead.get_reg(0); dead.set_reg(0); call(dead, 'second')
        return_nothing(dead)

        self.assertEqual(statements(self.convert(live)), ['t1 = this.g(3)', 'REG[0] = t1', f'GLOBAL[{GLOBAL_A}] = 5',
                                                          'return REG[0]'])
        self.assertEqual(statements(self.convert(dead)), ['t1 = callee()', 'REG[0] = t1', 'callee()', *RETURNED])


class TestTranslatorsCopies(CallResultTestCase):
    def test_a_copy_becomes_the_calls_output(self):
        """The first call's result, pending across the second, copied by the translator: written by the call"""
        asm = Asm()
        call(asm, 'first', 1); asm.get_reg(0)
        call(asm, 'second', 2); asm.get_reg(0)
        asm.add(); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm, callee_argc=1)

        self.assertEqual(statements(mlil), ['t2 = callee(1)', 't3 = callee(2)', f'GLOBAL[{GLOBAL_A}] = (t2 + t3)',
                                            *RETURNED])
        self.assertNotIn('t1', mlil.locals)

    def test_a_line_marker_between(self):
        asm = Asm()
        call(asm, 'first', 1); asm.get_reg(0)
        asm.debug_set_lineno(LINE); call(asm, 'second', 2); asm.get_reg(0)
        asm.add(); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm, callee_argc=1)

        self.assertEqual(statements(mlil)[:3], ['t2 = callee(1)', f'debug.line({LINE})', 't3 = callee(2)'])

    def test_a_result_copied_twice(self):
        """Two copies right after the call (a hand edit's GET_REG 0 twice): neither becomes the call's output"""
        asm = Asm()
        call(asm, 'first'); asm.get_reg(0); asm.get_reg(0)
        call(asm, 'second')
        asm.add(); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil), ['t1 = callee()', 't2 = t1', 't3 = t1', 'callee()',
                                            f'GLOBAL[{GLOBAL_A}] = (t2 + t3)', *RETURNED])

    def test_a_result_read_before_its_copy(self):
        """The temporary read elsewhere too: the copy stays"""
        asm = Asm()
        call(asm, 'first'); asm.get_reg(0); asm.get_reg(0); asm.set_global(GLOBAL_A)
        call(asm, 'second'); asm.get_reg(0)
        asm.add(); asm.set_global(GLOBAL_B)
        return_nothing(asm)
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil), ['t1 = callee()', f'GLOBAL[{GLOBAL_A}] = t1', 't2 = t1', 't3 = callee()',
                                            f'GLOBAL[{GLOBAL_B}] = (t2 + t3)', *RETURNED])


class TestNoResultRegister(unittest.TestCase):
    def test_a_function_without_one_is_unchanged(self):
        asm = Asm()
        call(asm, 'after'); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        _, llil = lift_asm(asm, others=(returning_callee(),))
        mlil = translated(llil)
        mlil.result_register = None
        before = statements(mlil)

        CallResultPass().run(mlil)

        self.assertEqual(statements(mlil), before)


if __name__ == '__main__':
    unittest.main()
