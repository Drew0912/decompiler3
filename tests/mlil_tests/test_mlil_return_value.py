#!/usr/bin/env python3
"""ReturnValuePass (ir/mlil/passes/pass_return_value.py) on assembled functions through the new path whole
(convert_falcom_llil_to_mlil_stack) and the shared checks (tests/shared/stack_translator_checks.py): a return of the
result register right after its store returns the stored value; and where it must leave the store: a statement
between (T1), another register, the stores in another block"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from ir.llil.llil import WORD_SIZE
from ir.mlil import ReturnValuePass
from tests.shared.llil_utils import lift_asm
from tests.shared.logic_check_functions import GLOBAL_A, call, return_nothing
from tests.shared.scp_asm import Asm, returning_callee
from tests.shared.stack_translator_checks import StackTranslationTestCase, statements, translated

SUBSYSTEM, COMMAND = 1, 2
VALUE, CHANGED = 7, 9
LINE = 5
OTHER_REGISTER = 1


def stored_in_both_arms(asm: Asm):
    """REG[0] = 1 or REG[0] = 2 by GLOBAL[0], then a join at 'join'"""
    asm.load_global(0); asm.jz('second')
    asm.push_int(1); asm.set_reg(0); asm.jmp('join')
    asm.label('second'); asm.push_int(2); asm.set_reg(0)
    asm.label('join')


class ReturnValueTestCase(StackTranslationTestCase):
    def convert(self, asm: Asm, argc: int = 0, callee_argc: int = 0):
        """asm's MLIL through the new path, after the shared checks"""
        _, llil = lift_asm(asm, argc=argc, others=(returning_callee(callee_argc),))
        return self.checked_translation(llil, convert_falcom_llil_to_mlil_stack)


class TestReturnedValues(ReturnValueTestCase):
    def test_a_constant(self):
        asm = Asm()
        return_nothing(asm)

        self.assertEqual(statements(self.convert(asm)), ['return 0'])

    def test_a_calls_result(self):
        """The corpus's wrappers: GET_REG 0; SET_REG 0; RETURN after the call"""
        def script_call(asm: Asm):
            asm.frame('back'); asm.push_int(3); asm.call_script(1); asm.label('back')

        def syscall(asm: Asm):
            asm.syscall(SUBSYSTEM, COMMAND, 0)

        for make, called in ((script_call, 'this.g(3)'), (syscall, f'syscall({SUBSYSTEM}, {COMMAND})')):
            with self.subTest(make.__name__):
                asm = Asm()
                make(asm); asm.get_reg(0); asm.set_reg(0); asm.ret()

                self.assertEqual(statements(self.convert(asm)), [f't1 = {called}', 'return t1'])

    def test_an_expression_over_a_calls_result(self):
        asm = Asm()
        call(asm, 'after'); asm.get_reg(0); asm.push_int(1); asm.add(); asm.set_reg(0); asm.ret()

        self.assertEqual(statements(self.convert(asm)), ['t1 = callee()', 'return (t1 + 1)'])

    def test_a_value_reading_the_register_itself(self):
        """After a join: the register read where the store read it, the arms' stores kept"""
        asm = Asm()
        stored_in_both_arms(asm)
        asm.get_reg(0); asm.push_int(1); asm.add(); asm.set_reg(0); asm.ret()
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil)[-1], 'return (REG[0] + 1)')
        self.assertIn('REG[0] = 1', statements(mlil))
        self.assertIn('REG[0] = 2', statements(mlil))

    def test_a_line_marker_between(self):
        """A hand edit's: the marker kept, the return after it"""
        asm = Asm()
        asm.push_int(VALUE); asm.set_reg(0); asm.debug_set_lineno(LINE); asm.ret()

        self.assertEqual(statements(self.convert(asm)), [f'debug.line({LINE})', f'return {VALUE}'])


class TestKeptStores(ReturnValueTestCase):
    def test_a_write_between(self):
        """T1: the value may read what the write changes, so the store stays where it is. One parameter (a pointer)
        and a local"""
        writes = {
            'the global it reads': (lambda asm: (asm.push_int(CHANGED), asm.set_global(GLOBAL_A)),
                                    f'GLOBAL[{GLOBAL_A}] = {CHANGED}'),
            'a local':             (lambda asm: (asm.push_int(CHANGED), asm.pop_to(-WORD_SIZE)), f'var_s1 = {CHANGED}'),
            'memory':              (lambda asm: (asm.push_int(CHANGED), asm.pop_to_deref(-2 * WORD_SIZE)),
                                    f'*arg1 = {CHANGED}'),
            'another register':    (lambda asm: (asm.push_int(CHANGED), asm.set_reg(OTHER_REGISTER)),
                                    f'REG[{OTHER_REGISTER}] = {CHANGED}'),
        }
        for name, (write, written) in writes.items():
            with self.subTest(name):
                asm = Asm()
                asm.push_raw(0)                         # the local, slot 1
                asm.load_global(GLOBAL_A); asm.set_reg(0)
                write(asm)
                asm.pop(2 * WORD_SIZE)                  # the local and the parameter
                asm.ret()

                self.assertEqual(statements(self.convert(asm, argc=1))[-3:],
                                 [f'REG[0] = GLOBAL[{GLOBAL_A}]', written, 'return REG[0]'])

    def test_a_store_to_another_register(self):
        """The return passes it on to the caller as it is"""
        asm = Asm()
        asm.push_int(VALUE); asm.set_reg(OTHER_REGISTER); asm.ret()

        self.assertEqual(statements(self.convert(asm)), [f'REG[{OTHER_REGISTER}] = {VALUE}', 'return REG[0]'])

    def test_the_stores_before_a_join(self):
        """Each predecessor would need its own return: left to HLIL"""
        asm = Asm()
        stored_in_both_arms(asm)
        asm.ret()
        mlil = self.convert(asm)

        self.assertEqual(statements(mlil)[-1], 'return REG[0]')
        self.assertIn('REG[0] = 1', statements(mlil))
        self.assertIn('REG[0] = 2', statements(mlil))


class TestNoResultRegister(unittest.TestCase):
    def test_a_function_without_one_is_unchanged(self):
        asm = Asm()
        return_nothing(asm)
        _, llil = lift_asm(asm, others=(returning_callee(),))
        mlil = translated(llil)
        mlil.result_register = None
        before = statements(mlil)

        ReturnValuePass().run(mlil)

        self.assertEqual(statements(mlil), before)


if __name__ == '__main__':
    unittest.main()
