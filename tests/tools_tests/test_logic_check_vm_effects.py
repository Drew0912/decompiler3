#!/usr/bin/env python3
"""The VM's effects in the logic check (tools/logic_check/vm_effects.py): each operation's effect on a layer's storage,
and each layer handing them its own operands"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.llil.llil import WORD_SIZE
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, MESSAGE, OUT_INITIAL, REG_INDEX, STORED, UNRELATED_ARG, call, categories, hlil_categories,
    initialised_out_parameter_function, mlil_and_hlil, reference_and_mlil, return_nothing,
)
from tests.shared.scp_asm import Asm
from logic_check.facts import Effect
from logic_check.state import ESCAPED, GLOBAL_EPOCH, MEMORY_EPOCH, REGISTER_EPOCH, State
from logic_check.trees import ENTRY, const
from logic_check.vm_effects import VMEffects


# === Assembled functions ===

def pointer_store_function() -> tuple[Asm, int]:
    """f(p): *p = STORED: a store through the caller's pointer"""
    asm = Asm()
    asm.push_int(STORED); asm.pop_to_deref(-WORD_SIZE)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def debug_log_after_call_function() -> tuple[Asm, int]:
    """callee(); a DEBUG_LOG; GLOBAL_A = REG[0]: a call that clobbers nothing between a call and its result's read"""
    asm = Asm()
    call(asm, 'after')
    asm.push_str(MESSAGE); asm.debug_log(1)
    asm.get_reg(0); asm.set_global(GLOBAL_A)
    return_nothing(asm)
    return asm, 0


class TestVMEffects(unittest.TestCase):
    """The VM's effects on a layer's storage (VMEffects), one definition for the three layers, so a slip in one makes
    every layer wrong alike: each operation's whole effect and the state it leaves"""

    ADDRESS       = 0x100
    PASSED        = ('stack', 1)                        # its address an argument; it holds POINTEE's
    POINTEE       = ('stack', 2)                        # reached through PASSED, never written
    ESCAPED_LOCAL = ('stack', 3)
    PARAMETER     = ('param', 1)                        # its address an argument, never written
    UNREACHED     = ('stack', 4)
    SPLIT         = ('name', f'reg{REG_INDEX}_v1')      # a de-SSA split of register REG_INDEX

    def setUp(self):
        neutral = {self.SPLIT: ('reg', REG_INDEX)}
        self.vm = VMEffects(lambda key: neutral.get(key, key))
        for key in (self.PASSED, self.POINTEE, self.ESCAPED_LOCAL, self.PARAMETER, self.UNREACHED):
            self.vm.address_of(key)

    @classmethod
    def escaped(cls, key: tuple) -> dict:
        return {(ESCAPED, key): (ESCAPED,)}

    def test_store_global(self):
        state = State()
        value = ('address', self.PASSED)
        self.assertEqual(self.vm.store_global(state, self.ADDRESS, GLOBAL_A, value),
                         Effect(self.ADDRESS, 'store global', GLOBAL_A, (value,)))
        self.assertEqual(state.items, {('global', GLOBAL_A): value, **self.escaped(self.PASSED)})

        state = State()
        self.vm.store_global(state, self.ADDRESS, GLOBAL_A, const(STORED))
        self.assertEqual(state.items, {('global', GLOBAL_A): const(STORED)})

    def test_store_deref(self):
        """The pointer first, then the value; memory behind pointers changes, no local"""
        state = State({self.UNREACHED: const(STORED)})
        pointer, value = self.PARAMETER, ('address', self.POINTEE)
        self.assertEqual(self.vm.store_deref(state, self.ADDRESS, pointer, value),
                         Effect(self.ADDRESS, 'store deref', None, (pointer, value)))
        self.assertEqual(state.items, {self.UNREACHED: const(STORED), MEMORY_EPOCH: self.ADDRESS,
                                       **self.escaped(self.POINTEE)})

    def test_return(self):
        """The value given, or for none the result register's; every other register passed on, the state unchanged"""
        result = ('reg', VMEffects.RESULT_REGISTER)
        state = State({('reg', REG_INDEX): const(STORED), result: const(OUT_INITIAL)})
        before = dict(state.items)
        registers = {('reg', index): const(STORED) if index == REG_INDEX else ('reg', index, ENTRY)
                     for index in range(VMEffects.REGISTER_COUNT) if index != VMEffects.RESULT_REGISTER}
        self.assertEqual(self.vm.ret(state, self.ADDRESS, const(UNRELATED_ARG)),
                         Effect(self.ADDRESS, 'return', None, (const(UNRELATED_ARG),), storage=registers))
        self.assertEqual(self.vm.ret(state, self.ADDRESS),
                         Effect(self.ADDRESS, 'return', None, (const(OUT_INITIAL),), storage=registers))
        self.assertEqual(state.items, before)

    def test_call_passes_and_changes(self):
        """Passed: the locals an argument holds the address of, one whose address escaped before, one a passed local
        points to; a never-written parameter as itself, a never-written stack slot as undefined. Then no register or
        global is left but the result, its value, every other register is read after the call, memory behind pointers
        changes, and so does every passed local"""
        state = State({self.PASSED: ('address', self.POINTEE), self.ESCAPED_LOCAL: const(STORED),
                       **self.escaped(self.ESCAPED_LOCAL), self.UNREACHED: const(UNRELATED_ARG),
                       ('global', GLOBAL_A): const(OUT_INITIAL), ('reg', REG_INDEX): const(OUT_INITIAL)})
        args = (('address', self.PASSED), ('address', self.PARAMETER))
        passed = {self.PARAMETER: self.PARAMETER, self.PASSED: ('address', self.POINTEE),
                  self.POINTEE: ('undef', self.POINTEE), self.ESCAPED_LOCAL: const(STORED)}
        self.assertEqual(self.vm.call(state, self.ADDRESS, 'script call', MESSAGE, args),
                         Effect(self.ADDRESS, 'script call', MESSAGE, args, storage=passed))

        self.assertEqual(state.items, {
            ('reg', VMEffects.RESULT_REGISTER): ('call', self.ADDRESS),
            GLOBAL_EPOCH: self.ADDRESS, REGISTER_EPOCH: ('after', self.ADDRESS), MEMORY_EPOCH: self.ADDRESS,
            **{key: ('slot_after', key, self.ADDRESS) for key in passed},
            **self.escaped(self.ESCAPED_LOCAL), self.UNREACHED: const(UNRELATED_ARG)})

    def test_call_kinds(self):
        for kind, target in (('call', MESSAGE), ('script call', MESSAGE), ('syscall', (GLOBAL_A, GLOBAL_B))):
            with self.subTest(kind=kind):
                self.assertEqual(self.vm.call(State(), self.ADDRESS, kind, target, ()),
                                 Effect(self.ADDRESS, kind, target, ()))

    def test_call_that_does_not_deliver_its_result(self):
        """A layer's call that writes no result register (an MLIL call with another output or none, an HLIL call)
        leaves it uncaptured, a value no LLIL holds; the rest as a call that delivers it"""
        state = State()
        self.vm.call(state, self.ADDRESS, 'call', MESSAGE, (), delivers_result=False)
        self.assertEqual(state.items, {
            ('reg', VMEffects.RESULT_REGISTER): ('uncaptured', self.ADDRESS),
            GLOBAL_EPOCH: self.ADDRESS, REGISTER_EPOCH: ('after', self.ADDRESS), MEMORY_EPOCH: self.ADDRESS})

    def test_call_that_does_not_clobber(self):
        state = State({self.PASSED: const(STORED), ('reg', REG_INDEX): const(OUT_INITIAL)})
        before = dict(state.items)
        args = (('address', self.PASSED),)
        self.assertEqual(self.vm.call(state, self.ADDRESS, 'call', DEBUG_LOG_CALL_TARGET, args, clobbers=False),
                         Effect(self.ADDRESS, 'call', DEBUG_LOG_CALL_TARGET, args))
        self.assertEqual(state.items, before)

    def test_write(self):
        """An address written to a register, or to a de-SSA split of one, escapes; to a stack slot not"""
        value = ('address', self.PASSED)
        for key, escapes in ((('reg', REG_INDEX), True), (self.SPLIT, True), (self.UNREACHED, False)):
            with self.subTest(key=key):
                state = State()
                self.vm.write(state, key, value)
                self.assertEqual(state.items, {key: value, **(self.escaped(self.PASSED) if escapes else {})})

    def test_address_written_to_a_register_reaches_the_next_call(self):
        state = State()
        self.vm.write(state, ('reg', REG_INDEX), ('address', self.PASSED))
        self.vm.call(state, self.ADDRESS, 'call', MESSAGE, ())
        self.assertEqual(state.get(self.PASSED, None), ('slot_after', self.PASSED, self.ADDRESS))


class TestLayerOperands(unittest.TestCase):
    """Each layer hands the shared VM effects its own operands: a function making the effect compares clean on both
    pairs, so a layer handing them otherwise differs from the next"""

    def test_store_through_a_pointer(self):
        self.assertEqual(categories(*reference_and_mlil(pointer_store_function, 1)), set())
        self.assertEqual(hlil_categories(*mlil_and_hlil(pointer_store_function, 1)), set())

    def test_result_kept_across_a_call_that_clobbers_nothing(self):
        """callee(); a DEBUG_LOG; GLOBAL_A = REG[0]: the debug.log call, which has no output, leaves the result where
        the call put it"""
        self.assertEqual(categories(*reference_and_mlil(debug_log_after_call_function)), set())
        self.assertEqual(hlil_categories(*mlil_and_hlil(debug_log_after_call_function)), set())

    def test_local_written_in_its_memory_form(self):
        """v = OUT_INITIAL before callee(&v): HLIL writes v as *(&v), the local, not memory behind a pointer"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(initialised_out_parameter_function)), set())


if __name__ == '__main__':
    unittest.main()
