#!/usr/bin/env python3
'''Unit tests for POP/POP_N virtual-stack synchronization, and argument counts that reach past the pushes into the
function's own parameters.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILSyscall, WORD_SIZE
from tests.shared.llil_utils import SECOND_BLOCK_START, instructions_of, lift_asm, make_builder
from tests.shared.scp_asm import SYSCALL_FUNC, SYSCALL_SUBSYSTEM, Asm


PUSHED_VALUE = 7


class TestPopKeepsVstackInSync(unittest.TestCase):
    '''pop_bytes/pop_n discard the matching vstack entries, not just move sp - before the fix, a
    later operation could read a stale, already-discarded entry instead of the value actually
    beneath it.'''

    def test_single_word_pop_then_arithmetic(self):
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        builder.pop_bytes(WORD_SIZE)   # discard the '2'
        builder.push_int(3)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 0)   # the '1'
        self.assertEqual(add_inst.rhs.slot_index, 1)   # the fresh '3', not the stale '2'
        self.assertEqual(builder.vstack_size(), 1)

    def test_multi_word_pop_then_arithmetic(self):
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        builder.push_int(3)
        builder.push_int(4)
        builder.pop_bytes(2 * WORD_SIZE)   # discard '3' and '4' in one POP
        builder.push_int(5)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 1)   # the '2'
        self.assertEqual(add_inst.rhs.slot_index, 2)   # the fresh '5'
        self.assertEqual(builder.vstack_size(), 2)

    def test_pop_n_keeps_vstack_in_sync(self):
        builder = make_builder()

        builder.push_int(10)
        builder.push_int(20)
        builder.pop_n(1)   # discard the '20'
        builder.push_int(30)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 0)
        self.assertEqual(add_inst.rhs.slot_index, 1)

    def test_debug_log_then_arithmetic(self):
        # DEBUG_LOG discards its logged args via pop_n internally - same bug class.
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        builder.debug_log(1)   # logs and discards the '2'
        builder.push_int(3)
        add_inst = builder.add()

        self.assertEqual(add_inst.lhs.slot_index, 0)
        self.assertEqual(add_inst.rhs.slot_index, 1)

    def test_pop_before_branch_preserves_trimmed_state(self):
        builder = make_builder()
        target = builder.create_basic_block(SECOND_BLOCK_START, 'stack_sync_test_target')

        builder.push_int(1)
        builder.push_int(2)
        builder.pop_bytes(WORD_SIZE)   # vstack should now hold just slot 0

        builder.save_stack_for_offset(target.start)

        saved = builder.saved_stacks[target.start]
        self.assertEqual(len(saved.values), 1)
        self.assertEqual(saved.values[0].slot_index, 0)

    def test_pop_into_parameter_area_empties_vstack_without_error(self):
        # Parameters occupy slots [0, num_params) and are never pushed to the vstack, so a POP
        # that crosses all the way into that area should just empty the vstack, not raise.
        builder = make_builder(num_params = 2)

        builder.push_int(1)
        builder.push_int(2)
        builder.pop_bytes(4 * WORD_SIZE)   # sp 4 -> 0, through both pushes and into params

        self.assertEqual(builder.sp_get(), 0)
        self.assertEqual(builder.vstack_size(), 0)

    def test_pop_no_longer_has_a_script_pointer_override(self):
        '''FalcomVMBuilder.pop() is deleted (its isinstance(expr, LowLevelILConstScript) check
        was unreachable - the vstack only ever holds LowLevelILStackLoad), so pop() now resolves
        straight to the base class and behaves like an ordinary single pop.'''
        builder = make_builder()

        builder.push_int(1)
        builder.push_int(2)
        popped = builder.pop()

        self.assertEqual(popped.slot_index, 1)
        self.assertEqual(builder.vstack_size(), 1)
        self.assertEqual(builder.sp_get(), 1)


class TestPopValidation(unittest.TestCase):
    '''A POP of 0 bytes is a legal no-op; a malformed POP fails in the parser's stack simulation first.'''

    def test_pop_bytes_zero_is_still_a_legal_no_op(self):
        builder = make_builder()
        builder.push_int(1)

        builder.pop_bytes(0)

        self.assertEqual(builder.sp_get(), 1)
        self.assertEqual(builder.vstack_size(), 1)


class TestArgumentCountReachingIntoParameters(unittest.TestCase):
    '''A function's own parameters sit on the VM stack below its pushes. An argument count larger than the pushes uses
    a parameter's slot in place: the lift fails at that instruction naming it, rather than take it as an argument.'''

    def assert_lift_fails_at(self, mnemonic: str, build, verb: str = 'uses'):
        asm = Asm()
        build(asm)

        uses = rf'{verb} the slot of parameter 1 \(arg1\) '
        with self.assertRaisesRegex(ValueError, rf'{mnemonic} at 0x[0-9A-F]+: {uses}'):
            lift_asm(asm, argc = 1)

    def test_syscall_with_more_arguments_than_pushed(self):
        def build(asm: Asm):
            asm.push_int(PUSHED_VALUE); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2)
            asm.pop(2 * WORD_SIZE); asm.ret()

        self.assert_lift_fails_at('SYSCALL', build)

    def test_debug_log_with_more_arguments_than_pushed(self):
        def build(asm: Asm):
            asm.push_int(PUSHED_VALUE); asm.debug_log(2); asm.ret()

        self.assert_lift_fails_at('DEBUG_LOG', build)

    def test_tail_call_with_more_arguments_than_pushed(self):
        def build(asm: Asm):
            asm.push_int(PUSHED_VALUE); asm.call_script_no_return(2)

        self.assert_lift_fails_at('CALL_SCRIPT_NO_RETURN', build, 'forwards')

    def test_syscall_with_exactly_the_pushed_arguments_is_accepted(self):
        asm = Asm()
        asm.push_int(PUSHED_VALUE); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 1); asm.pop(2 * WORD_SIZE); asm.ret()

        _, llil_func = lift_asm(asm, argc = 1)

        syscall, = instructions_of(llil_func, LowLevelILSyscall)
        self.assertEqual(len(syscall.args), syscall.argc)


if __name__ == '__main__':
    unittest.main()
