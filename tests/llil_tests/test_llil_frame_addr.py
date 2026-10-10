#!/usr/bin/env python3
'''Unit tests for push_stack_addr's parameter-slot check: the address of a slot that still holds
the caller's parameter is frame-relative (&argN), not the address of a new local.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILFrameAddr, LowLevelILStackAddr, WORD_SIZE
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter
from falcom.ed9.ir.mlil.mlil_translator import FalcomLLILToMLILTranslator
from ir.mlil.mlil import MLILSetVar, MLILAddressOf, MLILVar
from tests.shared.llil_utils import make_builder


def build_function_with_push_stack_addr(num_params: int, offset: int):
    '''The entry block of a function with num_params parameters whose first instruction is push_stack_addr(offset);
    sp starts at num_params, so a parameter slot takes a negative offset'''
    builder = make_builder(num_params)
    entry = builder.current_block

    builder.push_stack_addr(offset)

    return entry


class TestPushStackAddrParameterSlot(unittest.TestCase):
    '''push_stack_addr targeting a parameter slot emits a frame-relative address, not the
    address of an unrelated phantom local'''

    def test_parameter_slot_emits_frame_addr(self):
        # 1 parameter (slot 0). sp starts at 1 (num_params), so offset -WORD_SIZE targets
        # slot 0 - the sole parameter.
        entry = build_function_with_push_stack_addr(num_params = 1, offset = -WORD_SIZE)

        stack_store = entry.instructions[0]
        self.assertIsInstance(stack_store.value, LowLevelILFrameAddr)
        self.assertNotIsInstance(stack_store.value, LowLevelILStackAddr)
        self.assertEqual(stack_store.value.offset, 0)

    def test_non_parameter_slot_still_emits_stack_addr(self):
        # 1 parameter (slot 0) and a pushed local (slot 1): offset -WORD_SIZE targets the local,
        # not the parameter - unaffected by this fix, must keep today's StackAddr behavior.
        builder = make_builder(num_params = 1)
        entry = builder.current_block
        builder.push_int(0)                     # slot 1; sp 1->2
        builder.push_stack_addr(-WORD_SIZE)

        stack_store = entry.instructions[-2]    # the address's own store, before its SpAdd
        self.assertIsInstance(stack_store.value, LowLevelILStackAddr)
        self.assertEqual(stack_store.value.slot_index, 1)

    def test_frame_offset_is_absolute_slot_times_word_size(self):
        # 2 parameters (slots 0, 1), sp 2 on entry. The frame offset must come from the absolute slot
        # index, not the opcode's own sp-relative operand.
        for offset, frame_offset in ((-2 * WORD_SIZE, 0), (-WORD_SIZE, WORD_SIZE)):
            with self.subTest(offset = offset):
                entry = build_function_with_push_stack_addr(num_params = 2, offset = offset)
                inst = entry.instructions[0].value
                self.assertIsInstance(inst, LowLevelILFrameAddr)
                self.assertEqual(inst.offset, frame_offset)


class TestPushStackAddrParameterSlotMLIL(unittest.TestCase):
    '''A frame address of a parameter slot translates to &argN, not the address of a
    disconnected local - this is the actual bug fix.'''

    def test_translates_to_address_of_parameter(self):
        # push_stack_addr's own push() emits the StackStore that actually carries the
        # LowLevelILFrameAddr value (a later pop_to would only see a fresh StackLoad
        # placeholder reading it back, not the AddressOf expression itself) - so the
        # instruction to inspect is the very first one this call produces.
        builder = make_builder(num_params = 1)

        builder.push_stack_addr(-WORD_SIZE)  # var_s1 (slot 1) = &arg1; sp 1->2
        builder.pop_bytes(2 * WORD_SIZE)      # sp 2->0 (the pushed temp, then the param itself)
        builder.ret()

        mlil_func = FalcomLLILToMLILTranslator().translate(builder.function)
        block = mlil_func.basic_blocks[0]

        set_var_inst = block.instructions[0]
        self.assertIsInstance(set_var_inst, MLILSetVar)
        self.assertIsInstance(set_var_inst.value, MLILAddressOf)
        self.assertIsInstance(set_var_inst.value.operand, MLILVar)
        self.assertEqual(set_var_inst.value.operand.var.name, 'arg1')


class TestFrameAddrFormatting(unittest.TestCase):
    '''LLILFormatter renders LowLevelILFrameAddr like its StackAddr sibling'''

    def test_simplified_format_shows_pushed_address(self):
        entry = build_function_with_push_stack_addr(num_params = 1, offset = -WORD_SIZE)

        lines = FalcomLLILFormatter.format_instruction_sequence([entry.instructions[0]], indent = '')

        # ; [1] is the slot the resulting address value itself is pushed to (sp was 1 at the
        # time of the push), not the slot 0 the address points at (fp + 0, shown in the value)
        self.assertEqual(lines, ['STACK[sp] = &STACK[fp + 0] ; [1]'])


if __name__ == '__main__':
    unittest.main()
