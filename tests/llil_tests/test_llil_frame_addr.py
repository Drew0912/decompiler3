#!/usr/bin/env python3
"""Unit tests for push_stack_addr's parameter-slot check: the address of a slot that still holds
the caller's parameter is frame-relative (&argN), not the address of a new local."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILFrameAddr, LowLevelILStackAddr
from falcom.ed9.assembler.vm import WORD_SIZE
from falcom.ed9.ir.llil.llil_formatter import ED9LLILFormatter
from falcom.ed9.ir.mlil.mlil_converter import convert_ed9_llil_to_mlil_stack
from ir.mlil.mlil import MLILSetVar, MLILAddressOf, MLILVar
from tests.shared.llil_utils import make_builder


def build_function_with_push_stack_addr(num_params: int, slot_offset: int):
    """The entry block of a function with num_params parameters whose first instruction is
    push_stack_addr(slot_offset); sp starts at num_params, so a parameter slot takes a negative offset"""
    builder = make_builder(num_params)
    entry = builder.current_block

    builder.push_stack_addr(slot_offset)

    return entry


class TestPushStackAddrParameterSlot(unittest.TestCase):
    """push_stack_addr targeting a parameter slot emits a frame-relative address, not the
    address of an unrelated phantom local"""

    def test_non_parameter_slot_still_emits_stack_addr(self):
        # 1 parameter (slot 0) and a pushed local (slot 1): slot offset -1 targets the local,
        # not the parameter - unaffected by this fix, must keep today's StackAddr behavior.
        builder = make_builder(num_params=1)
        entry = builder.current_block
        builder.push_int(0)                     # slot 1; sp 1->2
        builder.push_stack_addr(-1)

        stack_store = entry.instructions[-2]    # the address's own store, before its SpAdd
        self.assertIsInstance(stack_store.value, LowLevelILStackAddr)
        self.assertEqual(stack_store.value.slot_index, 1)

    def test_frame_slot_offset_is_the_absolute_slot(self):
        # 2 parameters (slots 0, 1), sp 2 on entry. The frame slot offset must come from the absolute slot
        # index, not the opcode's own sp-relative operand.
        for slot_offset, frame_slot in ((-2, 0), (-1, 1)):
            with self.subTest(slot_offset=slot_offset):
                entry = build_function_with_push_stack_addr(num_params=2, slot_offset=slot_offset)
                inst = entry.instructions[0].value
                self.assertIsInstance(inst, LowLevelILFrameAddr)
                self.assertEqual(inst.slot_offset, frame_slot)


class TestPushStackAddrParameterSlotMLIL(unittest.TestCase):
    """A frame address of a parameter slot translates to &argN, not the address of a
    disconnected local - this is the actual bug fix."""

    def test_translates_to_address_of_parameter(self):
        # push_stack_addr's own push() emits the StackStore that actually carries the
        # LowLevelILFrameAddr value (a later pop_to would only see a fresh StackLoad
        # placeholder reading it back, not the AddressOf expression itself) - so the
        # instruction to inspect is the very first one this call produces.
        builder = make_builder(num_params=1)

        builder.push_stack_addr(-1)  # var_s1 (slot 1) = &arg1; sp 1->2
        builder.pop_bytes(2 * WORD_SIZE)      # sp 2->0 (the pushed temp, then the param itself)
        builder.ret()

        mlil_func = convert_ed9_llil_to_mlil_stack(builder.function)
        block = mlil_func.basic_blocks[0]

        set_var_inst = block.instructions[0]
        self.assertIsInstance(set_var_inst, MLILSetVar)
        self.assertIsInstance(set_var_inst.value, MLILAddressOf)
        self.assertIsInstance(set_var_inst.value.operand, MLILVar)
        self.assertEqual(set_var_inst.value.operand.var.name, 'arg1')


class TestFrameAddrFormatting(unittest.TestCase):
    """LLILFormatter renders LowLevelILFrameAddr like its StackAddr sibling"""

    def test_simplified_format_shows_pushed_address(self):
        entry = build_function_with_push_stack_addr(num_params=1, slot_offset=-1)

        lines = ED9LLILFormatter.format_instruction_sequence([entry.instructions[0]], indent='')

        # ; [1] is the slot the resulting address value itself is pushed to (sp was 1 at the
        # time of the push), not the slot 0 the address points at (fp + 0, shown in the value)
        self.assertEqual(lines, ['STACK[sp] = &STACK[fp + 0] ; [1]'])


if __name__ == '__main__':
    unittest.main()
