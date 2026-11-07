#!/usr/bin/env python3
"""Unit tests for dereference opcodes (LOAD_STACK_DEREF/POP_TO_DEREF) and how POP_TO_DEREF prints in LLIL."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILLoad, LowLevelILFrameLoad, WORD_SIZE
from falcom.ed9.ir.llil.llil_formatter import FalcomLLILFormatter
from tests.shared.llil_utils import build_function_with_deref

NOT_A_PARAMETER_SLOT_1 = '^dereferences slot 1, which holds no caller parameter: '


class TestDerefLift(unittest.TestCase):
    """LLIL-level shape: a dereference targeting a parameter slot builds a pointer expression
    exactly like load_stack (frame-relative), then wraps it in Load/Store (the Store: TestDerefFormatting)."""

    def test_load_stack_deref_wraps_frame_load(self):
        # 1 parameter (slot 0). offset=0 at entry (sp=1) -> slot_index = 1 + 0 = 1... use
        # -WORD_SIZE so slot_index = 1 - 1 = 0, the sole parameter slot.
        _, entry = build_function_with_deref(num_params=1, offset=-WORD_SIZE, deref_write=False)

        # load_stack_deref pushes via push(LowLevelILLoad(...)), i.e. a StackStore whose
        # value is the Load, followed by the push's own (visible) SpAdd.
        store_inst = entry.instructions[-2]
        self.assertIsInstance(store_inst.value, LowLevelILLoad)
        self.assertIsInstance(store_inst.value.src, LowLevelILFrameLoad)
        self.assertEqual(store_inst.value.src.offset, 0)

    def test_load_stack_deref_at_non_parameter_slot_raises(self):
        # 1 parameter (slot 0). offset=0 -> slot_index = 1, not a parameter slot.
        with self.assertRaisesRegex(NotImplementedError, NOT_A_PARAMETER_SLOT_1):
            build_function_with_deref(num_params=1, offset=0, deref_write=False)

    def test_pop_to_deref_at_non_parameter_slot_raises(self):
        # 1 parameter (slot 0). offset=0 after the push -> slot_index 1, not a parameter slot.
        with self.assertRaisesRegex(NotImplementedError, NOT_A_PARAMETER_SLOT_1):
            build_function_with_deref(num_params=1, offset=0, deref_write=True)


class TestDerefFormatting(unittest.TestCase):
    """FalcomLLILFormatter shows the pop POP_TO_DEREF hides, like POP_TO's"""

    def test_simplified_format_shows_popped_value(self):
        _, entry = build_function_with_deref(num_params=1, offset=-WORD_SIZE, deref_write=True)

        lines = FalcomLLILFormatter.format_instruction_sequence([entry.instructions[-1]], indent='')

        self.assertEqual(lines, ['*STACK[fp + 0] = STACK[--sp] ; STACK[sp<1>]'])


if __name__ == '__main__':
    unittest.main()
