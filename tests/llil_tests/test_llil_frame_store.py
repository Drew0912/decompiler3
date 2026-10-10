#!/usr/bin/env python3
'''Unit tests for parameter-slot stores: pop_to into a slot that still holds the caller's parameter is
a frame store (argN), not a new local.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILFrameStore, LowLevelILStackStore, LowLevelILConst, WORD_SIZE
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter
from falcom.ed9.ir.mlil.mlil_translator import FalcomLLILToMLILTranslator
from ir.mlil.mlil import MLILSetVar
from tests.shared.llil_utils import make_builder


def build_function_with_pop_to(num_params: int, offset: int):
    '''The entry block of a function with num_params parameters that pushes a marker, then pop_to(offset); not
    finalized (no cleanup pop or RETURN), since only the store's shape is checked'''
    builder = make_builder(num_params)
    entry = builder.current_block

    builder.push_int(99)
    builder.pop_to(offset)

    return entry


class TestPopToParameterSlot(unittest.TestCase):
    '''pop_to targeting a parameter slot emits a frame-relative store, not a new local'''

    def test_parameter_slot_emits_frame_store(self):
        # 1 parameter (slot 0). After push_int, sp=2; pop_to(-WORD_SIZE) pops back to sp=1,
        # then slot_index = 1 + (-WORD_SIZE // WORD_SIZE) = 0 - the sole parameter slot.
        entry = build_function_with_pop_to(num_params = 1, offset = -WORD_SIZE)

        inst = entry.instructions[-1]
        self.assertIsInstance(inst, LowLevelILFrameStore)
        self.assertNotIsInstance(inst, LowLevelILStackStore)
        self.assertEqual(inst.offset, 0)

    def test_non_parameter_slot_still_emits_stack_store(self):
        # 1 parameter (slot 0). pop_to(0) targets slot 1 (the just-pushed temp itself, a
        # local) - unaffected by this step, must keep today's StackStore behavior exactly.
        entry = build_function_with_pop_to(num_params = 1, offset = 0)

        inst = entry.instructions[-1]
        self.assertIsInstance(inst, LowLevelILStackStore)
        self.assertEqual(inst.slot_index, 1)

    def test_frame_offset_is_absolute_slot_times_word_size(self):
        # 2 parameters (slots 0, 1). The frame offset must come from the absolute slot
        # index (slot_index * WORD_SIZE), not the opcode's own sp-relative operand.
        for offset, frame_offset in ((-2 * WORD_SIZE, 0), (-WORD_SIZE, WORD_SIZE)):
            with self.subTest(offset = offset):
                inst = build_function_with_pop_to(num_params = 2, offset = offset).instructions[-1]
                self.assertIsInstance(inst, LowLevelILFrameStore)
                self.assertEqual(inst.offset, frame_offset)


class TestPopToParameterSlotMLIL(unittest.TestCase):
    '''A frame store to a parameter slot translates to a write of that same parameter variable,
    not a disconnected local - this is the actual bug fix (see btlsys.PlayStartVoice).'''

    def test_translates_to_parameter_set_var(self):
        builder = make_builder(num_params = 1)

        builder.push_int(99)
        builder.pop_to(-WORD_SIZE)
        builder.pop_bytes(WORD_SIZE)  # a real function cleans up its own param slot before RETURN
        builder.ret()  # MLIL finalize() requires every block to end in a terminal

        mlil_func = FalcomLLILToMLILTranslator().translate(builder.function)
        block = mlil_func.basic_blocks[0]

        set_var_inst = block.instructions[-2]  # last instruction is the translated ret
        self.assertIsInstance(set_var_inst, MLILSetVar)
        self.assertEqual(set_var_inst.var.name, 'arg1')


class TestFrameStoreFormatting(unittest.TestCase):
    '''FalcomLLILFormatter renders LowLevelILFrameStore (POP_TO into a parameter) like its StackStore sibling'''

    def test_simplified_format_shows_popped_value(self):
        inst = LowLevelILFrameStore(LowLevelILConst(42), offset = 0)

        lines = FalcomLLILFormatter.format_instruction_sequence([inst], indent = '')

        self.assertEqual(lines, ['STACK[fp + 0] = STACK[--sp] ; 42'])


if __name__ == '__main__':
    unittest.main()
