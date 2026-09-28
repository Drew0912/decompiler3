#!/usr/bin/env python3
'''Unit tests for parameter-slot stores: pop_to into a slot that still holds the caller's parameter is
a frame store (argN), not a new local.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILFrameStore, LowLevelILStackStore, LowLevelILConst, WORD_SIZE
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder, FalcomLLILFormatter
from falcom.ed9.ir.mlil.mlil_translator import FalcomLLILToMLILTranslator
from ir.mlil.mlil import MLILSetVar


FUNC_START = 0x1000


def build_function_with_pop_to(num_params: int, offset: int, *, name: str = 'pop_to_test'):
    '''Function with num_params parameters: pushes a marker value, then pop_to(offset)

    Returns the raw builder.function rather than calling finalize(): a real function
    would clean up its parameter slots with an explicit pop opcode before RETURN, but
    that is irrelevant to the instruction-shape assertions here, so skip finalize()'s
    unrelated sp == 0 end-of-function check rather than pad the test with a fake pop.
    '''
    builder = FalcomVMBuilder()
    builder.create_function(name, FUNC_START, num_params = num_params)
    entry = builder.create_basic_block(FUNC_START, name)
    builder.set_current_block(entry)

    builder.push_int(99)
    builder.pop_to(offset)

    return builder.function, entry


class TestPopToParameterSlot(unittest.TestCase):
    '''pop_to targeting a parameter slot emits a frame-relative store, not a new local'''

    def test_parameter_slot_emits_frame_store(self):
        # 1 parameter (slot 0). After push_int, sp=2; pop_to(-WORD_SIZE) pops back to sp=1,
        # then slot_index = 1 + (-WORD_SIZE // WORD_SIZE) = 0 - the sole parameter slot.
        _, entry = build_function_with_pop_to(num_params = 1, offset = -WORD_SIZE)

        inst = entry.instructions[-1]
        self.assertIsInstance(inst, LowLevelILFrameStore)
        self.assertNotIsInstance(inst, LowLevelILStackStore)
        self.assertEqual(inst.offset, 0)

    def test_non_parameter_slot_still_emits_stack_store(self):
        # 1 parameter (slot 0). pop_to(0) targets slot 1 (the just-pushed temp itself, a
        # local) - unaffected by this step, must keep today's StackStore behavior exactly.
        _, entry = build_function_with_pop_to(num_params = 1, offset = 0)

        inst = entry.instructions[-1]
        self.assertIsInstance(inst, LowLevelILStackStore)
        self.assertEqual(inst.slot_index, 1)

    def test_frame_offset_is_absolute_slot_times_word_size(self):
        # 2 parameters (slots 0, 1). The frame offset must come from the absolute slot
        # index (slot_index * WORD_SIZE), not the opcode's own sp-relative operand.
        _, entry_slot0 = build_function_with_pop_to(num_params = 2, offset = -2 * WORD_SIZE)
        inst_slot0 = entry_slot0.instructions[-1]
        self.assertIsInstance(inst_slot0, LowLevelILFrameStore)
        self.assertEqual(inst_slot0.offset, 0)

        _, entry_slot1 = build_function_with_pop_to(num_params = 2, offset = -1 * WORD_SIZE)
        inst_slot1 = entry_slot1.instructions[-1]
        self.assertIsInstance(inst_slot1, LowLevelILFrameStore)
        self.assertEqual(inst_slot1.offset, WORD_SIZE)


class TestPopToParameterSlotMLIL(unittest.TestCase):
    '''A frame store to a parameter slot translates to a write of that same parameter variable,
    not a disconnected local - this is the actual bug fix (see btlsys.PlayStartVoice).'''

    def test_translates_to_parameter_set_var(self):
        builder = FalcomVMBuilder()
        builder.create_function('pop_to_ret_test', FUNC_START, num_params = 1)
        entry = builder.create_basic_block(FUNC_START, 'pop_to_ret_test')
        builder.set_current_block(entry)

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
    '''LLILFormatter renders LowLevelILFrameStore like its StackStore sibling'''

    def test_simplified_format_shows_popped_value(self):
        inst = LowLevelILFrameStore(LowLevelILConst(42), offset = 0)

        lines = FalcomLLILFormatter.format_instruction_sequence([inst], indent = '')

        self.assertEqual(lines, ['STACK[fp + 0] = STACK[--sp] ; 42'])


if __name__ == '__main__':
    unittest.main()
