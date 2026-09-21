#!/usr/bin/env python3
'''Unit tests for .py label emission (only offsets something references) - Step 5 of the LLIL/MLIL hardening plan.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.disasm import *
from falcom.ed9.disasm.ed9_optable import ed9_create_fallthrough_jump
from falcom.ed9.parser import *


def disasm_to_dsl(name: str, bytecode: bytes) -> list[str]:
    '''Disassemble hand-coded bytecode and format it, same path scena2py.py uses for .py output'''
    context = DisassemblerContext(create_fallthrough_jump = ed9_create_fallthrough_jump)
    disasm = Disassembler(ED9_INSTRUCTION_TABLE, context)

    func = Function()
    func.name = name
    func.offset = 0
    func.is_common_func = False
    func.entry_block = disasm.disasm_function(bytecode, offset = 0, name = name)

    lines = Formatter(FormatterContext()).format_function(func)
    return [line.rstrip() for line in lines]


class TestDeadFallthroughLabelOmitted(unittest.TestCase):
    '''The block right after a conditional branch exists only because the branch ends a basic
    block - nothing actually jumps there, so it must get no label.'''

    def test_fallthrough_after_pop_jmp_zero_gets_no_label(self):
        bytecode = bytes([
            0x09, 0x00,                          # 0x00: GET_REG(0)
            0x0F, 0x12, 0x00, 0x00, 0x00,        # 0x02: POP_JMP_ZERO('loc_12')
            0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x07: PUSH_INT(1)  <- dead fall-through, offset 0x07
            0x0B, 0x18, 0x00, 0x00, 0x00,        # 0x0D: JMP('loc_18')
            0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x12: PUSH_INT(0)  <- real target of POP_JMP_ZERO
            0x0A, 0x00,                          # 0x18: SET_REG(0)  <- real target of JMP
            0x0D,                                # 0x1A: RETURN()
        ])

        lines = [line.strip() for line in disasm_to_dsl('test_cond', bytecode)]

        self.assertNotIn("label('loc_7')", lines)
        self.assertNotIn('def _loc_7(): pass', lines)
        self.assertIn("label('loc_12')", lines)
        self.assertIn("label('loc_18')", lines)


class TestReferencedEntryBlockGetsLabel(unittest.TestCase):
    '''A backward branch to offset 0 makes the entry block itself a real jump target - it must
    get a label too, even though the entry block previously never received one at all.'''

    def test_backward_jump_to_offset_zero_labels_the_entry_block(self):
        bytecode = bytes([
            0x09, 0x00,                          # 0x00: GET_REG(0)
            0x00, 0x04, 0x0A, 0x00, 0x00, 0x40,  # 0x02: PUSH_INT(10)
            0x19,                                # 0x08: LT()
            0x0F, 0x1E, 0x00, 0x00, 0x00,        # 0x09: POP_JMP_ZERO('loc_1E')
            0x09, 0x00,                          # 0x0E: GET_REG(0)   <- dead fall-through, offset 0x0E
            0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x10: PUSH_INT(1)
            0x10,                                # 0x16: ADD()
            0x0A, 0x00,                          # 0x17: SET_REG(0)
            0x0B, 0x00, 0x00, 0x00, 0x00,        # 0x19: JMP('loc_0')  <- back-edge to the entry block
            0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x1E: PUSH_INT(0)
            0x0A, 0x00,                          # 0x24: SET_REG(0)
            0x0D,                                # 0x26: RETURN()
        ])

        raw_lines = disasm_to_dsl('test_loop_to_entry', bytecode)
        lines = [line.strip() for line in raw_lines]

        # The label is the very first thing in the function body - right after 'def ...():'
        self.assertEqual(lines[2], 'def _loc_0(): pass')
        self.assertEqual(lines[3], "label('loc_0')")
        self.assertNotIn("label('loc_E')", lines)
        self.assertIn("label('loc_1E')", lines)


if __name__ == '__main__':
    unittest.main()
