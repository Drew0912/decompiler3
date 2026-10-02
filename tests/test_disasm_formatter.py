#!/usr/bin/env python3
'''Unit tests for .py label emission: only an offset something references gets a label.'''

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

    return Formatter(FormatterContext()).format_function(func)


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

    def test_spacer_after_each_label_is_empty(self):
        '''Not indented: editors that trim trailing whitespace would change four spaces'''
        bytecode = bytes([
            0x09, 0x00,                          # 0x00: GET_REG(0)
            0x0F, 0x0C, 0x00, 0x00, 0x00,        # 0x02: POP_JMP_ZERO('loc_C')
            0x0B, 0x00, 0x00, 0x00, 0x00,        # 0x07: JMP('loc_0')  <- back-edge to the entry block
            0x0D,                                # 0x0C: RETURN()
        ])

        lines = disasm_to_dsl('test_spacers', bytecode)
        label_indices = [index for index, line in enumerate(lines) if line.strip().startswith('label(')]

        self.assertEqual(len(label_indices), 2)
        self.assertEqual([lines[index + 1] for index in label_indices], ['', ''])


class TestOperandText(unittest.TestCase):
    def test_push_float_prints_the_shortest_literal(self):
        bytecode = bytes([
            0x00, 0x04, 0x66, 0x66, 0xA6, 0x8F,  # 0x00: PUSH_FLOAT(0.3), stored as 0.2999999523162842
            0x00, 0x04, 0x00, 0x00, 0xE0, 0x8F,  # 0x06: PUSH_FLOAT(1.0)
            0x00, 0x04, 0x00, 0x00, 0x00, 0xA0,  # 0x0C: PUSH_FLOAT(-0.0)
            0x0D,                                # 0x12: RETURN()
        ])

        lines = [line.strip() for line in disasm_to_dsl('test_floats', bytecode)]

        # A float literal even when integral: PUSH_FLOAT(1) / PUSH_FLOAT(-0) would compile differently
        self.assertEqual([line for line in lines if line.startswith('PUSH_FLOAT')],
                         ['PUSH_FLOAT(0.3)', 'PUSH_FLOAT(1.0)', 'PUSH_FLOAT(-0.0)'])

    def test_call_script_names_print_as_plain_strings(self):
        bytecode = bytes([
            0x22,                                # 0x00: CALL_SCRIPT(
            0x0B, 0x00, 0x00, 0xC0,              #           string at 0x0B,
            0x10, 0x00, 0x00, 0xC0,              #           string at 0x10,
            0x00,                                #           0)
            0x0D,                                # 0x0A: RETURN()
        ]) + b'this\0GetCoolClone\0'             # 0x0B, 0x10

        lines = [line.strip() for line in disasm_to_dsl('test_call_script', bytecode)]

        self.assertIn('CALL_SCRIPT("this", "GetCoolClone", 0)', lines)

    def test_float_defaults_print_the_shortest_literal(self):
        nullable = ScpParamFlags(typ = Nullable32)

        def param_text(default) -> str:
            return Formatter.format_param(0, FunctionParam(nullable, ScpValue(default)))

        self.assertEqual(param_text(0.19999998807907104), 'arg1: Nullable32 = 0.2')

        # Integer and integral float defaults keep their own form: they encode differently
        self.assertEqual(param_text(0), 'arg1: Nullable32 = 0')
        self.assertEqual(param_text(1.0), 'arg1: Nullable32 = 1.0')


if __name__ == '__main__':
    unittest.main()
