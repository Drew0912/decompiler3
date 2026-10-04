#!/usr/bin/env python3
'''Unit tests for the reachability audit (tools/scp_roundtrip_validator.py) used by --logic-round-trip'''

from pathlib import Path
import sys
import unittest
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from falcom.ed9.disasm import *
from falcom.ed9.disasm.ed9_optable import ED9_FORMAT_TABLE
from falcom.ed9.disasm.instruction_table import OperandDescriptor
from falcom.ed9.parser import *
from falcom.ed9.parser.code_layout import dropped_ranges
from scp_roundtrip_validator import (
    PAIRED_CALL_OPS,
    check_instruction_ranges,
    is_range_provably_dead,
)

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'


def make_instruction(offset: int, opcode: int, size: int = 1, offset_target: int | None = None) -> Instruction:
    '''A minimal Instruction, with one Offset operand when offset_target is given'''
    descriptor = ED9_INSTRUCTION_TABLE.get_descriptor(opcode)
    operands = []
    if offset_target is not None:
        op_desc = OperandDescriptor.from_format_string('O', ED9_FORMAT_TABLE)[0]
        operands = [Operand(descriptor = op_desc, value = offset_target)]

    return Instruction(offset = offset, opcode = opcode, descriptor = descriptor, operands = operands, size = size)


class TestIsRangeProvablyDead(unittest.TestCase):
    '''A dropped range's fate depends only on the instruction right before it'''

    def test_return_jmp_call_script_no_return_are_always_dead(self):
        for opcode in (ED9Opcode.RETURN, ED9Opcode.JMP, ED9Opcode.CALL_SCRIPT_NO_RETURN):
            self.assertTrue(is_range_provably_dead(opcode, paired = {}))

    def test_paired_call_returning_past_dead_bytes_is_accepted(self):
        # A local CALL whose PUSH_RET_ADDR resumes somewhere else, skipping intervening dead bytes -
        # a naive predecessor whitelist would wrongly reject every range following a CALL.
        self.assertTrue(is_range_provably_dead(ED9Opcode.CALL, paired = {ED9Opcode.CALL: True}))
        self.assertTrue(is_range_provably_dead(ED9Opcode.CALL_SCRIPT, paired = {ED9Opcode.CALL_SCRIPT: True}))

    def test_unpaired_call_is_rejected(self):
        self.assertFalse(is_range_provably_dead(ED9Opcode.CALL, paired = {ED9Opcode.CALL: False}))
        self.assertFalse(is_range_provably_dead(ED9Opcode.CALL_SCRIPT, paired = {ED9Opcode.CALL_SCRIPT: False}))

    def test_fall_through_instruction_is_rejected(self):
        self.assertFalse(is_range_provably_dead(ED9Opcode.GET_REG, paired = {}))

    def test_no_predecessor_is_rejected(self):
        self.assertFalse(is_range_provably_dead(None, paired = {}))


class TestDroppedRanges(unittest.TestCase):
    '''Dropped ranges are the raw byte complement of the reachable instructions - never anything
    read from disassembling the gap itself, so a range that can't be decoded is still audited.'''

    def test_gap_between_instructions_is_reported_with_its_predecessor(self):
        insts = [make_instruction(0x00, ED9Opcode.RETURN, size = 1)]
        ranges = dropped_ranges(insts, start = 0x00, end = 0x10)

        self.assertEqual(ranges, [(0x01, 0x10, insts[0])])

    def test_range_of_unparseable_garbage_is_still_reported(self):
        # 0xFF is not a valid opcode - if this range were disassembled instead of taken as a raw
        # byte complement, it would raise; dropped_ranges never tries.
        insts = [make_instruction(0x00, ED9Opcode.JMP, size = 5)]
        ranges = dropped_ranges(insts, start = 0x00, end = 0x08)

        self.assertEqual(ranges, [(0x05, 0x08, insts[0])])

    def test_no_gap_when_instructions_cover_the_whole_extent(self):
        insts = [make_instruction(0x00, ED9Opcode.RETURN, size = 1)]
        self.assertEqual(dropped_ranges(insts, start = 0x00, end = 0x01), [])


class TestCheckInstructionRanges(unittest.TestCase):
    '''Overlap and target-validity checks, hand-built rather than from a real .dat'''

    def test_target_inside_another_instruction_fails(self):
        insts = [
            make_instruction(0x00, ED9Opcode.JMP, size = 5, offset_target = 0x02),  # targets mid-instruction below
            make_instruction(0x05, ED9Opcode.RETURN, size = 1),
        ]
        failures = check_instruction_ranges(insts, start = 0x00, end = 0x06)

        self.assertTrue(any('not a reachable instruction' in f for f in failures))

    def test_target_on_a_real_instruction_start_passes(self):
        insts = [
            make_instruction(0x00, ED9Opcode.JMP, size = 5, offset_target = 0x05),
            make_instruction(0x05, ED9Opcode.RETURN, size = 1),
        ]
        self.assertEqual(check_instruction_ranges(insts, start = 0x00, end = 0x06), [])

    def test_overlapping_instructions_fail(self):
        insts = [
            make_instruction(0x00, ED9Opcode.JMP, size = 5, offset_target = 0x03),
            make_instruction(0x03, ED9Opcode.RETURN, size = 1),  # starts before the JMP's bytes end
        ]
        failures = check_instruction_ranges(insts, start = 0x00, end = 0x04)

        self.assertTrue(any('overlaps' in f for f in failures))


class TestRealCallPairing(unittest.TestCase):
    '''CALL/CALL_SCRIPT pairing (PUSH_RET_ADDR/PUSH_CALLER_FRAME) is a parser-level pattern match
    (falcom/ed9/parser/scp.py), not something the raw Disassembler does on its own - so this needs
    a real file through ScpParser, not hand-coded bytes fed straight to Disassembler.'''

    def test_call_and_push_ret_addr_counts_match(self):
        path = SORA2_DIR / 'battle' / 'btl_EV_00_14_00.dat'
        if not path.exists():
            self.skipTest(f'Test file not found: {path}')

        parser, functions = ScpParser.load(path, round_trip = False, keep_unreachable_code = False)

        self.assertTrue(functions)
        for func in functions:
            counts = Counter(inst.opcode for inst in parser.get_instructions(func))
            for call_op, ret_op in PAIRED_CALL_OPS.items():
                self.assertEqual(counts[call_op], counts[ret_op], f'{func.name}: {call_op} vs {ret_op}')


if __name__ == '__main__':
    unittest.main()
