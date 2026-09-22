#!/usr/bin/env python3
'''Unit tests for the common-function fingerprint (falcom/ed9/writer/metadata/signature.py)'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.disasm import *
from falcom.ed9.disasm.ed9_optable import ed9_create_fallthrough_jump
from falcom.ed9.parser import *
from falcom.ed9.writer.metadata.signature import body_fingerprint, function_fingerprint

SORA2_DIR = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en'


def load_function(test: unittest.TestCase, relative_path: str, name: str):
    '''(parser, function) for one common function of a local sora2_1.0 script, decompiled like scena2py.py'''
    path = SORA2_DIR / relative_path
    if not path.exists():
        test.skipTest(f'Test file not found: {path}')

    parser, functions = ScpParser.load(path, round_trip = False, keep_unreachable_code = False, filter_func = lambda f: f.name == name)
    return parser, functions[0]


def reachable_instructions(bytecode: bytes) -> list[Instruction]:
    '''Disassemble hand-coded bytecode; reachable instructions in offset order, like ScpParser.get_instructions'''
    context = DisassemblerContext(create_fallthrough_jump = ed9_create_fallthrough_jump)
    entry_block = Disassembler(ED9_INSTRUCTION_TABLE, context).disasm_function(bytecode, offset = 0, name = 'test')

    return Formatter.reachable_instructions(entry_block)


def branch_bytecode(target: int) -> bytes:
    '''Same instructions every time; only where POP_JMP_ZERO lands changes'''
    return bytes([
        0x09, 0x00,                          # 0x00: GET_REG(0)
        0x0F, target, 0x00, 0x00, 0x00,      # 0x02: POP_JMP_ZERO(target)
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x07: PUSH_INT(1)
        0x0A, 0x00,                          # 0x0D: SET_REG(0)
        0x00, 0x04, 0x02, 0x00, 0x00, 0x40,  # 0x0F: PUSH_INT(2)
        0x0A, 0x00,                          # 0x15: SET_REG(0)
        0x0D,                                # 0x17: RETURN()
    ])


class TestCorpusFingerprints(unittest.TestCase):
    '''Real common functions from sora2_1.0'''

    def test_same_function_in_two_scripts_matches(self):
        # Branches and CALLs at different offsets: the raw bytes differ, the function doesn't
        parser_a, func_a = load_function(self, 'ai/ai_chr0001_c49_e00.dat', 'CheckSBreak')
        parser_b, func_b = load_function(self, 'ai/ai_chr0100_e00.dat', 'CheckSBreak')

        self.assertNotEqual(func_a.offset, func_b.offset)
        self.assertEqual(function_fingerprint(parser_a, func_a), function_fingerprint(parser_b, func_b))

    def test_same_body_different_signature_differs(self):
        parser_a, func_a = load_function(self, 'ani/etc1200.dat', 'chr_is_play_animeclip')
        parser_b, func_b = load_function(self, 'ani/etc0020.dat', 'chr_is_play_animeclip')
        body_a, signature_a = function_fingerprint(parser_a, func_a)
        body_b, signature_b = function_fingerprint(parser_b, func_b)

        # str vs NullableStr = '' parameter: identical code, different param flags and default
        self.assertEqual(body_a, body_b)
        self.assertNotEqual(signature_a, signature_b)

    def test_arity_variant_differs(self):
        parser_a, func_a = load_function(self, 'ani/mon5240_c10__.dat', 'btl_damage')
        parser_b, func_b = load_function(self, 'ani/chr0111.dat', 'btl_damage')

        self.assertNotEqual(len(func_a.params), len(func_b.params))
        self.assertNotEqual(function_fingerprint(parser_a, func_a), function_fingerprint(parser_b, func_b))


class TestBranchDestination(unittest.TestCase):
    '''A branch target must be identified by where it lands, not just by which label it is'''

    def test_branch_landing_one_instruction_later_differs(self):
        to_set_reg = reachable_instructions(branch_bytecode(0x0D))
        to_push_int = reachable_instructions(branch_bytecode(0x0F))
        no_calls = lambda func_id: None
        no_globals = lambda index: None

        # Same opcodes and non-branch operands in the same order
        self.assertEqual([inst.opcode for inst in to_set_reg], [inst.opcode for inst in to_push_int])
        self.assertNotEqual(
            body_fingerprint(to_set_reg, 0, no_calls, no_globals),
            body_fingerprint(to_push_int, 0, no_calls, no_globals),
        )


if __name__ == '__main__':
    unittest.main()
