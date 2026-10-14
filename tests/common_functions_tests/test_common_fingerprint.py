#!/usr/bin/env python3
'''Unit tests for the common-function fingerprint (falcom/ed9/metadata/fingerprint.py): real common functions,
branch targets by where they land and relative to the function, global operands by name'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.disasm import *
from falcom.ed9.disasm.ed9_optable import ed9_create_fallthrough_jump
from falcom.ed9.metadata.fingerprint import (
    GLOBAL_INDEX_TAG, GLOBAL_TAG, UNRESOLVED_BRANCH_TAG, body_fingerprint, function_fingerprint,
)
from falcom.ed9.parser import *
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.scp_asm import GLOBAL_INDEX, REG_INDEX, Asm

OTHER_GLOBAL_INDEX = GLOBAL_INDEX + 5
OTHER_BASE = 0x40


def load_function(relative_path: str, name: str):
    '''(parser, function) for one common function of a local sora2_1.0 script, decompiled like scena2py.py'''
    path = require(SORA2_SCRIPTS / relative_path)
    parser, functions = ScpParser.load(path, round_trip = False, keep_unreachable_code = False,
                                       filter_func = lambda f: f.name == name)
    return parser, functions[0]


def reachable_instructions(bytecode: bytes, offset: int = 0) -> list[Instruction]:
    '''Disassemble hand-coded bytecode from offset; reachable instructions in offset order, like
    ScpParser.get_instructions'''
    context = DisassemblerContext(create_fallthrough_jump = ed9_create_fallthrough_jump)
    entry_block = Disassembler(ED9_INSTRUCTION_TABLE, context).disasm_function(bytecode, offset = offset, name = 'test')

    return Formatter.reachable_instructions(entry_block)


def no_calls(func_id: int) -> None:
    return None


def no_globals(index: int) -> None:
    return None


def branch_bytecode(target: str) -> bytes:
    '''Same instructions every time; only where POP_JMP_ZERO lands changes'''
    asm = Asm()
    asm.get_reg(REG_INDEX); asm.jz(target)
    asm.push_int(1); asm.label('set_reg'); asm.set_reg(REG_INDEX)
    asm.label('push_int'); asm.push_int(2); asm.set_reg(REG_INDEX); asm.ret()
    return asm.assemble(0, {})[0]


class TestCorpusFingerprints(unittest.TestCase):
    '''Real common functions from sora2_1.0'''

    def test_same_function_in_two_scripts_matches(self):
        # Branches and CALLs at different offsets: the raw bytes differ, the function doesn't
        parser_a, func_a = load_function('ai/ai_chr0001_c49_e00.dat', 'CheckSBreak')
        parser_b, func_b = load_function('ai/ai_chr0100_e00.dat', 'CheckSBreak')

        self.assertNotEqual(func_a.offset, func_b.offset)
        self.assertEqual(function_fingerprint(parser_a, func_a), function_fingerprint(parser_b, func_b))

    def test_same_body_different_signature_differs(self):
        parser_a, func_a = load_function('ani/etc1200.dat', 'chr_is_play_animeclip')
        parser_b, func_b = load_function('ani/etc0020.dat', 'chr_is_play_animeclip')
        body_a, signature_a = function_fingerprint(parser_a, func_a)
        body_b, signature_b = function_fingerprint(parser_b, func_b)

        # str vs NullableStr = '' parameter: identical code, different param flags and default
        self.assertEqual(body_a, body_b)
        self.assertNotEqual(signature_a, signature_b)

    def test_arity_variant_differs(self):
        parser_a, func_a = load_function('ani/mon5240_c10__.dat', 'btl_damage')
        parser_b, func_b = load_function('ani/chr0111.dat', 'btl_damage')

        self.assertNotEqual(len(func_a.params), len(func_b.params))
        self.assertNotEqual(function_fingerprint(parser_a, func_a), function_fingerprint(parser_b, func_b))


class TestBranchDestination(unittest.TestCase):
    '''A branch target must be identified by where it lands, not just by which label it is'''

    def test_branch_landing_one_instruction_later_differs(self):
        to_set_reg = reachable_instructions(branch_bytecode('set_reg'))
        to_push_int = reachable_instructions(branch_bytecode('push_int'))

        # Same opcodes and non-branch operands in the same order
        self.assertEqual([inst.opcode for inst in to_set_reg], [inst.opcode for inst in to_push_int])
        self.assertNotEqual(
            body_fingerprint(to_set_reg, 0, no_calls, no_globals),
            body_fingerprint(to_push_int, 0, no_calls, no_globals),
        )


class TestUnresolvedBranch(unittest.TestCase):
    '''A target that is not a reachable instruction start is keyed relative to the function'''

    @classmethod
    def pruned(cls, base: int) -> list[Instruction]:
        '''The jump's function at base, without the instruction the jump lands on'''
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('landing')
        asm.push_int(1); asm.label('landing'); asm.set_reg(REG_INDEX)
        asm.push_int(2); asm.set_reg(REG_INDEX); asm.ret()
        code, labels = asm.assemble(base, {})
        return [inst for inst in reachable_instructions(bytes(base) + code, base) if inst.offset != labels['landing']]

    def test_target_is_relative_to_the_function(self):
        '''One function at two offsets: the raw targets differ, the fingerprint doesn't'''
        at_zero = body_fingerprint(self.pruned(0), 0, no_calls, no_globals)
        at_offset = body_fingerprint(self.pruned(OTHER_BASE), OTHER_BASE, no_calls, no_globals)

        self.assertEqual(at_zero, at_offset)
        self.assertEqual(at_zero[1][1][0], UNRESOLVED_BRANCH_TAG)


class TestGlobalOperands(unittest.TestCase):
    @classmethod
    def fingerprint(cls, index: int, global_name) -> tuple:
        asm = Asm()
        asm.load_global(index); asm.set_reg(REG_INDEX); asm.ret()
        return body_fingerprint(reachable_instructions(asm.assemble(0, {})[0]), 0, no_calls, global_name)

    def test_named_global_is_keyed_by_name_not_index(self):
        '''The same function in two scripts that number the global differently has one fingerprint'''
        keys = [self.fingerprint(index, lambda i: 'flag') for index in (GLOBAL_INDEX, OTHER_GLOBAL_INDEX)]

        self.assertEqual(keys[0], keys[1])
        self.assertEqual(keys[0][0][1], (GLOBAL_TAG, 'flag'))

    def test_unnamed_global_is_keyed_by_index(self):
        keys = [self.fingerprint(index, no_globals) for index in (GLOBAL_INDEX, OTHER_GLOBAL_INDEX)]

        self.assertNotEqual(keys[0], keys[1])
        self.assertEqual(keys[1][0][1], (GLOBAL_INDEX_TAG, OTHER_GLOBAL_INDEX))


if __name__ == '__main__':
    unittest.main()
