#!/usr/bin/env python3
"""Unit tests for the common-function fingerprint (falcom/ed9/structs/fingerprint.py): real common functions,
branch targets by where they land and relative to the function, global operands by name, the code without its line
markers, a NaN by its word"""

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from assembler import Disassembler, DisassemblerContext, Function, Instruction
from falcom.ed9.assembler import *
from falcom.ed9.assembler.opcode_table import ed9_create_fallthrough_jump
from falcom.ed9.structs.fingerprint import (
    GLOBAL_INDEX_TAG, GLOBAL_TAG, UNRESOLVED_BRANCH_TAG, body_fingerprint, function_fingerprint,
    body_fingerprint_without_line_markers, signature_fingerprint,
)
from falcom.ed9.structs.scp_types import FloatWord, ScpValue
from falcom.ed9.parser.scp import ScpParser
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.scp_asm import GLOBAL_INDEX, REG_INDEX, Asm

OTHER_GLOBAL_INDEX = GLOBAL_INDEX + 5
OTHER_BASE = 0x40

# Float words holding a NaN: the plain one, its negative and one with a payload
NAN_WORD            = 0x9FF00000
NEGATIVE_NAN_WORD   = 0xBFF00000
PAYLOAD_NAN_WORD    = 0x9FF048D1


def load_function(relative_path: str, name: str):
    """(parser, function) for one common function of a local sora2_1.0 script, decompiled like scp2py.py"""
    path = require(SORA2_SCRIPTS / relative_path)
    parser, functions = ScpParser.load(path, round_trip=False, keep_unreachable_code=False,
                                       filter_func=lambda f: f.name == name)
    return parser, functions[0]


def reachable_instructions(bytecode: bytes, offset: int = 0) -> list[Instruction]:
    """Disassemble hand-coded bytecode from offset; reachable instructions in offset order
    (Function.reachable_instructions)"""
    context = DisassemblerContext(create_fallthrough_jump=ed9_create_fallthrough_jump)
    entry_block = Disassembler(ED9_INSTRUCTION_TABLE, context).disasm_function(bytecode, offset=offset, name='test')

    return Function(entry_block=entry_block).reachable_instructions()


def no_calls(func_id: int) -> None:
    return None


def no_globals(index: int) -> None:
    return None


def branch_bytecode(target: str) -> bytes:
    """Same instructions every time; only where POP_JMP_ZERO lands changes"""
    asm = Asm()
    asm.get_reg(REG_INDEX); asm.jz(target)
    asm.push_int(1); asm.label('set_reg'); asm.set_reg(REG_INDEX)
    asm.label('push_int'); asm.push_int(2); asm.set_reg(REG_INDEX); asm.ret()
    return asm.assemble(0, {})[0]


class TestCorpusFingerprints(unittest.TestCase):
    """Real common functions from sora2_1.0"""

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
    """A branch target must be identified by where it lands, not just by which label it is"""

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
    """A target that is not a reachable instruction start is keyed relative to the function"""

    @classmethod
    def pruned(cls, base: int) -> list[Instruction]:
        """The jump's function at base, without the instruction the jump lands on"""
        asm = Asm()
        asm.get_reg(REG_INDEX); asm.jz('landing')
        asm.push_int(1); asm.label('landing'); asm.set_reg(REG_INDEX)
        asm.push_int(2); asm.set_reg(REG_INDEX); asm.ret()
        code, labels = asm.assemble(base, {})
        return [inst for inst in reachable_instructions(bytes(base) + code, base) if inst.offset != labels['landing']]

    def test_target_is_relative_to_the_function(self):
        """One function at two offsets: the raw targets differ, the fingerprint doesn't"""
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
        """The same function in two scripts that number the global differently has one fingerprint"""
        keys = [self.fingerprint(index, lambda i: 'flag') for index in (GLOBAL_INDEX, OTHER_GLOBAL_INDEX)]

        self.assertEqual(keys[0], keys[1])
        self.assertEqual(keys[0][0][1], (GLOBAL_TAG, 'flag'))

    def test_unnamed_global_is_keyed_by_index(self):
        keys = [self.fingerprint(index, no_globals) for index in (GLOBAL_INDEX, OTHER_GLOBAL_INDEX)]

        self.assertNotEqual(keys[0], keys[1])
        self.assertEqual(keys[1][0][1], (GLOBAL_INDEX_TAG, OTHER_GLOBAL_INDEX))


def marked_bytecode(markers: bool) -> bytes:
    """One function, with line markers where the compiler writes them when markers: one first, two at a branch's
    target, one before the return"""
    asm = Asm()
    if markers:
        asm.debug_set_lineno(1)

    asm.get_reg(REG_INDEX); asm.jz('target')
    asm.push_int(1); asm.set_reg(REG_INDEX)
    asm.label('target')
    if markers:
        asm.debug_set_lineno(2); asm.debug_set_lineno(3)

    asm.push_int(2); asm.set_reg(REG_INDEX)
    if markers:
        asm.debug_set_lineno(4)

    asm.ret()
    return asm.assemble(0, {})[0]


class TestFingerprintWithoutLineMarkers(unittest.TestCase):
    """The code without its line markers: a function written in the HLIL DSL, which writes none, compiles to it"""

    @classmethod
    def keys(cls, fingerprint, markers: bool) -> tuple:
        return fingerprint(reachable_instructions(marked_bytecode(markers)), 0, no_calls, no_globals)

    def test_markers_left_out_and_a_branch_to_one_is_to_the_next_instruction(self):
        unmarked = self.keys(body_fingerprint, markers=False)
        self.assertEqual(self.keys(body_fingerprint_without_line_markers, markers=True), unmarked)
        self.assertNotEqual(self.keys(body_fingerprint, markers=True), unmarked)

    def test_without_markers_it_is_the_fingerprint(self):
        self.assertEqual(self.keys(body_fingerprint_without_line_markers, markers=False),
                         self.keys(body_fingerprint, markers=False))


class TestNaNValues(unittest.TestCase):
    """Every NaN's repr is 'nan': a NaN pushed or given as a parameter's default is keyed by the word it is stored as"""

    @classmethod
    def body(cls, word: int) -> tuple:
        asm = Asm()
        asm.push_float(FloatWord(word)); asm.set_reg(REG_INDEX); asm.ret()
        return body_fingerprint(reachable_instructions(asm.assemble(0, {})[0]), 0, no_calls, no_globals)

    @classmethod
    def signature(cls, word: int) -> tuple:
        """A function whose one parameter defaults to the NaN stored as word"""
        param = SimpleNamespace(type=SimpleNamespace(flags=0), default_value=ScpValue(FloatWord(word)))
        return signature_fingerprint(SimpleNamespace(params=[param]))

    def test_nan_words_differ(self):
        for fingerprint in (self.body, self.signature):
            keys = [fingerprint(word) for word in (NAN_WORD, NEGATIVE_NAN_WORD, PAYLOAD_NAN_WORD)]
            self.assertEqual(len(set(keys)), len(keys), fingerprint.__name__)

    def test_one_nan_word_matches(self):
        for fingerprint in (self.body, self.signature):
            self.assertEqual(fingerprint(NAN_WORD), fingerprint(NAN_WORD), fingerprint.__name__)


if __name__ == '__main__':
    unittest.main()
