#!/usr/bin/env python3
"""The dead code an everyday parse drops, logged once per function: at DEBUG when every block of it is the compiler's
boilerplate (falcom/ed9/parser/dead_code.py), else at INFO; nothing when quiet or when the code is kept"""

from pathlib import Path
import logging
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.logging import log
from falcom.ed9.assembler.vm import WORD_SIZE
from tests.shared.scp_asm import LEFT_VALUE, REG_INDEX, Asm, Func, Program, main_function, returning_callee

DROPPED = 'unreachable bytes not decompiled'


def with_dead_code(lead: Asm, dead: Asm, *others: Func, **layout) -> tuple[Program, int, int]:
    """f: lead, then dead, which nothing reaches, followed by others; the program (layout: Program's keywords), the dead
    code's offset and its size"""
    lead.label('dead')
    lead.items += dead.items
    program = Program(main_function(lead), *others, **layout)
    return program, program.label('dead'), dead.size()


def returns() -> Asm:
    asm = Asm()
    asm.debug_set_lineno(1); asm.ret()
    return asm


def tail_calls() -> Asm:
    asm = Asm()
    asm.debug_set_lineno(1); asm.call_script_no_return(0)
    return asm


def return_zero() -> Asm:
    """A function's closing return 0, as the compiler writes it after a tail call"""
    asm = Asm()
    asm.push_raw(0); asm.set_reg(REG_INDEX); asm.pop(WORD_SIZE); asm.ret()
    return asm


def a_body() -> Asm:
    asm = Asm()
    asm.push_int(LEFT_VALUE); asm.pop(WORD_SIZE); asm.ret()
    return asm


def a_jump() -> Asm:
    asm = Asm()
    asm.jmp(0)
    return asm


class TestDroppedCodeLog(unittest.TestCase):
    def logged(self, program: Program, keep_unreachable_code: bool = False) -> list[tuple[int, str]]:
        """Each dead-code line the parse logs, with its level"""
        with self.assertLogs(log, logging.DEBUG) as logs:
            program.parser(keep_unreachable_code).disasm_all_functions()

        return [(record.levelno, record.getMessage()) for record in logs.records if DROPPED in record.getMessage()]

    def test_a_jump_after_return_is_boilerplate(self):
        """f is followed by another function, which drops nothing"""
        program, _, size = with_dead_code(returns(), a_jump(), returning_callee(), pool=())
        self.assertEqual(self.logged(program),
                         [(logging.DEBUG, f'test.dat [f]: {size} {DROPPED} (compiler boilerplate: JMP)')])

    def test_a_body_after_return_is_info(self):
        program, offset, size = with_dead_code(returns(), a_body(), pool=())
        self.assertEqual(self.logged(program),
                         [(logging.INFO, f'test.dat [f]: {size} {DROPPED} (3 instructions from 0x{offset:X}, after '
                                         'RETURN)')])

    def test_the_closing_return_zero_is_boilerplate_only_after_a_tail_call(self):
        program, _, size = with_dead_code(tail_calls(), return_zero())
        self.assertEqual(self.logged(program), [
            (logging.DEBUG, f'test.dat [f]: {size} {DROPPED} (compiler boilerplate: PUSH_RAW SET_REG POP RETURN)'),
        ])

        program, offset, size = with_dead_code(returns(), return_zero(), pool=())
        self.assertEqual(self.logged(program),
                         [(logging.INFO, f'test.dat [f]: {size} {DROPPED} (4 instructions from 0x{offset:X}, after '
                                         'RETURN)')])

    def test_nothing_when_quiet(self):
        program, _, _ = with_dead_code(returns(), a_body(), pool=())
        with self.assertNoLogs(log, logging.DEBUG):
            program.parser().disasm_all_functions(quiet=True)

    def test_nothing_when_the_code_is_kept(self):
        program, _, _ = with_dead_code(returns(), a_body(), pool=())
        self.assertEqual(self.logged(program, keep_unreachable_code=True), [])


if __name__ == '__main__':
    unittest.main()
