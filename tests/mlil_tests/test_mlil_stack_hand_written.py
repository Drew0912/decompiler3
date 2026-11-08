#!/usr/bin/env python3
"""The stack translator on shapes only a hand edit makes (the game's compiler never does): a value pending across a
write that may change it, a value crossing a fork, a join or a loop header, a register read before any write, a
syscall argument read before its pop, a push never read. Written in the LLIL DSL as the functions of one script,
compiled once by the writer with its compile check, parsed and lifted; per shape the shared checks
(tests/shared/stack_translator_checks.py) and the MLIL it is about. Also the script's logic round trip: a check of
the writer and the parser on these shapes, not of the translator"""

import contextlib
import io
import logging
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from dc3.logging import log
from falcom.ed9.assembler.stack_effects import RESULT_REGISTER
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import HEX, at, fresh_writer, local_call
from tests.shared.stack_translator_checks import StackTranslationTestCase, statements
from scp_roundtrip_validator import Status, check_logic_round_trip

GLOBAL_READ     = 0     # the global read: pending, or a branch's condition
GLOBAL_RESULT   = 1     # where each shape stores the value it is about
GLOBAL_BRANCH   = 2     # written on one branch's path
GLOBAL_COUNT    = 3
GLOBAL_TYPE     = 0     # the global table's type field, which nothing here reads
INITIAL         = 4     # a value stored before the write
CHANGED         = 9     # the value each write stores
VALUE, OTHER_VALUE = 5, 7
SUBSYSTEM, COMMAND = 1, 2
OTHER_REGISTER  = 1


def return_nothing():
    PUSH_INT(0); SET_REG(RESULT_REGISTER); RETURN()


def register_across_its_store(register: int):
    PUSH_INT(INITIAL); SET_REG(register)
    GET_REG(register)                               # pending
    PUSH_INT(CHANGED); SET_REG(register)
    SET_GLOBAL(GLOBAL_RESULT)
    return_nothing()


def define_shapes(writer):
    """The shapes, one function each; labels are script-wide, so each shape's are its own"""
    @writer.GlobalVars()
    def globalvars():
        for index in range(GLOBAL_COUNT):
            GLOBAL_VAR(f'g{index}', GLOBAL_TYPE)

    @writer.LLILCode()
    def GlobalAcrossItsStore():
        LOAD_GLOBAL(GLOBAL_READ)                    # pending
        PUSH_INT(CHANGED); SET_GLOBAL(GLOBAL_READ)
        SET_GLOBAL(GLOBAL_RESULT)                   # the old value
        return_nothing()

    @writer.LLILCode()
    def LocalAcrossItsStore():
        PUSH_INT(INITIAL)                           # the local
        LOAD_STACK(-WORD_SIZE)                      # pending
        PUSH_INT(CHANGED); POP_TO(-2 * WORD_SIZE)
        SET_GLOBAL(GLOBAL_RESULT)                   # the old value
        POP(WORD_SIZE)
        return_nothing()

    @writer.LLILCode()
    def ParameterAcrossItsStore(arg1: Value32):
        LOAD_STACK(-WORD_SIZE)                      # pending
        PUSH_INT(CHANGED); POP_TO(-2 * WORD_SIZE)
        SET_GLOBAL(GLOBAL_RESULT)
        POP(WORD_SIZE)
        return_nothing()

    @writer.LLILCode()
    def DereferenceAcrossAPointerStore(arg1: Value32):
        LOAD_STACK_DEREF(-WORD_SIZE)                # pending
        PUSH_INT(CHANGED); POP_TO_DEREF(-2 * WORD_SIZE)
        SET_GLOBAL(GLOBAL_RESULT)
        POP(WORD_SIZE)
        return_nothing()

    @writer.LLILCode()
    def ResultRegisterAcrossItsStore():
        register_across_its_store(RESULT_REGISTER)

    @writer.LLILCode()
    def OtherRegisterAcrossItsStore():
        register_across_its_store(OTHER_REGISTER)

    @writer.LLILCode()
    def AcrossAFork():
        PUSH_INT(VALUE)
        LOAD_GLOBAL(GLOBAL_READ); POP_JMP_ZERO('fork_skip')
        PUSH_INT(1); SET_GLOBAL(GLOBAL_BRANCH)
        label('fork_skip'); SET_GLOBAL(GLOBAL_RESULT)
        return_nothing()

    @writer.LLILCode()
    def AtAJoin():
        LOAD_GLOBAL(GLOBAL_READ); POP_JMP_ZERO('join_else')
        PUSH_INT(VALUE); JMP('join')
        label('join_else'); PUSH_INT(OTHER_VALUE)
        label('join'); SET_GLOBAL(GLOBAL_RESULT)
        return_nothing()

    @writer.LLILCode()
    def AtALoopHeader():
        PUSH_INT(0)
        label('loop_head'); LOAD_GLOBAL(GLOBAL_READ); POP_JMP_ZERO('loop_done')
        PUSH_INT(1); ADD(); JMP('loop_head')
        label('loop_done'); SET_GLOBAL(GLOBAL_RESULT)
        return_nothing()

    @writer.LLILCode()
    def RegisterBeforeAnyWrite():
        GET_REG(OTHER_REGISTER); SET_GLOBAL(GLOBAL_RESULT)
        return_nothing()

    @writer.LLILCode()
    def Callee():
        return_nothing()

    @writer.LLILCode()
    def RegisterAfterACall():
        PUSH_INT(INITIAL); SET_REG(OTHER_REGISTER)
        local_call(Callee, 'call_back', [])
        GET_REG(OTHER_REGISTER); SET_GLOBAL(GLOBAL_RESULT)
        return_nothing()

    @writer.LLILCode()
    def SyscallArgumentReread():
        PUSH_INT(OTHER_VALUE); SYSCALL(SUBSYSTEM, COMMAND, 1)    # line: syscall
        LOAD_STACK(-WORD_SIZE); SET_GLOBAL(GLOBAL_RESULT)       # the argument, before its pop
        POP(WORD_SIZE)
        return_nothing()

    @writer.LLILCode()
    def UnreadAcrossBranches():
        PUSH_INT(VALUE)                             # never read
        LOAD_GLOBAL(GLOBAL_READ); POP_JMP_ZERO('unread_skip')
        PUSH_INT(1); SET_GLOBAL(GLOBAL_BRANCH)
        label('unread_skip'); POP(WORD_SIZE)
        return_nothing()


class WarningRecorder(logging.Handler):
    """The warnings logged while it is log's only handler"""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class TestHandWrittenShapes(StackTranslationTestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.dat = cls.work / 'hand_written.dat'
        writer = fresh_writer(cls.dat)
        writer.check_compiled = True
        define_shapes(writer)
        recorder = WarningRecorder()
        with mock.patch.object(log, 'handlers', [recorder]):
            data = writer.build({})
        cls.warnings = recorder.messages
        cls.dat.write_bytes(data)

        parser, functions = ScpParser.load_bytes(data, cls.dat.name, round_trip=False, keep_unreachable_code=False,
                                                 quiet=True)
        lifter = ED9VMLifter(parser=parser)
        cls.llil = {func.name: lifter.lift_function(func) for func in functions}

    def shape(self, name: str) -> list[str]:
        """The shape's MLIL statements, after the shared checks"""
        return statements(self.checked_translation(self.llil[name]))

    def assertRegisterCopied(self, name: str, register: int):
        mlil = self.shape(name)
        self.assertEqual(mlil[:4], [f'REG[{register}] = {INITIAL}', f't1 = REG[{register}]',
                                    f'REG[{register}] = {CHANGED}', f'GLOBAL[{GLOBAL_RESULT}] = t1'])

    def test_a_global_pending_across_its_store(self):
        mlil = self.shape('GlobalAcrossItsStore')
        self.assertEqual(mlil[:3], [f't1 = GLOBAL[{GLOBAL_READ}]', f'GLOBAL[{GLOBAL_READ}] = {CHANGED}',
                                    f'GLOBAL[{GLOBAL_RESULT}] = t1'])

    def test_a_local_pending_across_its_store(self):
        mlil = self.shape('LocalAcrossItsStore')
        self.assertEqual(mlil[:4], [f'var_s0 = {INITIAL}', 't1 = var_s0', f'var_s0 = {CHANGED}',
                                    f'GLOBAL[{GLOBAL_RESULT}] = t1'])

    def test_a_parameter_pending_across_its_store(self):
        mlil = self.shape('ParameterAcrossItsStore')
        self.assertEqual(mlil[:3], ['t1 = arg1', f'arg1 = {CHANGED}', f'GLOBAL[{GLOBAL_RESULT}] = t1'])

    def test_a_dereference_pending_across_a_pointer_store(self):
        mlil = self.shape('DereferenceAcrossAPointerStore')
        self.assertEqual(mlil[:3], ['t1 = *arg1', f'*arg1 = {CHANGED}', f'GLOBAL[{GLOBAL_RESULT}] = t1'])

    def test_the_result_register_pending_across_its_store(self):
        self.assertRegisterCopied('ResultRegisterAcrossItsStore', RESULT_REGISTER)

    def test_another_register_pending_across_its_store(self):
        self.assertRegisterCopied('OtherRegisterAcrossItsStore', OTHER_REGISTER)

    def test_a_value_pending_across_a_fork(self):
        mlil = self.shape('AcrossAFork')
        self.assertEqual(mlil[0], f'var_s0 = {VALUE}')
        self.assertIn(f'GLOBAL[{GLOBAL_RESULT}] = var_s0', mlil)

    def test_two_values_meeting_at_a_join(self):
        mlil = self.shape('AtAJoin')
        for statement in (f'var_s0 = {VALUE}', f'var_s0 = {OTHER_VALUE}', f'GLOBAL[{GLOBAL_RESULT}] = var_s0'):
            self.assertIn(statement, mlil)

    def test_a_loop_carried_value_at_a_loop_header(self):
        mlil = self.shape('AtALoopHeader')
        for statement in ('var_s0 = 0', 'var_s0 = (var_s0 + 1)', f'GLOBAL[{GLOBAL_RESULT}] = var_s0'):
            self.assertIn(statement, mlil)

    def test_a_register_read_after_a_call(self):
        mlil = self.shape('RegisterAfterACall')
        self.assertEqual(mlil[:4], [f'REG[{OTHER_REGISTER}] = {INITIAL}', 't1 = Callee()',
                                    f'REG[{RESULT_REGISTER}] = t1', f'GLOBAL[{GLOBAL_RESULT}] = REG[{OTHER_REGISTER}]'])

    def test_a_syscall_argument_read_before_its_pop(self):
        """The compile check warns of it, the script's only warning; the argument stays one variable"""
        self.assertEqual(len(self.warnings), 1, self.warnings)
        self.assertRegex(self.warnings[0],
                         rf'^{at(__file__, "syscall")}SyscallArgumentReread: SYSCALL at {HEX}: reads 1 value, but the '
                         rf'next opcode is LOAD_STACK, not POP\({WORD_SIZE}\)$')
        mlil = self.shape('SyscallArgumentReread')
        self.assertEqual(mlil[:4], [f'var_s0 = {OTHER_VALUE}', f't1 = syscall({SUBSYSTEM}, {COMMAND}, var_s0)',
                                    f'REG[{RESULT_REGISTER}] = t1', f'GLOBAL[{GLOBAL_RESULT}] = var_s0'])

    def test_a_push_never_read_across_branches(self):
        mlil = self.shape('UnreadAcrossBranches')
        self.assertEqual(mlil[0], f'var_s0 = {VALUE}')
        self.assertFalse([statement for statement in mlil[1:] if 'var_s0' in statement])

    def test_the_script_round_trips(self):
        """The validator's logic round trip of the compiled script: a check of the writer and the parser on these
        shapes (the .py comes from the parser), not of the translator"""
        with contextlib.redirect_stderr(io.StringIO()):
            results = check_logic_round_trip(self.dat, self.work)

        self.assertEqual([f'{result.name}: {result.summary}' for result in results if result.status == Status.FAIL],
                         [])
        self.assertEqual((results[-1].name, results[-1].status), ('logic round trip', Status.PASS))


if __name__ == '__main__':
    unittest.main()
