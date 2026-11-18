#!/usr/bin/env python3
"""HLIL bodies with helpers and hooks (docs/dsl/HLIL_DSL.md, Calls; docs/dsl/HOOKS.md): helpers in the script or a
module of their own build the caller's statements; a global keeps a value between functions; today's hooks work on an
HLIL function - an LLIL replacement, inline_original_func() and original.Name() of an HLIL original (its labels named
for the function compiling), function callbacks by the body's level, opcode callbacks on the lowered opcodes - by each
kind of game writer; the compile check names HLIL lines"""

import functools
from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.assembler import ED9Opcode
from falcom.ed9.writer.hlil_dsl.build import HLILError
from falcom.ed9.writer.scp_compile_check import CompileCheckError
from falcom.ed9.writer.scp_hlil_dsl_helper import *
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.hlil_dsl_test_utils import *
from tests.shared.scp_writer_test_utils import HEX, at, load_module, local_call, marked_line

HELPER_MODULE_SOURCE = '''from falcom.ed9.writer.scp_hlil_dsl_helper import *
from tests.shared.hlil_dsl_test_utils import chr_wait_animeclip


def wait_twice(chr_id):
    chr_wait_animeclip(chr_id, 0)
    chr_wait_animeclip(chr_id, 1)
'''


def remember(chr_id):
    """A helper keeping a value for another function: in a global, as the game keeps it"""
    Set(this.target, chr_id)


def wait_remembered():
    chr_wait_animeclip(this.target, 0)


def counted_wait(chr_id):
    """A helper keeping a Python value made by a call: no call of the DSL's, so the source check lets it be"""
    frame = len('abc')
    chr_wait_animeclip(chr_id, frame)


def target_global(scena):
    @scena.GlobalVars()
    def globalvars():
        GLOBAL_VAR("target", 0)


def llil_waits(arg1_offset: int, *frames: int):
    """chr_wait_animeclip(arg1, frame) for each frame, arg1 at arg1_offset (each call pushes its own setup)"""
    for frame in frames:
        local_call(chr_wait_animeclip, genLabel(), [(PUSH_INT, frame), (LOAD_STACK, arg1_offset)])


def llil_return(param_count: int):
    PUSH_RAW(RawInt(0))
    SET_REG(0)
    if param_count:
        POP(param_count * WORD_SIZE)

    RETURN()


class TestHelpers(HLILTestCase):
    def test_helpers_in_the_script_and_in_a_module_of_their_own(self):
        """A helper's statements are its caller's, in order; a helper module imports the DSL like a script"""
        path = self.tmp / 'helpers.py'
        path.write_text(HELPER_MODULE_SOURCE, encoding='utf-8', newline='\n')
        helpers = load_module(path)

        def wait_once(chr_id):
            chr_wait_animeclip(chr_id, 2)

        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func(arg1: Value32):
                helpers.wait_twice(arg1)
                wait_once(arg1)
                Return()

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def Func(arg1: Value32):
                llil_waits(-16, 0, 1, 2)
                llil_return(1)

        self.assert_twins(hlil, llil)

    def test_a_helper_keeping_a_python_value(self):
        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func(arg1: Value32):
                counted_wait(arg1)
                Return()

        def plain(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func(arg1: Value32):
                chr_wait_animeclip(arg1, 3)
                Return()

        self.assert_twins(hlil, plain)

    def test_a_wrapped_function_called_with_its_parameters(self):
        """Under an *args wrapper it takes its wrapped function's parameters, as its registration has them"""
        def callee(scena):
            @scena.LLILCode()
            @passthrough
            def Callee(arg1: Value32):
                POP(WORD_SIZE)
                RETURN()

            return Callee

        def hlil(scena):
            Callee = callee(scena)

            @scena.HLILCode()
            def Caller(arg1: Value32):
                Callee(arg1)
                Return()

        def llil(scena):
            Callee = callee(scena)

            @scena.LLILCode()
            def Caller(arg1: Value32):
                local_call(Callee, 'call', [(LOAD_STACK, -12)])
                llil_return(1)

        self.assert_twins(hlil, llil)

    def test_a_value_kept_between_functions_in_a_global(self):
        def hlil(scena):
            use_library(scena)
            target_global(scena)

            @scena.HLILCode()
            def First(arg1: Value32):
                remember(arg1)
                Return()

            @scena.HLILCode()
            def Second():
                wait_remembered()
                Return()

        def llil(scena):
            use_library(scena)
            target_global(scena)

            @scena.LLILCode()
            def First(arg1: Value32):
                LOAD_STACK(-4)
                SET_GLOBAL("target")
                llil_return(1)

            @scena.LLILCode()
            def Second():
                local_call(chr_wait_animeclip, 'wait', [(PUSH_INT, 0), (LOAD_GLOBAL, "target")])
                llil_return(0)

        self.assert_twins(hlil, llil)


def hlil_target(scena):
    """Target(arg1), an HLIL function waiting on arg1; returns its stub"""
    use_library(scena)

    @scena.HLILCode()
    def Target(arg1: Value32):
        chr_wait_animeclip(arg1, 0)
        Return()

    return Target


class TestHooks(HLILTestCase):
    def test_an_llil_replacement_inlining_the_hlil_original(self):
        """inline_original_func() lowers the original onto the stack its parameters are on"""
        def hlil(scena):
            hlil_target(scena)

            @replace_function('Target')
            def Target(arg1: Value32):
                PUSH_INT(1)
                POP(WORD_SIZE)
                inline_original_func()

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def Target(arg1: Value32):
                PUSH_INT(1)
                POP(WORD_SIZE)
                llil_waits(-16, 0)
                llil_return(1)

        self.assert_twins(hlil, llil)

    def test_an_hlil_original_inlined_twice_and_elsewhere_gets_fresh_labels(self):
        """Into another function while it compiles on its own, twice into one function: each label is named for the
        function compiling, so none is defined twice"""
        writers = []

        def register(scena):
            writers.append(scena)
            scena.warn_unreachable_code = False  # the second copy follows the first one's RETURN
            hlil_target(scena)

            @scena.LLILCode()
            def Host(arg1: Value32):
                original.Target(arg1)
                original.Target(arg1)

            @scena.LLILCode()
            def Other(arg1: Value32):
                original.Target(arg1)

        for writer_class in WRITER_CLASSES:
            with self.subTest(writer=writer_class.__name__):
                self.compiled(register, writer_class)
                self.assertLessEqual({'Target:0', 'Host:0', 'Host:1', 'Other:0'}, set(writers[-1].labels))

    def test_function_callbacks_by_the_body_level(self):
        """A body passed on stays HLIL; a functools.wraps wrapper of it is HLIL, its statements first"""
        def hlil(scena):
            hlil_target(scena)

            @registerFuncCallback
            def passed_on(name, func):
                return func

            @registerFuncCallback
            def wrap(name, func):
                if name != 'Target':
                    return None

                @functools.wraps(func)
                def wrapper(*args):
                    chr_wait_animeclip(65534, 5)
                    func(*args)

                return wrapper

        def plain(scena):
            use_library(scena)

            @scena.HLILCode()
            def Target(arg1: Value32):
                chr_wait_animeclip(65534, 5)
                chr_wait_animeclip(arg1, 0)
                Return()

        self.assert_twins(hlil, plain)

    def test_a_wrapper_of_a_stub_calls_its_function(self):
        """functools.wraps of an HLIL function's name: its stub in the wrapper is a call"""
        def hlil(scena):
            target = hlil_target(scena)

            @scena.HLILCode()
            def Caller(arg1: Value32):
                Return()

            @registerFuncCallback
            def wrap(name, func):
                if name != 'Caller':
                    return None

                @functools.wraps(target)
                def wrapper(*args):
                    target(*args)
                    Return()

                return wrapper

        def llil(scena):
            target = hlil_target(scena)

            @scena.LLILCode()
            def Caller(arg1: Value32):
                local_call(target, 'call', [(LOAD_STACK, -12)])
                llil_return(1)

        self.assert_twins(hlil, llil)

    def test_an_llil_wrapper_calling_the_hlil_body_raw(self):
        """The HLIL body runs as LLIL there: its first statement raises at its line"""
        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def Target(arg1: Value32):
                Set(arg1, 1)  # line: hlil run raw
                Return()

            @registerFuncCallback
            def wrap(name, func):
                if name != 'Target':
                    return None

                def wrapper(arg1: Value32):
                    func(arg1)

                return wrapper

        message = re.escape('Target: Set(...) builds an HLIL node')
        with self.assertRaisesRegex(HLILError, f'^{at(__file__, "hlil run raw")}{message}'):
            self.compiled(register)

    def test_opcode_callbacks_see_the_lowered_opcodes(self):
        """As from the LLIL twin, the called function's stub included; a return label is named for its function"""
        def recorder(seen: list):
            def record(opcode, *args):
                seen.append((ED9Opcode(opcode).name, args))

            return record

        def hlil(scena):
            hlil_target(scena)
            registerOpcodeCallback(recorder(hlil_seen))

        def llil(scena):
            use_library(scena)
            registerOpcodeCallback(recorder(llil_seen))

            @scena.LLILCode()
            def Target(arg1: Value32):
                local_call(chr_wait_animeclip, 'Target:0', [(PUSH_INT, 0), (LOAD_STACK, -16)])
                llil_return(1)

        for writer_class in WRITER_CLASSES:
            with self.subTest(writer=writer_class.__name__):
                hlil_seen, llil_seen = [], []
                self.compiled(hlil, writer_class)
                self.compiled(llil, writer_class)
                self.assertEqual(hlil_seen, llil_seen)
                self.assertIn(('PUSH_RET_ADDR', ('Target:0',)), hlil_seen)

    def test_the_compile_check_names_hlil_lines(self):
        """An opcode callback dropping the syscall's POP leaves its argument on the stack at the RETURN"""
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Syscall(1, 2, arg1)  # line: pushed
                Return()  # line: returned

            registerOpcodeCallback(lambda opcode, *args: opcode == ED9Opcode.POP and args == (WORD_SIZE,))

        pushed = re.escape(f'(line {marked_line(__file__, "pushed")})')
        with self.assertRaisesRegex(CompileCheckError, f'^{at(__file__, "returned")}Func: RETURN at {HEX}: the stack '
                                                       f'is not empty: .*{pushed}'):
            self.compiled(register)


if __name__ == '__main__':
    unittest.main()
