#!/usr/bin/env python3
"""The function stubs (falcom/ed9/writer/hlil_dsl/stubs.py): a library function under @library_function and a script
function under @scena.LLILCode() / LLILCommonCode() have their names bound to a stub, which CALL, CommonImports and the
function callbacks see through to the body; a bare call raises at its line"""

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.writer.hlil_dsl.stubs import stub_body
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import WriterTestCase, at, local_call, location


def echo_arg(arg1: Value32):
    """A library function's body: returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


def bare_call_message(caller: str, callee: str) -> str:
    return re.escape(f'{caller}: {callee}(...) builds an HLIL call; in an LLIL body write CALL({callee})')


class TestLibraryStubs(WriterTestCase):
    def compile_calling(self, library) -> bytes:
        """A script importing library and calling it once, the compile check on"""
        writer = self.fresh_writer()

        @writer.CommonImports()
        def commonImports():
            return [library]

        @writer.LLILCode()
        def Caller():
            local_call(library, 'ret', [(PUSH_INT, 7)])
            RETURN()

        return writer.build({})

    def test_a_stub_compiles_as_its_body(self):
        """CommonImports and CALL of the stub give the plain function's bytes, and the writer holds the body"""
        plain = self.compile_calling(echo_arg)

        self.assertEqual(self.compile_calling(library_function(echo_arg)), plain)
        self.assertIs(get_scp_writer().functions_by_name['echo_arg'].body, echo_arg)

    def test_a_signature_error_names_the_library_def(self):
        """Registration unwraps the stub first, so the error is at the body's def, not the stub's"""
        def untyped(arg1):  # line: untyped def
            RETURN()

        message = f'^{location(__file__, "untyped def")}: parameter arg1 of untyped: needs a type'
        with self.assertRaisesRegex(TypeError, message):
            @self.writer.CommonImports()
            def commonImports():
                return [library_function(untyped)]

    def test_a_bare_call_raises_at_its_line(self):
        """In an LLIL body; a plain function called there would have inlined its opcodes"""
        echo = library_function(echo_arg)

        @self.writer.CommonImports()
        def commonImports():
            return [echo]

        @self.writer.LLILCode()
        def Caller():
            PUSH_INT(7)
            echo(7)  # line: bare library call
            RETURN()

        with self.assertRaisesRegex(TypeError, f'^{at(__file__, "bare library call")}'
                                               f'{bare_call_message("Caller", "echo_arg")}$'):
            self.writer.build({})


class TestScriptStubs(WriterTestCase):
    def test_a_bare_call_raises_at_its_line(self):
        @self.writer.LLILCode()
        def Callee():
            RETURN()

        @self.writer.LLILCode()
        def Caller():
            Callee()  # line: bare script call
            RETURN()

        with self.assertRaisesRegex(TypeError, f'^{at(__file__, "bare script call")}'
                                               f'{bare_call_message("Caller", "Callee")}$'):
            self.writer.build({})

    def test_a_function_callback_may_return_a_function_by_its_name(self):
        """The stub it returns stands for that function's body"""
        @self.writer.LLILCode()
        def Replacement():
            RETURN()

        @self.writer.LLILCode()
        def Target():
            PUSH_INT(1)
            POP(WORD_SIZE)
            RETURN()

        registerFuncCallback(lambda name, func: Replacement if name == 'Target' else None)
        self.writer.build({})

        self.assertIs(self.writer.functions_by_name['Target'].body, stub_body(Replacement))


if __name__ == '__main__':
    unittest.main()
