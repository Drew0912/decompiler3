#!/usr/bin/env python3
'''DSL argument checks (bool operands, CALL's function argument) and the helper module's non-opcode statements
(label, GLOBAL_VAR).'''

import math
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from ml import fileio

from common.config import default_encoding
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.types_scp import ScpValue
from falcom.ed9.writer import scp_writer_helper
from falcom.ed9.writer.metadata import SCP_WRITER_HELPER_IMPORT
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import fresh_writer


class TestBoolRejected(unittest.TestCase):
    '''bool is an int subclass, so isinstance checks alone let True/False through as 1/0'''

    def setUp(self):
        fresh_writer()

    def test_scp_value_rejects_bool(self):
        with self.assertRaises(TypeError) as ctx:
            ScpValue(True)

        self.assertEqual(str(ctx.exception), 'ScpValue takes int, float, str or RawInt, not bool: True')

    def test_push_int_rejects_bool(self):
        with self.assertRaisesRegex(TypeError, 'PUSH_INT takes no bool operand: True'):
            PUSH_INT(True)

    def test_integer_operands_reject_bool(self):
        with self.assertRaisesRegex(TypeError, 'POP takes no bool operand: True'):
            POP(True)

        # Not the first operand: every operand is checked
        with self.assertRaisesRegex(TypeError, 'SYSCALL takes no bool operand: True'):
            SYSCALL(0, 0, True)

    def test_global_var_type_rejects_bool(self):
        with self.assertRaisesRegex(AssertionError, 'GLOBAL_VAR type must be an int'):
            GLOBAL_VAR('isblackroom', True)


class TestCall(unittest.TestCase):
    def setUp(self):
        fresh_writer()

    def test_call_by_name_names_the_mistake(self):
        with self.assertRaisesRegex(AssertionError, r"CALL takes the function itself, not 'CheckSBreak'"):
            CALL('CheckSBreak')


class TestHelperStatements(unittest.TestCase):
    '''label() and GLOBAL_VAR emit no instruction, so they live in the helper next to genLabel()'''

    def test_generated_scripts_get_them_from_the_helper(self):
        namespace = {}
        exec(SCP_WRITER_HELPER_IMPORT, namespace)

        for name in ('label', 'GLOBAL_VAR', 'genLabel'):
            with self.subTest(name = name):
                self.assertEqual(namespace[name].__module__, scp_writer_helper.__name__)


class TestPushFloat(unittest.TestCase):
    def setUp(self):
        self.writer = fresh_writer()
        self.writer.fs = fileio.FileStream(encoding = default_encoding()).OpenMemory()

    def test_int_is_pushed_as_a_float(self):
        # The value's Python type picks the encoding: unconverted, PUSH_FLOAT(1) wrote Integer 1 (00 04 01 00 00 40)
        PUSH_FLOAT(1)

        self.assertEqual(self.writer.fs.ReadAll(), bytes.fromhex('00 04 00 00 E0 8F'))
        self.assertEqual(self.writer.calls[-1], (ED9Opcode.PUSH_FLOAT, (1.0,)))
        self.assertIs(type(self.writer.calls[-1][1][0]), float)

    def test_bool_is_still_rejected(self):
        with self.assertRaisesRegex(TypeError, 'PUSH_FLOAT takes no bool operand: True'):
            PUSH_FLOAT(True)

    def test_non_finite_float_does_not_compile(self):
        for value in (math.inf, -math.inf, math.nan):
            with self.subTest(value = value):
                with self.assertRaisesRegex(ValueError, f"non-finite float {value}: the game can't use it"):
                    PUSH_FLOAT(value)

    def test_float_past_float32_range_does_not_compile(self):
        with self.assertRaisesRegex(ValueError, r"float 3\.5e\+38 is outside float32's range: the game can't use it"):
            PUSH_FLOAT(3.5e38)

    def test_non_finite_default_does_not_compile(self):
        # A real compile: defaults are written with the function table, apart from the bodies
        with tempfile.TemporaryDirectory() as tmp:
            writer = create_scp_writer(str(Path(tmp) / 'nan_default.dat'))

            @writer.LLILCode()
            def NanDefault(arg1: Nullable32 = math.nan):
                RETURN()

            with self.assertRaisesRegex(ValueError, "non-finite float nan: the game can't use it"):
                writer.run({'NanDefault': NanDefault})

            # A failed run leaves its output file open
            writer.fs.Close()


if __name__ == '__main__':
    unittest.main()
