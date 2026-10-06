#!/usr/bin/env python3
'''DSL argument checks (bool operands, CALL's function argument, value ranges, operand count), UNKNOWN_28's raw bytes
and the helper module's non-opcode statements (label, GLOBAL_VAR).'''

import math
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.types_scp import ScpValue
from falcom.ed9.writer import scp_writer_helper
from falcom.ed9.writer.metadata import SCP_WRITER_HELPER_IMPORT
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import at, body_writer, fresh_writer


class TestBoolRejected(unittest.TestCase):
    '''bool is an int subclass, so isinstance checks alone let True/False through as 1/0'''

    def setUp(self):
        body_writer()

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

    def test_unregistered_function_is_named(self):
        body_writer()

        def Missing():
            pass

        with self.assertRaisesRegex(TypeError, r'^CALL has unknown function name: Missing$'):
            CALL(Missing)


class TestHandleOpcode(unittest.TestCase):
    '''Paths no opcode function or corpus script reaches'''

    def setUp(self):
        self.writer = body_writer()

    def test_operand_count_is_checked(self):
        with self.assertRaisesRegex(AssertionError, r'^POP: expected 1 operands, got 2$'):
            self.writer.handle_opcode(ED9Opcode.POP, WORD_SIZE, WORD_SIZE)

    def test_unknown_28_writes_its_operand_bytes_as_given(self):
        # No table row, so no operand format; tracked like any opcode (the real tracker ignores it, so a stub records)
        calls = []
        self.writer.call_tracker = SimpleNamespace(on_opcode = lambda *call: calls.append(call))
        UNKNOWN_28(b'\x01\x02')

        self.assertEqual(self.writer.fs.ReadAll(), bytes.fromhex('28 01 02'))
        self.assertEqual(calls, [(ED9Opcode.UNKNOWN_28, (b'\x01\x02',), None)])


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
        self.writer = body_writer()

    def test_int_is_pushed_as_a_float(self):
        # The value's Python type picks the encoding: unconverted, PUSH_FLOAT(1) wrote Integer 1 (00 04 01 00 00 40)
        PUSH_FLOAT(1)

        self.assertEqual(self.writer.fs.ReadAll(), bytes.fromhex('00 04 00 00 E0 8F'))

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
        '''Rejected at its def, with the line: defaults are written apart from the bodies'''
        writer = fresh_writer()
        with self.assertRaisesRegex(TypeError, rf"^{at(__file__, 'nan default')}parameter arg1 of NanDefault: "
                                               "non-finite float nan: the game can't use it$"):
            @writer.LLILCode()
            def NanDefault(arg1: Nullable32 = math.nan):    # line: nan default
                RETURN()


class TestValueRanges(unittest.TestCase):
    '''The payload under the 2-bit type tag is 30 bits: a value outside it would compile as a different value or type'''

    def test_integer_bounds(self):
        for value in (ScpValue.INTEGER_MIN, ScpValue.INTEGER_MAX):
            with self.subTest(value = value):
                self.assertEqual(ScpValue().from_value(ScpValue(value).to_word()).value, value)

        for value in (ScpValue.INTEGER_MIN - 1, ScpValue.INTEGER_MAX + 1):
            with self.subTest(value = value):
                with self.assertRaisesRegex(ValueError, '^' + re.escape(f'Integer {value} is outside -536870912..536870911')):
                    ScpValue(value).to_bytes()

    def test_raw_bounds(self):
        for value in (0, ScpValue.PAYLOAD_MASK):
            with self.subTest(value = value):
                decoded = ScpValue().from_value(ScpValue(RawInt(value)).to_word())
                self.assertEqual((decoded.type, decoded.value), (ScpValue.Type.Raw, value))

        for value, text in ((-1, '-0x1'), (ScpValue.PAYLOAD_MASK + 1, '0x40000000')):
            with self.subTest(value = value):
                with self.assertRaisesRegex(ValueError, '^' + re.escape(f'RawInt {text} is outside 0..0x3fffffff')):
                    ScpValue(RawInt(value)).to_bytes()

    def test_default_past_the_range_does_not_compile(self):
        writer = fresh_writer()
        with self.assertRaisesRegex(TypeError, rf"^{at(__file__, 'big default')}parameter arg2 of BigDefault: "
                                               'Integer 600000000 is outside'):
            @writer.LLILCode()
            def BigDefault(arg1: Value32, arg2: Value32 = 600000000):   # line: big default
                RETURN()

    def test_push_past_the_range_does_not_compile(self):
        body_writer()

        # Before the check these compiled as -473741824 and as Integer 1
        for message, push in (
            ('Integer 600000000 is outside', lambda: PUSH_INT(600000000)),
            ('RawInt 0x40000001 is outside', lambda: PUSH_RAW(RawInt(0x40000001))),
        ):
            with self.subTest(message = message):
                with self.assertRaisesRegex(ValueError, f'^{message}'):
                    push()


if __name__ == '__main__':
    unittest.main()
