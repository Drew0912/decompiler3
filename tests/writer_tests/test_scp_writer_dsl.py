#!/usr/bin/env python3
'''DSL argument checks (bool operands, CALL's function argument, value ranges), UNKNOWN_28's raw bytes, what
handle_opcode tracks, every opcode function handing the writer its own opcode, and PUSH.'''

from enum import IntEnum
import inspect
import math
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9_INSTRUCTION_TABLE, ED9Opcode
from falcom.ed9.parser.types_scp import RawInt, ScpValue
from falcom.ed9.writer import scp_writer_opcode_handler
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import at, body_writer, fresh_writer


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
    '''handle_opcode itself: UNKNOWN_28's raw bytes, and what it hands the tracker'''

    def setUp(self):
        self.writer = body_writer()

    def test_unknown_28_writes_its_operand_bytes_as_given(self):
        # No table row, so no operand format; tracked like any opcode (the real tracker ignores it, so a stub records)
        calls = []
        self.writer.call_tracker = SimpleNamespace(on_opcode = lambda *call: calls.append(call))
        UNKNOWN_28(b'\x01\x02')

        self.assertEqual(self.writer.fs.ReadAll(), bytes.fromhex('28 01 02'))
        self.assertEqual(calls, [(ED9Opcode.UNKNOWN_28, (b'\x01\x02',), None)])

    def test_tracked_once_after_its_write(self):
        '''Tracked once, after its write, with the normalized operands and a pushed constant's (value, string) payload;
        an opcode whose write raises is not tracked. UNKNOWN_28's branch: the test above'''
        calls = []
        self.writer.call_tracker = SimpleNamespace(on_opcode = lambda *call: calls.append(call))
        self.writer._build_function_table()             # PUSH_CURRENT_FUNC_ID writes the function's table index
        PUSH_FLOAT(1)
        PUSH_STR('text')
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('ret')
        POP(WORD_SIZE)

        with self.assertRaises(ValueError):
            PUSH_FLOAT(math.inf)                        # raises after the PUSH header is written

        self.assertEqual([call[:2] for call in calls], [
            (ED9Opcode.PUSH_FLOAT, (1.0,)), (ED9Opcode.PUSH_STR, ('text',)), (ED9Opcode.PUSH_CURRENT_FUNC_ID, ()),
            (ED9Opcode.PUSH_RET_ADDR, ('ret',)), (ED9Opcode.POP, (WORD_SIZE,)),
        ])
        self.assertIs(type(calls[0][1][0]), float)
        [(float_value, no_string), (str_value, string), *no_payloads] = [payload for _, _, payload in calls]
        self.assertEqual((float_value.type, float_value.value, no_string), (ScpValue.Type.Float, 1.0, None))
        self.assertEqual((str_value.value, string.text), ('text', 'text'))
        self.assertEqual(no_payloads, [None, None, None])


class TestOpcodeFunctions(unittest.TestCase):
    ARGS = {
        'PUSH': (1,), 'POP': (WORD_SIZE,), 'LOAD_STACK': (0,), 'LOAD_STACK_DEREF': (0,), 'PUSH_STACK_OFFSET': (0,),
        'POP_TO': (0,), 'POP_TO_DEREF': (0,), 'LOAD_GLOBAL': (0,), 'SET_GLOBAL': (0,), 'GET_REG': (0,),
        'SET_REG': (0,), 'JMP': ('target',), 'CALL': (lambda: None,), 'POP_JMP_NOT_ZERO': ('target',),
        'POP_JMP_ZERO': ('target',), 'CALL_SCRIPT': ('this', 'func', 0), 'CALL_SCRIPT_NO_RETURN': ('this', 'func', 0),
        'SYSCALL': (1, 2, 3), 'PUSH_CALLER_FRAME': ('target',), 'DEBUG_SET_LINENO': (1,), 'DEBUG_LOG': (1,),
        'UNKNOWN_28': (b'',), 'PUSH_RET_ADDR': ('target',), 'PUSH_RAW': (RawInt(1),), 'PUSH_INT': (1,),
        'PUSH_FLOAT': (1.0,), 'PUSH_STR': ('s',),
    }

    @classmethod
    def opcode_functions(cls) -> dict:
        return {name: func for name, func in vars(scp_writer_opcode_handler).items()
                if inspect.isfunction(func) and func.__module__ == scp_writer_opcode_handler.__name__}

    def test_each_function_emits_its_own_opcode(self):
        '''Every statement of the DSL hands the writer its opcode and operands; none returns before it'''
        writer = body_writer()
        functions = self.opcode_functions()
        no_operands = {name: () for name in ED9Opcode.__members__ if name not in self.ARGS}
        args = {**no_operands, **self.ARGS}
        emitted = []
        with mock.patch.object(writer, 'handle_opcode', lambda opcode, *operands: emitted.append((opcode, operands))):
            for name, func in functions.items():
                func(*args[name])

        self.assertEqual(emitted, [(ED9Opcode[name], args[name]) for name in functions])


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


class TestPush(unittest.TestCase):
    def test_push_encodes_like_its_typed_twin(self):
        cases = {'int': (7, PUSH_INT), 'float': (1.5, PUSH_FLOAT), 'str': ('text', PUSH_STR),
                 'raw': (RawInt(3), PUSH_RAW)}
        for case, (value, typed) in cases.items():
            with self.subTest(case):
                writer = body_writer()
                typed(value)
                expected = writer.fs.ReadAll()

                writer = body_writer()
                PUSH(value)

                self.assertEqual(writer.fs.ReadAll(), expected)


class TestValueRanges(unittest.TestCase):
    '''A value outside what its encoding holds would compile as a different value or type: a pushed value's payload
    under the 2-bit type tag is 30 bits, and an opcode's integer operand is what its type reads back'''

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

    def test_last_operand_that_fits_reads_back_and_the_next_fails(self):
        '''SET_REG(256) used to compile as SET_REG(0)'''
        cases = [
            # (mnemonic, emit, operand number, last value that fits, first that doesn't, the range)
            ('SET_REG', SET_REG, 1, 255, 256, '0..255'),
            ('GET_REG', GET_REG, 1, 0, -1, '0..255'),
            ('POP', POP, 1, 255, 256, '0..255'),
            ('SYSCALL', lambda value: SYSCALL(1, value, 0), 2, 255, 256, '0..255'),
            ('CALL_SCRIPT', lambda value: CALL_SCRIPT('this', 'Main', value), 3, 255, 256, '0..255'),
            ('DEBUG_SET_LINENO', DEBUG_SET_LINENO, 1, 65535, 65536, '0..65535'),
            ('LOAD_STACK', LOAD_STACK, 1, 2**31 - 1, 2**31, '-2147483648..2147483647'),
            ('LOAD_STACK', LOAD_STACK, 1, -2**31, -2**31 - 1, '-2147483648..2147483647'),
        ]
        for mnemonic, emit, number, fits, too_far, valid in cases:
            with self.subTest(mnemonic, value = fits):
                writer = body_writer()
                emit(fits)
                self.assertEqual(self.first_operands(writer)[number - 1], fits)

            with self.subTest(mnemonic, value = too_far):
                body_writer()
                with self.assertRaisesRegex(ValueError, rf'^Body: {mnemonic} operand {number} is {too_far}, outside '
                                                        rf'{re.escape(valid)}$'):
                    emit(too_far)

    def test_int_subclass_operand_is_compared_not_scanned(self):
        '''Pin: `in` on a range scans it with == for an int subclass - an IntEnum slot offset took 91 s'''
        class Slot(IntEnum):
            ARG1 = -WORD_SIZE

            def __eq__(self, other):
                raise AssertionError('the range check scanned the range')

            __hash__ = IntEnum.__hash__

        writer = body_writer()
        LOAD_STACK(Slot.ARG1)
        self.assertEqual(self.first_operands(writer), [-WORD_SIZE])

    @classmethod
    def first_operands(cls, writer) -> list:
        '''The operand values of the first opcode the body wrote'''
        writer.fs.Position = 0
        return [operand.value for operand in ED9_INSTRUCTION_TABLE.decode_instruction(writer.fs, 0).operands]


if __name__ == '__main__':
    unittest.main()
