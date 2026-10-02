#!/usr/bin/env python3
'''DSL argument checks (bool operands, CALL's function argument) and the helper module's non-opcode statements
(label, GLOBAL_VAR).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

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


if __name__ == '__main__':
    unittest.main()
