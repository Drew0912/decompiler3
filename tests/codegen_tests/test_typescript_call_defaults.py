#!/usr/bin/env python3
'''End to end: scena2py's .ts leaves out a local call's trailing arguments equal to the callee's defaults, with the
defaults converted as the lifter converts them (so a float default matches its argument), from the whole function
table (a callee left out of the output still counts); a Raw argument is not an Integer default.'''

from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.scena2py import process_file
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import fresh_writer

CALLEE_ARGC = 4
DEFAULT_INT = 3
DEFAULT_FLOAT = 0.3
DEFAULT_TEXT = 'x'
FIRST_ARG = 1
FOLDED_LEFT = 1
FOLDED_RIGHT = DEFAULT_INT - FOLDED_LEFT


def call_callee(callee, ret: str, arg2_push):
    '''Callee(FIRST_ARG, <arg2_push>, DEFAULT_FLOAT, DEFAULT_TEXT): the last argument is pushed first'''
    PUSH_CURRENT_FUNC_ID()
    PUSH_RET_ADDR(ret)
    PUSH_STR(DEFAULT_TEXT)
    PUSH_FLOAT(DEFAULT_FLOAT)
    arg2_push()
    PUSH_INT(FIRST_ARG)
    CALL(callee)
    label(ret)


def decompile(filter_func = None) -> str:
    '''The .ts of a script whose Main calls Callee(arg1, arg2 = 3, arg3 = 0.3, arg4 = 'x') three times: arg2 pushed
    as an Integer 3, as a Raw 3, and as 1 + 2 (folded)'''
    with tempfile.TemporaryDirectory() as tmp:
        dat = Path(tmp) / 'defaults.dat'
        writer = fresh_writer(dat)

        @writer.LLILCode()
        def Callee(arg1: Value32, arg2: Value32 = DEFAULT_INT, arg3: Value32 = DEFAULT_FLOAT,
                   arg4: str = DEFAULT_TEXT):
            POP(CALLEE_ARGC * WORD_SIZE)
            RETURN()

        @writer.LLILCode()
        def Main():
            call_callee(Callee, 'integer', lambda: PUSH_INT(DEFAULT_INT))
            call_callee(Callee, 'raw', lambda: PUSH_RAW(RawInt(DEFAULT_INT)))
            call_callee(Callee, 'folded', lambda: (PUSH_INT(FOLDED_LEFT), PUSH_INT(FOLDED_RIGHT), ADD()))
            RETURN()

        writer.run({'Callee': Callee, 'Main': Main})

        config = ScenaDecompileConfig()
        config.output_dir = Path(tmp) / 'out'
        config.filter_func = filter_func
        process_file(dat, config)
        return (config.output_dir / dat.stem / f'{dat.stem}.ts').read_text(encoding = 'utf-8')


class TestCallDefaultsEndToEnd(unittest.TestCase):
    def test_trailing_defaults_left_out(self):
        ts = decompile()

        self.assertIn(f'function Callee(arg1: number, arg2: number = {DEFAULT_INT}, arg3: number = {DEFAULT_FLOAT}, '
                      f'arg4: string = "{DEFAULT_TEXT}")', ts)
        # Integer and folded arg2 go with the float and string defaults; a Raw 3 is another word than Integer 3
        self.assertEqual(ts.count(f'Callee({FIRST_ARG});'), 2)
        self.assertIn(f'Callee({FIRST_ARG}, {DEFAULT_INT});', ts)

    def test_callee_left_out_of_the_output_still_counts(self):
        ts = decompile(filter_func = lambda func: func.name != 'Callee')

        self.assertNotIn('function Callee(', ts)
        self.assertEqual(ts.count(f'Callee({FIRST_ARG});'), 2)


if __name__ == '__main__':
    unittest.main()
