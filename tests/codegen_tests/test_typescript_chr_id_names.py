#!/usr/bin/env python3
"""End to end through scp2py with sora2's tracked syscall rows: a constant passed to a wrapper's ID parameter, or at a
raw syscall's ID slot, prints by name in .ts; at another slot it stays a number; a wrapper the output leaves out marks
nothing; with id_names off, .ts has numbers and the header without the tables"""

from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3 import quote_string
from falcom.ed9.consts import PseudoChrId
from falcom.ed9.scp2py_base import process_file
from falcom.ed9.scp2py_config import ScpDecompileConfig
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.corpus import require_chr_table
from tests.shared.scp_writer_test_utils import fresh_writer, local_call

GAME            = 'sora2'
WAIT_ARGC       = 2         # Chr 0x19 with 2 arguments: the character first (sora2's rows)
TEXT            = 'Hello'
NOT_THE_DEFAULT = 3         # a second argument for Wait that its call keeps


def decompile(first_arg: int, second_arg: int | None = None, filter_func=None, id_names: bool = True) -> str:
    """The .ts of a script whose Main calls Wait(first_arg, second_arg, by default first_arg), a wrapper of Chr 0x19
    (an ID, then anything else), and makes the raw syscall Mes 0x13(PseudoChrId.Nothing, TEXT) (the speaker first)"""
    with tempfile.TemporaryDirectory() as tmp:
        dat = Path(tmp) / 'chr_ids.dat'
        writer = fresh_writer(dat)

        @writer.LLILCode()
        def Wait(arg1: Value32, arg2: Nullable32 = 0):
            LOAD_STACK(-WAIT_ARGC * WORD_SIZE)
            LOAD_STACK(-WAIT_ARGC * WORD_SIZE)
            SYSCALL(1, 0x19, WAIT_ARGC)
            POP(WAIT_ARGC * WORD_SIZE)
            PUSH_RAW(RawInt(0))
            SET_REG(0)
            POP(WAIT_ARGC * WORD_SIZE)
            RETURN()

        @writer.LLILCode()
        def Main():
            second = first_arg if second_arg is None else second_arg
            local_call(Wait, 'wait', [(PUSH_INT, second), (PUSH_INT, first_arg)])
            PUSH_STR(TEXT)
            PUSH_INT(PseudoChrId.Nothing.value)
            SYSCALL(5, 0x13, 2)
            POP(2 * WORD_SIZE)
            RETURN()

        writer.run({'Wait': Wait, 'Main': Main})

        config = ScpDecompileConfig()
        config.output_dir = Path(tmp) / 'out'
        config.filter_func = filter_func
        config.id_names = id_names
        process_file(dat, config, game=GAME)
        return (config.output_dir / dat.stem / f'{dat.stem}.ts').read_text(encoding='utf-8')


class TestChrIdNamesEndToEnd(unittest.TestCase):

    def test_a_wrappers_id_argument_and_a_raw_syscalls_are_named(self):
        ts = decompile(PseudoChrId.Self.value)

        self.assertIn(f'Wait(PseudoChrId.Self, {PseudoChrId.Self.value});', ts)
        self.assertIn(f'syscall(5, 19, PseudoChrId.Nothing, "{TEXT}");', ts)
        self.assertIn('enum PseudoChrId {', ts)

    def test_a_wrapper_left_out_marks_nothing(self):
        ts = decompile(PseudoChrId.Self.value, filter_func=lambda func: func.name == 'Main')

        self.assertIn(f'Wait({PseudoChrId.Self.value}, {PseudoChrId.Self.value});', ts)
        self.assertIn(f'syscall(5, 19, PseudoChrId.Nothing, "{TEXT}");', ts)

    def test_off_every_id_is_a_number(self):
        ts = decompile(PseudoChrId.Self.value, id_names=False)

        self.assertIn(f'Wait({PseudoChrId.Self.value}, {PseudoChrId.Self.value});', ts)
        self.assertIn(f'syscall(5, 19, {PseudoChrId.Nothing.value}, "{TEXT}");', ts)
        self.assertNotIn('PseudoChrId', ts)
        self.assertNotIn('ChrIdTable', ts)

    def test_a_table_id_prints_the_tables_name(self):
        names = require_chr_table(GAME)
        chr_id = 0

        self.assertIn(f"Wait(ChrIdTable[{quote_string(names[chr_id], "'")}], {NOT_THE_DEFAULT});",
                      decompile(chr_id, NOT_THE_DEFAULT))


if __name__ == '__main__':
    unittest.main()
