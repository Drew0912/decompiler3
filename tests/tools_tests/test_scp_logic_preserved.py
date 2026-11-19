#!/usr/bin/env python3
"""Unit tests for the validator's logic comparison (--logic-round-trip): check_logic_preserved and LogicSnapshot on
compiled scripts, each change the game logic definition covers failing (docs/ROUND_TRIP_POLICY.md), a difference in
line markers only passing just for a function the source decompile printed in the HLIL DSL; and the logic round trip
of a script whose function the HLIL DSL holds. The check runs only when a plan names it, so these are what guards it
(docs/HARDENING_POLICY.md)"""

from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from dc3.logging import log
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer import scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from round_trip.logic_preserved import LogicSnapshot, check_logic_preserved
from round_trip.logic_round_trip import check_logic_round_trip
from round_trip.results import Status
from tests.shared.scp_writer_test_utils import fresh_writer

GAME = 'sora2'


def define_main(marked: bool = True, value: int = 5, default: int = 0, common: bool = False, extra: bool = False):
    """A script whose Main is straight-line: a syscall of value, then the compiler's return; a line marker before each
    statement when marked; with extra, a second function"""
    def define(writer: scp_writer.ScpWriter):
        decorator = writer.LLILCommonCode() if common else writer.LLILCode()

        @decorator
        def Main(arg1: Value32 = default):
            if marked:
                DEBUG_SET_LINENO(1)

            PUSH_INT(value)
            SYSCALL(1, 2, 1)
            POP(WORD_SIZE)
            if marked:
                DEBUG_SET_LINENO(2)

            PUSH_RAW(RawInt(0))
            SET_REG(0)
            POP(WORD_SIZE)
            RETURN()

        if extra:
            @writer.LLILCode()
            def Extra():
                RETURN()

    return define


class LogicTestCase(unittest.TestCase):
    def setUp(self):
        self.addCleanup(fresh_writer)
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.scripts = 0

    def compiled(self, define) -> Path:
        """define's script through a fresh writer, into a .dat of its own"""
        self.scripts += 1
        dat = self.folder / f'script{self.scripts}.dat'
        writer = scp_writer.ScpWriter()
        scp_writer.install_scp_writer(writer)
        create_scp_writer(str(dat))
        define(writer)
        writer.run({})
        return dat

    def snapshot(self, define, without_line_markers: frozenset[str] = frozenset()) -> LogicSnapshot:
        dat = self.compiled(define)
        parser, functions = ScpParser.load_bytes(dat.read_bytes(), dat.name, round_trip=False,
                                                 keep_unreachable_code=False, quiet=True)
        return LogicSnapshot.of(parser, functions, without_line_markers)

    def assert_failed(self, source: LogicSnapshot, other: LogicSnapshot, expected: str):
        result = check_logic_preserved(source, other)
        self.assertEqual(result.status, Status.FAIL, result.summary)
        self.assertTrue(any(expected in detail for detail in result.details), result.details)


class TestEachChangeFails(LogicTestCase):
    def setUp(self):
        super().setUp()
        self.source = self.snapshot(define_main())

    def test_the_same_script_passes(self):
        self.assertEqual(check_logic_preserved(self.source, self.snapshot(define_main())).status, Status.PASS)

    def test_an_operand(self):
        self.assert_failed(self.source, self.snapshot(define_main(value=6)), 'Main: fingerprint differs')

    def test_a_signature(self):
        self.assert_failed(self.source, self.snapshot(define_main(default=1)), 'Main: fingerprint differs')

    def test_is_common_func(self):
        self.assert_failed(self.source, self.snapshot(define_main(common=True)), 'Main: is_common_func')

    def test_a_missing_and_an_extra_function(self):
        with_extra = self.snapshot(define_main(extra=True))
        self.assert_failed(self.source, with_extra, "extra after recompile: ['Extra']")
        self.assert_failed(with_extra, self.source, "missing after recompile: ['Extra']")

    def test_the_global_table_and_the_header(self):
        self.assert_failed(self.source, replace(self.source, globals_table=[('flag', 0)]), 'global table differs')
        self.assert_failed(self.source, replace(self.source, dword_14=self.source.dword_14 + 1), 'header dword_14')


class TestLineMarkers(LogicTestCase):
    def test_left_out_only_for_a_function_printed_in_the_hlil_dsl(self):
        hlil = frozenset({'Main'})
        result = check_logic_preserved(self.snapshot(define_main(), hlil),
                                       self.snapshot(define_main(marked=False), hlil))
        self.assertEqual(result.status, Status.PASS, result.details)
        self.assertIn('1 without line markers', result.summary)
        self.assert_failed(self.snapshot(define_main()), self.snapshot(define_main(marked=False)),
                           'Main: fingerprint differs')

    def test_any_other_change_still_fails_without_them(self):
        hlil = frozenset({'Main'})
        self.assert_failed(self.snapshot(define_main(), hlil), self.snapshot(define_main(marked=False, value=6), hlil),
                           'Main: fingerprint (without line markers) differs')


class TestHLILRoundTrip(LogicTestCase):
    def test_a_function_in_the_hlil_dsl_keeps_its_logic_and_its_mode(self):
        work = self.folder / 'work'
        work.mkdir()
        dat = self.compiled(define_main())
        with self.assertLogs(log, 'INFO'):
            results = {result.name: result for result in check_logic_round_trip(dat, work, game=GAME)}
        self.assertEqual([name for name, result in results.items() if result.status == Status.FAIL], [])
        self.assertIn('1 without line markers', results['round 1 logic preserved'].summary)
        self.assertEqual(results['round 2 mode'].summary, '1 functions HLIL, as in the source decompile')
        self.assertEqual(results['logic round trip'].summary, 'converged at round 2')


if __name__ == '__main__':
    unittest.main()
