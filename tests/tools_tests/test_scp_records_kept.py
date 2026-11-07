#!/usr/bin/env python3
"""Unit tests for the validator's records kept check (--logic-round-trip): each round's records against the source's,
call by call. The check runs only when a plan names it, so these are what guards it (docs/HARDENING_POLICY.md)"""

from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.games.kuro1.writer.scp_writer import Kuro1ScpWriter
from falcom.ed9.writer import scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from scp_roundtrip_validator import (EXCUSED_COMMON, EXCUSED_DEAD, EXCUSED_EXTRA, EXCUSED_NO_CODE, EXCUSED_SECOND_COPY,
                                     Status, check_logic_round_trip, check_records_kept, file_record_views, load_script,
                                     source_records)
from tests.shared.scp_writer_test_utils import fresh_writer, local_call

STRING_DEFAULT = 'fallback'


class DoublingWriter(scp_writer.ScpWriter):
    """Writes Doubled's list twice, as the older compiler does"""

    def _build_debug_records(self):
        super()._build_debug_records()
        function = self.functions_by_name.get('Doubled')
        if function is not None:
            function.debug_records *= 2


class StubRecordsWriter(scp_writer.ScpWriter):
    """Gives Stub, which makes no call, Caller's records"""

    def _build_debug_records(self):
        super()._build_debug_records()
        self.functions_by_name['Stub'].debug_records = list(self.functions_by_name['Caller'].debug_records)


class LostRecordWriter(scp_writer.ScpWriter):
    """Loses Caller's syscall record, which no alignment can leave out"""

    def _build_debug_records(self):
        super()._build_debug_records()
        del self.functions_by_name['Caller'].debug_records[0]


def define_calls(writer: scp_writer.ScpWriter):
    """Caller makes a syscall with a String, a local call with one argument the rule keeps and one it trims, and a
    second local call"""
    @writer.LLILCode()
    def Callee(arg1: Value32, arg2: Value32 = 0):
        POP(2 * WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Other():
        RETURN()

    @writer.LLILCode()
    def Caller():
        PUSH_STR('spoken')
        SYSCALL(1, 2, 1)
        POP(WORD_SIZE)
        local_call(Callee, 'written_out', ((PUSH_INT, 0), (PUSH_INT, 1)), debug_argc=2)
        local_call(Other, 'other', ())
        RETURN()


class RecordsKeptTestCase(unittest.TestCase):
    def setUp(self):
        self.addCleanup(fresh_writer)
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def compiled(self, writer: scp_writer.ScpWriter, define) -> tuple[dict, dict]:
        """define's script through writer: its source records and its record views"""
        dat = self.folder / 'test.dat'
        scp_writer.install_scp_writer(writer)
        create_scp_writer(str(dat))
        define(writer)
        writer.run({})
        ctx = load_script(dat)
        self.addCleanup(ctx.fs.Close)
        return source_records(ctx), file_record_views(ctx.data)

    def assert_failed(self, source: dict, views: dict, expected: str):
        result = check_records_kept(source, views)
        self.assertEqual((result.status, len(result.details)), (Status.FAIL, 1), result.details)
        self.assertIn(expected, result.details[0])

    def assert_excused(self, source: dict, views: dict, reason: str, count: int):
        result = check_records_kept(source, views)
        self.assertEqual(result.status, Status.PASS, result.details)
        self.assertIn(f'{count} {reason}', result.summary)


class TestALossFails(RecordsKeptTestCase):
    def setUp(self):
        super().setUp()
        self.source, self.views = self.compiled(scp_writer.ScpWriter(), define_calls)
        self.caller = self.views['Caller']

    def with_caller(self, records: list) -> dict:
        return {**self.views, 'Caller': records}

    def test_an_unchanged_rebuild_passes(self):
        result = check_records_kept(self.source, self.views)
        self.assertEqual((result.status, result.summary), (Status.PASS, '3 kept (0 trimmed)'))

    def test_a_lost_record(self):
        self.assert_failed(self.source, self.with_caller(self.caller[:-1]), 'Caller record 2: missing')

    def test_an_added_record(self):
        self.assert_failed(self.source, self.with_caller(self.caller + self.caller[:1]), 'Caller record 3: extra')

    def test_two_swapped(self):
        swapped = [self.caller[1], self.caller[0], self.caller[2]]
        self.assert_failed(self.source, self.with_caller(swapped), 'Caller record 0')

    def test_a_changed_string(self):
        syscall = self.caller[0]
        args = (*syscall.args[:-1], (syscall.args[-1][0], 'other'))
        self.assert_failed(self.source, self.with_caller([replace(syscall, args=args), *self.caller[1:]]), "'other'")

    def test_a_changed_callee(self):
        changed = replace(self.caller[2], callee='Callee')
        self.assert_failed(self.source, self.with_caller([*self.caller[:2], changed]), 'callee Callee, original Other')

    def test_a_trim_down_to_the_rule_passes(self):
        call = self.caller[1]
        trimmed = self.with_caller([self.caller[0], replace(call, args=call.args[:1]), self.caller[2]])
        result = check_records_kept(self.source, trimmed)
        self.assertEqual((result.status, result.summary), (Status.PASS, '3 kept (1 trimmed)'))

    def test_a_trim_below_the_rule(self):
        call = self.caller[1]
        self.assert_failed(self.source, self.with_caller([self.caller[0], replace(call, args=()), self.caller[2]]),
                           'Caller record 1: 0 args, the rule keeps 1')

    def test_a_function_gone_is_left_to_the_logic_check(self):
        views = {name: records for name, records in self.views.items() if name != 'Caller'}
        self.assertEqual(check_records_kept(self.source, views).status, Status.PASS)

    def test_records_that_dont_pair_fail(self):
        source, views = self.compiled(LostRecordWriter(), define_calls)
        self.assert_failed(source, views, "Caller: the source's 2 records don't pair with its calls")


class TestExcuses(RecordsKeptTestCase):
    def test_a_dead_call(self):
        def define(writer):
            @writer.LLILCode()
            def Callee():
                RETURN()

            @writer.LLILCode()
            def Main():
                RETURN()
                local_call(Callee, 'dead', ())
                RETURN()

        source, views = self.compiled(scp_writer.ScpWriter(), define)
        self.assert_excused(source, {**views, 'Main': []}, EXCUSED_DEAD, 1)

    def test_a_second_copy(self):
        def define(writer):
            define_calls(writer)

            @writer.LLILCode()
            def Doubled():
                local_call(writer.functions_by_name['Other'].body, 'doubled', ())
                RETURN()

        source, views = self.compiled(DoublingWriter(), define)
        self.assertEqual(len(views['Doubled']), 2)
        self.assert_excused(source, {**views, 'Doubled': views['Doubled'][:1]}, EXCUSED_SECOND_COPY, 1)

    def test_a_common_function_a_sora_writer_leaves_without(self):
        def define(writer):
            @writer.LLILCommonCode()
            def Common():
                PUSH_INT(1)
                SYSCALL(1, 2, 1)
                POP(WORD_SIZE)
                RETURN()

        source, views = self.compiled(Kuro1ScpWriter(), define)
        self.assert_excused(source, {**views, 'Common': []}, EXCUSED_COMMON, 1)

    def test_a_common_function_with_no_records_expects_none(self):
        def define(writer):
            @writer.LLILCommonCode()
            def Common():
                PUSH_INT(1)
                SYSCALL(1, 2, 1)
                POP(WORD_SIZE)
                RETURN()

        source, views = self.compiled(scp_writer.ScpWriter(), define)
        self.assertEqual(check_records_kept(source, views).status, Status.PASS)

    def test_a_function_with_no_code_left(self):
        def define(writer):
            define_calls(writer)

            @writer.LLILCode()
            def Stub():
                RETURN()

        source, views = self.compiled(StubRecordsWriter(), define)
        self.assert_excused(source, {**views, 'Stub': []}, EXCUSED_NO_CODE, 3)

    def test_a_call_the_compiler_left_without_a_record(self):
        def define(writer):
            @writer.LLILCode()
            def Skill(arg1: Value32):
                POP(WORD_SIZE)
                RETURN()

            @writer.LLILCode()
            def SkillTable():
                for number, recorded in enumerate((True, False)):
                    PUSH_CURRENT_FUNC_ID()
                    PUSH_RET_ADDR(f'ret{number}')
                    PUSH_INT(number)
                    CALL(Skill, debug_record=recorded)
                    label(f'ret{number}')

                RETURN()

        source, views = self.compiled(scp_writer.ScpWriter(), define)
        [kept] = views['SkillTable']
        extra = replace(kept, args=((kept.args[0][0], 1),))
        self.assert_excused(source, {**views, 'SkillTable': [kept, extra]}, EXCUSED_EXTRA, 1)
        self.assert_failed(source, {**views, 'SkillTable': [kept, replace(extra, callee='SkillTable')]},
                           'call of Skill')


class TestNoDefaultFallback(RecordsKeptTestCase):
    def trim_of(self, callee_name: str) -> tuple[dict, dict]:
        """A call of callee_name that writes out its String default, and a rebuild that trims it"""
        def define(writer):
            def body(arg1: str = STRING_DEFAULT):
                POP(WORD_SIZE)
                RETURN()

            body.__name__ = callee_name
            writer.LLILCode()(body)

            @writer.LLILCode()
            def Main():
                local_call(body, 'ret', ((PUSH_STR, STRING_DEFAULT),), debug_argc=1)
                RETURN()

        source, views = self.compiled(scp_writer.ScpWriter(), define)
        [record] = views['Main']
        return source, {**views, 'Main': [replace(record, args=())]}

    def test_the_walk_loses_the_name_where_it_has_no_fallback(self):
        self.assert_failed(*self.trim_of('chr_play_animeclip'), 'chr_play_animeclip dropped a String')

    def test_the_walk_falls_back_elsewhere(self):
        source, views = self.trim_of('chr_other')
        self.assertEqual(check_records_kept(source, views).status, Status.PASS)


class TestEveryRound(RecordsKeptTestCase):
    def test_every_round_is_checked(self):
        self.compiled(scp_writer.ScpWriter(), define_calls)
        work = self.folder / 'work'
        work.mkdir()
        names = [result.name for result in check_logic_round_trip(self.folder / 'test.dat', work)]
        self.assertEqual([name for name in names if name.endswith('records kept')],
                         ['round 1 records kept', 'round 2 records kept'])


if __name__ == '__main__':
    unittest.main()
