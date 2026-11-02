#!/usr/bin/env python3
"""Unit tests for tools/ir_semantic_validator.py: a regression export compared with a run of the same script reports
no change; the comparison goes by difference (category and key), so one difference replaced by another of its category
is a regression and an improvement both; a new internal error is a regression. The check failing at each of its stages,
or not: the pairs it compared, and the report's pair lines, summary, JSON, --failed-only and exit status"""

from pathlib import Path
from typing import Callable
from unittest import mock
import contextlib
import io
import json
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.llil import ED9VMLifter
from tests.shared import scp_asm
from tests.shared.corpus import SORA2_SCRIPTS, require
from logic_check import Difference, LLILLayer, MLILLayer, scripts
from ir_semantic_validator import (
    BASELINE_VERSION, CHECK, PAIRS, Formatter, IRPipeline, Validator, changes, compare_baseline, export_baseline,
)

SCRIPT = 'ai/ai_chr0100_e00.dat'    # 18 functions
FUNCTION = 'f'
FIRST_KEY = "(4772, 'call')"
OTHER_KEY = "(4800, 'call')"
PLANTED_ERROR = RuntimeError('planted')
PLANTED = Difference('order_differs', (4, 'call'), 'planted')
NOT_COMPARED, PASS, FAIL = 'not compared', 'PASS', 'FAIL'   # a pair's outcome: FAIL with PLANTED alone


def document(*functions: dict) -> dict:
    """A report_json document of functions"""
    return {'version': BASELINE_VERSION, 'check': CHECK, 'file': 'f.dat', 'functions': list(functions)}


def function(hlil_differences: tuple = (), internal_error: str | None = None) -> dict:
    return {'function': FUNCTION, 'llil_mlil': [], 'mlil_hlil': [list(difference) for difference in hlil_differences],
            'decompile_error': None, 'internal_error': internal_error}


class TestRegressionBaseline(unittest.TestCase):

    def test_export_then_compare_reports_no_change(self):
        pipeline = IRPipeline(str(require(SORA2_SCRIPTS / SCRIPT)))
        self.assertTrue(pipeline.check())
        shown = io.StringIO()
        with tempfile.TemporaryDirectory() as folder:
            baseline = str(Path(folder) / 'before.json')
            self.assertTrue(export_baseline(pipeline, baseline))
            with contextlib.redirect_stdout(shown):
                self.assertEqual(compare_baseline(pipeline, baseline), 0)
        self.assertIn('No changes detected from baseline', shown.getvalue())

    def test_a_difference_by_its_category_and_key(self):
        """A guard_differs for another at another key: its category's count unchanged, yet a regression and an
        improvement"""
        found = changes(document(function([('guard_differs', FIRST_KEY, '')])),
                        document(function([('guard_differs', OTHER_KEY, '')])))
        self.assertEqual([change.found for change in found['regressions']], [f'guard_differs {OTHER_KEY}'])
        self.assertEqual([change.found for change in found['improvements']], [f'guard_differs {FIRST_KEY}'])

    def test_new_internal_error_is_a_regression(self):
        found = changes(document(function()), document(function(internal_error='HLIL: RuntimeError: planted')))
        self.assertEqual([(change.what, change.found) for change in found['regressions']],
                         [('internal error', 'HLIL: RuntimeError: planted')])


# === The check's stages ===

def failing(target, name: str) -> Callable:
    """A patch making target's name raise PLANTED_ERROR"""
    return lambda: mock.patch.object(target, name, side_effect=PLANTED_ERROR)


def failing_analysis(layer_type: type, gated: bool) -> Callable:
    """A patch making the check's analysis of a layer_type layer, gated or not, raise PLANTED_ERROR"""
    analyze = scripts.analyze

    def analysis(layer, **options):
        if isinstance(layer, layer_type) and options.get('gated', False) == gated:
            raise PLANTED_ERROR
        return analyze(layer, **options)
    return lambda: mock.patch.object(scripts, 'analyze', analysis)


STAGES = (  # the stage failing, the patch failing it, the error field, LLIL -> MLIL and MLIL -> HLIL, the exit status
    ('LLIL',       failing(ED9VMLifter, 'lift_function'),                 'decompile_error', NOT_COMPARED, NOT_COMPARED, 0),
    ('LLIL',       failing_analysis(LLILLayer, gated=False),              'internal_error',  NOT_COMPARED, NOT_COMPARED, 1),
    ('MLIL',       failing(scripts, 'convert_falcom_llil_to_mlil_stack'), 'decompile_error', NOT_COMPARED, NOT_COMPARED, 0),
    ('MLIL',       failing(scripts, 'compare_facts'),                     'internal_error',  NOT_COMPARED, NOT_COMPARED, 1),
    ('MLIL gated', failing_analysis(MLILLayer, gated=True),               'internal_error',  FAIL,         NOT_COMPARED, 1),
    ('HLIL',       failing(scripts, 'convert_falcom_mlil_to_hlil'),       'decompile_error', FAIL,         NOT_COMPARED, 1),
    ('HLIL',       failing(scripts, 'compare_gated'),                     'internal_error',  FAIL,         NOT_COMPARED, 1),
    (None,         contextlib.nullcontext,                                None,              FAIL,         PASS,         1),
    (None,         contextlib.nullcontext,                                None,              PASS,         PASS,         0),
)
DIFFERENCES = {NOT_COMPARED: None, PASS: [], FAIL: [PLANTED]}
PAIR_LINE = {NOT_COMPARED: 'not compared', PASS: 'PASS', FAIL: 'FAIL (1 difference)'}
SUMMARY = {NOT_COMPARED: '0/0 functions without differences', PASS: '1/1 functions without differences',
           FAIL: '0/1 functions without differences (order_differs 1)'}
JSON_LIST = {NOT_COMPARED: [], PASS: [], FAIL: [['order_differs', "(4, 'call')", "'planted'"]]}


def returning_function() -> tuple:
    """(parser, function) of a function that only returns: both pairs compare it clean"""
    asm = scp_asm.Asm()
    asm.push_raw(0); asm.set_reg(0); asm.ret()
    parser, functions = scp_asm.Program(scp_asm.main_function(asm)).disassemble()
    return parser, next(func for func in functions if func.name == scp_asm.FUNC_NAME)


class TestCheckStages(unittest.TestCase):
    """The check failing at each of its stages (STAGES; the LLIL -> MLIL comparison returning PLANTED where the pair
    is to FAIL, so a list handed on shows), and succeeding: the pairs it compared, and how the report shows them"""

    @classmethod
    def check(cls, fails: Callable, planted: bool) -> scripts.FunctionResult:
        parser, func = returning_function()
        planting = (mock.patch.object(scripts, 'compare_facts', return_value=[PLANTED]) if planted
                    else contextlib.nullcontext())
        with planting, fails():
            return scripts.check_function(ED9VMLifter(parser=parser), func)

    @classmethod
    def report(cls, result: scripts.FunctionResult, **options) -> tuple[int, str]:
        pipeline = IRPipeline('f.dat')
        pipeline.results = [result]
        shown = io.StringIO()
        return Validator(pipeline, Formatter(use_color=False), shown, **options).report(PAIRS), shown.getvalue()

    def test_pairs_compared_and_reported(self):
        for stage, fails, error_field, *outcomes, exit_status in STAGES:
            with self.subTest(stage=stage, error=error_field, outcomes=outcomes):
                result = self.check(fails, planted=outcomes[0] == FAIL)
                self.assertEqual([result.mlil_differences, result.hlil_differences],
                                 [DIFFERENCES[outcome] for outcome in outcomes])
                errors = {'decompile_error': result.decompile_error, 'internal_error': result.internal_error}
                self.assertEqual(errors, {field: f'{stage}: RuntimeError: planted' if field == error_field else None
                                          for field in errors})

                code, text = self.report(result)
                self.assertEqual(code, exit_status)
                lines = text.splitlines()
                for pair, outcome in zip(PAIRS, outcomes):
                    self.assertIn(f'    {pair.label}: {PAIR_LINE[outcome]}', lines)
                    self.assertIn(f'{pair.label}: {SUMMARY[outcome]}', lines)
                if FAIL in outcomes:
                    self.assertIn("      order_differs  (4, 'call')  'planted'", lines)
                if error_field is not None:
                    self.assertIn(f"    {error_field.replace('_', ' ')}: {errors[error_field]}", lines)

                code, text = self.report(result, as_json=True)
                self.assertEqual(code, exit_status)
                self.assertEqual(json.loads(text)['functions'],
                                 [{'function': scp_asm.FUNC_NAME, **{pair.key: JSON_LIST[outcome]
                                                                     for pair, outcome in zip(PAIRS, outcomes)},
                                   **errors}])

                code, text = self.report(result, failed_only=True)
                self.assertEqual(code, exit_status)
                shown = error_field is not None or FAIL in outcomes     # a difference or an error
                self.assertEqual(f'  {scp_asm.FUNC_NAME}' in text.splitlines(), shown)


if __name__ == '__main__':
    unittest.main()
