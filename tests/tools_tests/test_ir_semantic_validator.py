#!/usr/bin/env python3
"""Unit tests for tools/ir_semantic_validator.py: a regression export compared with a run of the same script reports
no change; the comparison goes by difference (category and key), so one difference replaced by another of its category
is a regression and an improvement both; a new internal error is a regression"""

from pathlib import Path
import contextlib
import io
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from tests.shared.corpus import SORA2_SCRIPTS, require
from ir_semantic_validator import BASELINE_VERSION, CHECK, IRPipeline, changes, compare_baseline, export_baseline

SCRIPT = 'ai/ai_chr0100_e00.dat'    # 18 functions
FUNCTION = 'f'
FIRST_KEY = "(4772, 'call')"
OTHER_KEY = "(4800, 'call')"


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


if __name__ == '__main__':
    unittest.main()
