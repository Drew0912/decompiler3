#!/usr/bin/env python3
'''dc3/gc_policy.py: infrequent_gc() spaces collections out for a block and restores the thresholds it found, and
the decompile and compile entry points run under it.'''

from pathlib import Path
import gc
import sys
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.gc_policy import GC_THRESHOLD, infrequent_gc
from falcom.ed9 import scena2py
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from falcom.ed9.writer.scp_writer import ScpWriter

OUTER_THRESHOLDS = (700, 11, 12)


class Stop(Exception):
    pass


class TestInfrequentGc(unittest.TestCase):

    def setUp(self):
        self.addCleanup(gc.set_threshold, *gc.get_threshold())
        gc.set_threshold(*OUTER_THRESHOLDS)

    def test_threshold_inside_the_block_and_restored_after(self):
        with infrequent_gc():
            self.assertEqual(gc.get_threshold(), (GC_THRESHOLD, *OUTER_THRESHOLDS[1:]))

        self.assertEqual(gc.get_threshold(), OUTER_THRESHOLDS)

    def test_restored_after_an_exception(self):
        with self.assertRaises(Stop):
            with infrequent_gc():
                raise Stop

        self.assertEqual(gc.get_threshold(), OUTER_THRESHOLDS)

    def test_nested_use_restores_only_at_the_outer_end(self):
        with infrequent_gc():
            with infrequent_gc():
                pass

            self.assertEqual(gc.get_threshold()[0], GC_THRESHOLD)

        self.assertEqual(gc.get_threshold(), OUTER_THRESHOLDS)

    def test_collector_switched_off_by_the_caller_stays_off(self):
        self.addCleanup(gc.enable)
        gc.disable()
        with infrequent_gc():
            self.assertFalse(gc.isenabled())

        self.assertFalse(gc.isenabled())

    def test_decorated_function_runs_under_it_on_every_call(self):
        seen = []

        @infrequent_gc()
        def work():
            seen.append(gc.get_threshold()[0])

        work()
        work()
        self.assertEqual(seen, [GC_THRESHOLD, GC_THRESHOLD])
        self.assertEqual(gc.get_threshold(), OUTER_THRESHOLDS)


class TestEntryPoints(unittest.TestCase):

    def setUp(self):
        self.addCleanup(gc.set_threshold, *gc.get_threshold())
        gc.set_threshold(*OUTER_THRESHOLDS)
        self.seen = []

    def record_and_stop(self, *args, **kwargs):
        self.seen.append(gc.get_threshold()[0])
        raise Stop

    def test_decompile_runs_under_it(self):
        with mock.patch.object(scena2py.ScpParser, 'load', side_effect = self.record_and_stop):
            with self.assertRaises(Stop):
                scena2py.process_file(Path('x.dat'), ScenaDecompileConfig())

        self.assertEqual(self.seen, [GC_THRESHOLD])
        self.assertEqual(gc.get_threshold(), OUTER_THRESHOLDS)

    def test_compile_runs_under_it(self):
        writer = ScpWriter()
        with mock.patch.object(writer, 'build', side_effect = self.record_and_stop):
            with self.assertRaises(Stop):
                writer.run({})

        self.assertEqual(self.seen, [GC_THRESHOLD])
        self.assertEqual(gc.get_threshold(), OUTER_THRESHOLDS)


if __name__ == '__main__':
    unittest.main()
