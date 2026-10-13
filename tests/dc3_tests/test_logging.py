#!/usr/bin/env python3
'''The shared logger (dc3.logging.log): a level change always takes effect, even after the level was cached.'''

from pathlib import Path
import logging
import sys
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.logging import log


class TestLogLevel(unittest.TestCase):

    def test_info_enabled_again_after_assert_logs(self):
        with self.assertLogs(log, 'WARNING'):
            log.info('dropped at WARNING')
            log.warning('captured')

        self.assertTrue(log.isEnabledFor(logging.INFO))

    def test_set_level_after_a_cached_check(self):
        self.addCleanup(log.setLevel, log.level)
        self.assertTrue(log.isEnabledFor(logging.INFO))
        log.setLevel(logging.ERROR)
        self.assertFalse(log.isEnabledFor(logging.INFO))

    def test_records_do_not_reach_the_root_logger(self):
        with mock.patch.object(log, 'handlers', [logging.NullHandler()]), self.assertNoLogs(logging.getLogger(), 'INFO'):
            log.warning('only on the shared handler')


if __name__ == '__main__':
    unittest.main()
