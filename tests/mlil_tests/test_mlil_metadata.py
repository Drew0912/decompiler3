#!/usr/bin/env python3
"""Unit tests for MLIL metadata preservation."""

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil import MLILRet
from tests.shared.ir_utils import MetadataTestCase, set_metadata


SOURCE_ADDRESS = 0x1000
SOURCE_INST_INDEX = 42
SOURCE_LLIL_INDEX = 24


class TestMLILMetadataPreservation(MetadataTestCase):
    """Tests for MLIL source metadata propagation."""

    def test_copy_metadata_from_copies_source_tracking(self):
        source = set_metadata(MLILRet(), SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)
        target = MLILRet()

        copied = target.copy_metadata_from(source)

        self.assertIs(copied, target)
        self.assert_metadata(target, SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)


if __name__ == '__main__':
    unittest.main()
