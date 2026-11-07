#!/usr/bin/env python3
"""Unit tests for MLIL provenance: every statement's llil_index names the LLIL instruction it comes from, at the
same address, and every statement of a finished MLIL function has a unique inst_index, 0..N-1 in block order."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from tests.shared.llil_utils import ProvenanceTestCase, build_call_function


class TestTranslatedProvenance(ProvenanceTestCase):
    """Through the decompile path's converter"""

    def test_every_statement_names_its_llil_instruction(self):
        llil = build_call_function()
        mlil = convert_falcom_llil_to_mlil_stack(llil)
        self.assertIs(mlil.llil_function, llil)
        self.check_contract(mlil, llil)


if __name__ == '__main__':
    unittest.main()
