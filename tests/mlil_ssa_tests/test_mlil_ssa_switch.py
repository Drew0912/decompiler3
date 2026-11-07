#!/usr/bin/env python3
"""Dispatch chains as the compiler writes them, assembled, through the SSA path and HLIL: the labels the stack path
gives"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil_ssa.mlil_converter import convert_falcom_llil_to_mlil_ssa
from tests.shared.switch_chains import IF_SHAPES, SWITCH_SHAPES, case_labels, hlil_and_differences, switches


def convert(llil):
    return convert_falcom_llil_to_mlil_ssa(llil, optimize=True, infer_types=False)


class TestSwitchOnSSAPath(unittest.TestCase):
    def test_each_chain_is_one_switch(self):
        for name, (build, selector, labels) in SWITCH_SHAPES.items():
            with self.subTest(chain=name):
                hlil, differences = hlil_and_differences(build, selector.argc, convert)

                [switch] = switches(hlil)
                self.assertEqual(case_labels(switch), labels)
                self.assertEqual(differences, set())

    def test_a_short_chain_and_an_ordering_chain_stay_ifs(self):
        for name, build in IF_SHAPES.items():
            with self.subTest(chain=name):
                hlil, differences = hlil_and_differences(build, 0, convert)

                self.assertEqual(switches(hlil), [])
                self.assertEqual(differences, set())


if __name__ == '__main__':
    unittest.main()
