#!/usr/bin/env python3
'''Unit tests for tools/ir_line_order_report.py: MLIL line directives are read in address order, and
a file is analysed the way scena2py.py decompiles it. BlockMergePass splices a block onto its only
predecessor wherever that sits in the block list, so reading MLIL in block order reports line
reorders the bytecode does not have.'''

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.scena2py import RECURSION_LIMIT
from falcom.ed9.scena2py_config import ScenaDecompileConfig
from ir.mlil.mlil import MediumLevelILFunction, MLILDebug, MLILGoto, MLILIf, MLILRet, MLILVar
from ir.mlil.passes import BlockMergePass
from ir_line_order_report import analyse_file, collect_mlil_lines


SMALL_SCRIPT = Path(__file__).parent.parent / 'sora2_1.0' / 'script_en' / 'minigame' / 'slot.dat'
PYTHON_DEFAULT_RECURSION_LIMIT = 1000

ENTRY_START = 0x1000
HEAD_START = 0x1010
OTHER_START = 0x1020
TARGET_START = 0x1030

ENTRY_LINE = 10
HEAD_LINE = 20
OTHER_LINE = 30
TARGET_LINE = 40


class TestMLILLinesInAddressOrder(unittest.TestCase):

    def test_block_spliced_onto_an_earlier_block_keeps_its_address_order(self):
        func = MediumLevelILFunction('merged')
        entry = func.create_block(start = ENTRY_START, label = 'entry')
        head = func.create_block(start = HEAD_START, label = 'head')
        other = func.create_block(start = OTHER_START, label = 'other')
        target = func.create_block(start = TARGET_START, label = 'target')
        cond = MLILVar(func.get_or_create_local('cond'))

        entry.add_instruction(MLILDebug('line', ENTRY_LINE, address = ENTRY_START))
        entry.add_instruction(MLILIf(cond, head, other))
        entry.add_outgoing_edge(head)
        entry.add_outgoing_edge(other)

        head.add_instruction(MLILDebug('line', HEAD_LINE, address = HEAD_START))
        head.add_instruction(MLILGoto(target))
        head.add_outgoing_edge(target)

        other.add_instruction(MLILDebug('line', OTHER_LINE, address = OTHER_START))
        other.add_instruction(MLILRet(None))

        target.add_instruction(MLILDebug('line', TARGET_LINE, address = TARGET_START))
        target.add_instruction(MLILRet(None))

        BlockMergePass().run(func)

        # head's goto was target's only way in: target's code now sits ahead of other's block
        self.assertEqual(func.basic_blocks, [entry, head, other])
        self.assertIn(TARGET_LINE, [inst.value for inst in head.instructions if isinstance(inst, MLILDebug)])

        self.assertEqual(collect_mlil_lines(func), [ENTRY_LINE, HEAD_LINE, OTHER_LINE, TARGET_LINE])


class TestAnalyseFileMatchesScena2py(unittest.TestCase):
    '''The report describes the generated .ts only if it runs the same pipeline: scena2py's parser
    settings, and its recursion headroom so the most deeply nested scripts are not dropped'''

    def setUp(self):
        if not SMALL_SCRIPT.exists():
            self.skipTest(f'Test file not found: {SMALL_SCRIPT}')

        self.addCleanup(sys.setrecursionlimit, sys.getrecursionlimit())
        sys.setrecursionlimit(PYTHON_DEFAULT_RECURSION_LIMIT)

        self.load_settings = []
        real_load = ScpParser.load

        def recording_load(path, **settings):
            self.load_settings.append(settings)
            return real_load(path, **settings)

        with mock.patch.object(ScpParser, 'load', recording_load):
            self.reports = analyse_file(SMALL_SCRIPT)

    def test_parses_with_scena2py_settings(self):
        config = ScenaDecompileConfig()
        expected = {'round_trip': config.round_trip, 'keep_unreachable_code': config.keep_unreachable_code}

        self.assertEqual(self.load_settings, [expected])
        self.assertTrue(self.reports)

    def test_raises_the_recursion_limit_to_scena2py_headroom(self):
        self.assertGreaterEqual(sys.getrecursionlimit(), RECURSION_LIMIT)


if __name__ == '__main__':
    unittest.main()
