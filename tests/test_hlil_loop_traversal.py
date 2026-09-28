#!/usr/bin/env python3
'''Unit tests for uniform HLIL child-block traversal: DeadCodeEliminationPass,
CommonReturnExtractionPass and TypeScriptGenerator._infer_return_type see into every loop body,
a do-while's as well as a while's. Checked on hand-built cases.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILCall,
    HLILConst,
    HLILDoWhile,
    HLILExprStmt,
    HLILIf,
    HLILReturn,
    DeadCodeEliminationPass,
    CommonReturnExtractionPass,
)
from codegen.typescript import TypeScriptGenerator


class TestDeadCodeEliminationInDoWhile(unittest.TestCase):
    def test_dead_code_after_return_inside_do_while_body_is_removed(self):
        body = HLILBlock([
            HLILReturn(HLILConst(1)),
            HLILExprStmt(HLILCall('unreachable', [])),
        ])
        loop = HLILDoWhile(HLILConst(0), body)
        func = HighLevelILFunction('f')
        func.add_statement(loop)

        DeadCodeEliminationPass().run(func)

        self.assertEqual(len(loop.body.statements), 1)
        self.assertIsInstance(loop.body.statements[0], HLILReturn)


class TestCommonReturnExtractionInDoWhile(unittest.TestCase):
    def test_common_return_in_if_nested_in_do_while_body_is_hoisted(self):
        branch = HLILIf(
            HLILConst(1),
            HLILBlock([HLILReturn(HLILConst(5))]),
            HLILBlock([HLILReturn(HLILConst(5))]),
        )
        loop = HLILDoWhile(HLILConst(0), HLILBlock([branch]))
        func = HighLevelILFunction('f')
        func.add_statement(loop)

        CommonReturnExtractionPass().run(func)

        self.assertEqual(len(loop.body.statements), 2)
        self.assertIsInstance(loop.body.statements[0], HLILIf)
        self.assertEqual(len(loop.body.statements[0].true_block.statements), 0)
        self.assertIsInstance(loop.body.statements[1], HLILReturn)


class TestReturnTypeInferenceInDoWhile(unittest.TestCase):
    def test_return_only_inside_do_while_body_is_not_typed_void(self):
        body = HLILBlock([
            HLILIf(HLILConst(1), HLILBlock([HLILReturn(HLILConst(5))]), None),
        ])
        loop = HLILDoWhile(HLILConst(0), body)
        block = HLILBlock([loop])

        inferred = TypeScriptGenerator._infer_return_type(block)

        self.assertEqual(inferred, 'number')


if __name__ == '__main__':
    unittest.main()
