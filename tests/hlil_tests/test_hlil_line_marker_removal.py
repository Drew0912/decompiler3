#!/usr/bin/env python3
'''Unit tests for line_marker_number, LineMarkerRemovalPass and convert_falcom_mlil_to_hlil's line_markers flag: off,
the line(N) comments go once every pass that reads them has run, so the code statements and their order stay, and
the if arms they leave empty are tidied. Any other comment stays.'''

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILComment,
    HLILConst,
    HLILExprStmt,
    HLILFormatter,
    HLILIf,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
    HLILWhile,
    LineMarkerRemovalPass,
    iter_tree,
    line_marker_number,
)
from tests.shared.hlil_cfg_utils import build_function, with_markers

LINE = 7
# DEBUG_SET_LINENO's operand can be 0: a marker like any other
ZERO_LINE = 0
THRESHOLD = 2
CASE_VALUE = 1
# The converter's one comment that is not a line marker (a test whose arms reach one block)
NOTE = 'if (C || true) { A }'
# Names a line but is not a marker
MENTION = f'see line({LINE}) for context'
MARKER_LINE = re.compile(r'^\s*// line\(\d+\)$')

# if (p) a(); else b(); m() - with_markers numbers lines in dict order, so b's comes first and branch-order
# normalization puts its arm first
SOURCE_ORDER = {
    'C':    ([], ('if', 'p', 'A', 'B')),
    'B':    (['b'], ('goto', 'M')),
    'A':    (['a'], ('goto', 'M')),
    'M':    (['m'], ('ret', 0)),
}


def marker() -> HLILComment:
    return HLILComment(f'line({LINE})')


def work(name: str) -> HLILExprStmt:
    return HLILExprStmt(HLILCall(name, []))


def condition() -> HLILBinaryOp:
    return HLILBinaryOp(BinaryOp.GT, HLILVar(HLILVariable('selector')), HLILConst(THRESHOLD))


def remove_markers(*statements) -> list:
    '''The body's statements after the pass'''
    func = HighLevelILFunction('line_markers')
    func.body = HLILBlock(list(statements))
    return LineMarkerRemovalPass().run(func).body.statements


class TestLineMarkerNumber(unittest.TestCase):
    def test_a_marker_gives_its_line(self):
        self.assertEqual(line_marker_number(marker()), LINE)

    def test_line_zero_is_a_marker(self):
        self.assertEqual(line_marker_number(HLILComment(f'line({ZERO_LINE})')), ZERO_LINE)

    def test_a_comment_naming_a_line_is_not_one(self):
        self.assertIsNone(line_marker_number(HLILComment(MENTION)))

    def test_a_statement_that_is_no_comment_is_not_one(self):
        self.assertIsNone(line_marker_number(work('a')))


class TestLineMarkerRemoval(unittest.TestCase):
    def test_markers_go_from_every_block(self):
        selector = HLILVar(HLILVariable('selector'))
        body = remove_markers(
            marker(),
            HLILIf(condition(), HLILBlock([marker(), work('a')]), HLILBlock([marker(), work('b')])),
            HLILWhile(condition(), HLILBlock([marker(), work('c')])),
            HLILSwitch(selector, [HLILSwitchCase([HLILConst(CASE_VALUE)], HLILBlock([marker(), work('d')]))]),
        )

        self.assertEqual([node for stmt in body for node in iter_tree(stmt) if isinstance(node, HLILComment)], [])
        self.assertEqual(sorted(node.func_name for stmt in body for node in iter_tree(stmt)
                                if isinstance(node, HLILCall)), ['a', 'b', 'c', 'd'])

    def test_line_zero_goes(self):
        body = remove_markers(HLILComment(f'line({ZERO_LINE})'), work('a'))

        self.assertEqual([str(stmt) for stmt in body], ['a()'])

    def test_other_comments_stay(self):
        body = remove_markers(HLILComment(NOTE), HLILComment(MENTION), marker())

        self.assertEqual([str(stmt) for stmt in body], [f'// {NOTE}', f'// {MENTION}'])

    def test_else_left_empty_goes(self):
        [result] = remove_markers(HLILIf(condition(), HLILBlock([work('a')]), HLILBlock([marker()])))

        self.assertEqual((str(result.condition), result.false_block), (f'selector > {THRESHOLD}', None))

    def test_then_left_empty_takes_the_else(self):
        [result] = remove_markers(HLILIf(condition(), HLILBlock([marker()]), HLILBlock([marker(), work('b')])))

        self.assertEqual(str(result.condition), f'selector <= {THRESHOLD}')
        self.assertEqual([str(stmt) for stmt in result.true_block.statements], ['b()'])
        self.assertIsNone(result.false_block)

    def test_then_left_empty_before_an_else_if_takes_it(self):
        inner = HLILIf(HLILCall('ready', []), HLILBlock([work('b')]))
        [result] = remove_markers(HLILIf(condition(), HLILBlock([marker()]), HLILBlock([marker(), inner])))

        self.assertEqual(str(result.condition), f'selector <= {THRESHOLD}')
        self.assertEqual(result.true_block.statements, [inner])

    def test_both_left_empty_keep_the_test(self):
        [result] = remove_markers(HLILIf(HLILCall('check', []), HLILBlock([marker()]), HLILBlock([marker()])))

        self.assertEqual((str(result.condition), result.true_block.statements, result.false_block),
                         ('check()', [], None))


class TestLineMarkersFlag(unittest.TestCase):
    '''convert_falcom_mlil_to_hlil's line_markers: on by default; off, a function with no arm left empty loses only its
    comments, also where the markers decide the arm order (so the pass must run after branch-order normalization)'''

    def text(self, **flags) -> list:
        func = build_function('f', with_markers(SOURCE_ORDER))
        return HLILFormatter.format_function(convert_falcom_mlil_to_hlil(func, **flags))

    def test_on_by_default(self):
        self.assertTrue(any(MARKER_LINE.match(line) for line in self.text()))

    def test_off_changes_only_the_comments(self):
        self.assertEqual(self.text(line_markers = False),
                         [line for line in self.text() if not MARKER_LINE.match(line)])


if __name__ == '__main__':
    unittest.main()
