#!/usr/bin/env python3
"""The debug text of every HLIL node (str) and its repr. Debug text is what a failing test and a log line show, so a
node that prints None or the wrong branch hides the real failure."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.hlil import (
    BinaryOp, UnaryOp, HLILTypeKind, HLILOperation, HighLevelILFunction, HLILAddressOf, HLILAssign, HLILBinaryOp,
    HLILBlock, HLILBreak, HLILCall, HLILComment, HLILConst, HLILContinue, HLILDeref, HLILDoWhile, HLILExprStmt,
    HLILExternCall, HLILIf, HLILInstruction, HLILReturn, HLILSwitch, HLILSwitchCase, HLILSyscall, HLILUnaryOp,
    HLILUnstructured, HLILVar, HLILVariable, HLILWhile,
)

HEX_VALUE = 0xFF
LABEL = 'loop_1'


def cond() -> HLILVar:
    return HLILVar(HLILVariable('c'))


# (node, str(node), repr(node))
NODE_TEXT = [
    (HLILVariable('x', HLILTypeKind.INT), 'x', 'HLILVariable(x: INT)'),
    (HLILVariable('x'), 'x', 'HLILVariable(x)'),
    (HLILConst('t'), '"t"', 'HLILConst(t)'),
    (HLILConst('a"b'), r'"a\"b"', 'HLILConst(a"b)'),
    (HLILConst(True), 'true', 'HLILConst(True)'),
    (HLILConst(HEX_VALUE, True), '0x000000FF', 'HLILConst(255)'),
    (HLILConst(HEX_VALUE), '255', 'HLILConst(255)'),
    (HLILBinaryOp(BinaryOp.ADD, cond(), HLILConst(1)), 'c + 1', 'HLILBinaryOp(ADD)'),
    (HLILUnaryOp(UnaryOp.NOT, cond()), '!c', 'HLILUnaryOp(NOT)'),
    (HLILAddressOf(cond()), '&c', 'HLILAddressOf(c)'),
    (HLILDeref(cond()), '*c', 'HLILDeref(c)'),
    (HLILCall('f', [cond()]), 'f(c)', 'HLILCall(f, 1 args)'),
    (HLILSyscall(0, 3, [cond()]), '0.3(c)', 'HLILSyscall(0.3)'),
    (HLILExternCall('m:g', [cond()]), 'm:g(c)', 'HLILExternCall(m:g, 1 args)'),
    (HLILBlock([HLILReturn()]), '{ 1 statements }', 'HLILBlock(1 stmts)'),
    (HLILIf(cond(), HLILBlock()), 'if (c) { ... }', 'HLILIf(cond=c)'),
    (HLILWhile(cond(), HLILBlock()), 'while (c) { ... }', 'HLILWhile(cond=c)'),
    (HLILWhile(cond(), HLILBlock(), LABEL), 'loop_1: while (c) { ... }', 'HLILWhile(cond=c)'),
    (HLILDoWhile(cond(), HLILBlock()), 'do { ... } while (c)', 'HLILDoWhile(cond=c)'),
    (HLILDoWhile(cond(), HLILBlock(), LABEL), 'loop_1: do { ... } while (c)', 'HLILDoWhile(cond=c)'),
    (HLILSwitch(cond(), []), 'switch (c) { 0 cases }', 'HLILSwitch(0 cases)'),
    (HLILBreak(), 'break', 'HLILBreak()'),
    (HLILBreak(LABEL), 'break loop_1', 'HLILBreak(loop_1)'),
    (HLILContinue(), 'continue', 'HLILContinue()'),
    (HLILContinue(LABEL), 'continue loop_1', 'HLILContinue(loop_1)'),
    (HLILReturn(), 'return', 'HLILReturn(None)'),
    (HLILReturn(HLILConst(1)), 'return 1', 'HLILReturn(1)'),
    (HLILUnstructured('L', 'why'), 'unstructured jump to L (why)', 'HLILUnstructured(L)'),
    (HLILAssign(cond(), HLILConst(1)), 'c = 1', 'HLILAssign(c = 1)'),
    (HLILExprStmt(HLILCall('f', [])), 'f()', 'HLILExprStmt(f())'),
    (HLILComment('note'), '// note', 'HLILComment(note)'),
    (HighLevelILFunction('fn'), 'HighLevelILFunction(fn, 0 stmts)', 'HighLevelILFunction(fn)'),
    (HLILSwitchCase([HLILConst(1), HLILConst(2)], HLILBlock()), 'case 1, 2: { ... }', 'HLILSwitchCase(1, 2)'),
    (HLILSwitchCase(None, HLILBlock()), 'default: { ... }', 'HLILSwitchCase(default)'),
]


class TestNodeText(unittest.TestCase):

    def test_str_and_repr_of_every_node(self):
        for node, text, representation in NODE_TEXT:
            with self.subTest(node=representation):
                self.assertEqual(str(node), text)
                self.assertEqual(repr(node), representation)

    def test_base_node_prints_its_operation(self):
        self.assertEqual(str(HLILInstruction(HLILOperation.HLIL_BLOCK)), 'HLIL_BLOCK')


if __name__ == '__main__':
    unittest.main()
