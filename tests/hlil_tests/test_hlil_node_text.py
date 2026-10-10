#!/usr/bin/env python3
'''The debug text of every HLIL node (str) and its repr, and the attributes every node starts with. Debug
text is what a failing test and a log line show, so a node that prints None or the wrong branch hides the
real failure.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.core import UNASSIGNED_INST_INDEX
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
    (HLILConst(True), 'true', 'HLILConst(True)'),
    (HLILConst(HEX_VALUE, True), '0x000000FF', 'HLILConst(255)'),
    (HLILConst(HEX_VALUE), '255', 'HLILConst(255)'),
    (HLILBinaryOp(BinaryOp.ADD, cond(), HLILConst(1)), 'c + 1', 'HLILBinaryOp(ADD)'),
    (HLILUnaryOp(UnaryOp.NOT, cond()), '!c', 'HLILUnaryOp(NOT)'),
    (HLILAddressOf(cond()), '&c', 'HLILAddressOf(c)'),
    (HLILDeref(cond()), '*c', 'HLILDeref(c)'),
    (HLILCall('f', [cond()]), 'f(c)', 'HLILCall(f, 1 args)'),
    (HLILSyscall('0', '3', [cond()]), '0.3(c)', 'HLILSyscall(0.3)'),
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

# Every node type and the operation it announces
NODE_OPERATIONS = [
    (HLILVar(HLILVariable('x')), HLILOperation.HLIL_VAR),
    (HLILConst(1), HLILOperation.HLIL_CONST),
    (HLILBinaryOp(BinaryOp.ADD, cond(), cond()), HLILOperation.HLIL_BINARY_OP),
    (HLILUnaryOp(UnaryOp.NOT, cond()), HLILOperation.HLIL_UNARY_OP),
    (HLILAddressOf(cond()), HLILOperation.HLIL_ADDRESS_OF),
    (HLILDeref(cond()), HLILOperation.HLIL_DEREF),
    (HLILCall('f', []), HLILOperation.HLIL_CALL),
    (HLILSyscall('0', '3', []), HLILOperation.HLIL_SYSCALL),
    (HLILExternCall('m:g', []), HLILOperation.HLIL_CALL),
    (HLILBlock(), HLILOperation.HLIL_BLOCK),
    (HLILIf(cond(), HLILBlock()), HLILOperation.HLIL_IF),
    (HLILWhile(cond(), HLILBlock()), HLILOperation.HLIL_WHILE),
    (HLILDoWhile(cond(), HLILBlock()), HLILOperation.HLIL_DO_WHILE),
    (HLILSwitch(cond(), []), HLILOperation.HLIL_SWITCH),
    (HLILBreak(), HLILOperation.HLIL_BREAK),
    (HLILContinue(), HLILOperation.HLIL_CONTINUE),
    (HLILReturn(), HLILOperation.HLIL_RETURN),
    (HLILUnstructured('L', 'why'), HLILOperation.HLIL_UNSTRUCTURED),
    (HLILAssign(cond(), HLILConst(1)), HLILOperation.HLIL_ASSIGN),
    (HLILExprStmt(HLILCall('f', [])), HLILOperation.HLIL_EXPR_STMT),
    (HLILComment('note'), HLILOperation.HLIL_COMMENT),
]


class TestNodeText(unittest.TestCase):

    def test_str_and_repr_of_every_node(self):
        for node, text, representation in NODE_TEXT:
            with self.subTest(node = representation):
                self.assertEqual(str(node), text)
                self.assertEqual(repr(node), representation)

    def test_base_node_prints_its_operation(self):
        self.assertEqual(str(HLILInstruction(HLILOperation.HLIL_BLOCK)), 'HLIL_BLOCK')


class TestNodeAttributes(unittest.TestCase):

    def test_every_node_announces_its_operation_and_starts_without_a_source(self):
        for node, operation in NODE_OPERATIONS:
            with self.subTest(node = type(node).__name__):
                self.assertEqual(node.operation, operation)
                self.assertEqual(node.address, 0)
                self.assertEqual(node.mlil_index, UNASSIGNED_INST_INDEX)

    def test_syscall_keeps_its_target(self):
        syscall = HLILSyscall('0', '3', [cond()])

        self.assertEqual((syscall.subsystem, syscall.cmd), ('0', '3'))


if __name__ == '__main__':
    unittest.main()
