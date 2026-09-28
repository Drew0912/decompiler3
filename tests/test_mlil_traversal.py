#!/usr/bin/env python3
'''Unit tests for MLIL operand traversal - operands(), walk() and iter_ssa_reads(), the one
shared answer to "what does this node read" that every use collector is built on.'''

from pathlib import Path
import itertools
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILInstruction, MediumLevelILFunction, MediumLevelILBasicBlock, MediumLevelILCall,
    MLILVariable, MLILConst, MLILUndef, MLILVar, MLILSetVar, MLILBinaryOp, MLILUnaryOp, MLILAdd, MLILMul,
    MLILNeg, MLILAddressOf, MLILGoto, MLILIf, MLILRet, MLILCall, MLILSyscall, MLILCallScript,
    MLILLoadGlobal, MLILStoreGlobal, MLILLoadReg, MLILStoreReg, MLILNop, MLILDebug, MLILStoreDeref, walk,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILPhi, iter_ssa_reads
from ir.mlil.passes.pass_ssa_copy_propagation import CopyPropagationPass
from ir.mlil.passes.pass_ssa_expression_inlining import ExpressionInliningPass


def concrete_subclasses(base: type) -> set:
    found = set()
    pending = list(base.__subclasses__())
    while pending:
        cls = pending.pop()
        children = cls.__subclasses__()
        if children:
            pending.extend(children)

        else:
            found.add(cls)

    return found


_const_values = itertools.count()


def c() -> MLILConst:
    '''A constant whose value no other c() call returns, so every operand is distinct'''
    return MLILConst(next(_const_values))


def samples() -> list:
    '''One instance of every concrete MLIL node type, with distinct expression operands.'''
    block = MediumLevelILBasicBlock(0)
    var = MLILVariable('x')
    ssa_var = MLILVariableSSA(var, 1)
    nodes = [
        c(), MLILUndef(), MLILVar(var), MLILSetVar(var, c()),
        MLILGoto(block), MLILIf(c(), block, block), MLILRet(c()), MLILRet(),
        MLILCall('f', [c(), c()]), MLILSyscall(1, 2, [c(), c()]), MLILCallScript('m', 'f', [c(), c()]),
        MLILLoadGlobal(0), MLILStoreGlobal(0, c()), MLILLoadReg(0), MLILStoreReg(0, c()),
        MLILNop(), MLILDebug('line', 5), MLILStoreDeref(c(), c()),
        MLILVarSSA(ssa_var), MLILSetVarSSA(ssa_var, c()), MLILPhi(ssa_var, [(MLILVariableSSA(var, 0), block)]),
    ]
    nodes += [cls(c(), c()) for cls in concrete_subclasses(MLILBinaryOp)]
    nodes += [cls(c()) for cls in concrete_subclasses(MLILUnaryOp)]
    return nodes


def expression_fields(node) -> list:
    '''Every MLIL expression a node holds in a field, lists included.'''
    found = []
    for value in vars(node).values():
        for item in (value if isinstance(value, (list, tuple)) else [value]):
            if isinstance(item, MediumLevelILInstruction):
                found.append(item)

    return found


class TestOperandsCoverEveryExpressionField(unittest.TestCase):
    '''operands() is the single list of a node's direct child expressions: every node type must
    return exactly the expressions it holds. A new node type fails here until it has a sample and
    its own operands().'''

    def test_every_node_type_has_a_sample(self):
        sampled = {type(node) for node in samples()}
        missing = concrete_subclasses(MediumLevelILInstruction) - sampled
        self.assertEqual(missing, set(), [cls.__name__ for cls in missing])

    def test_operands_are_exactly_the_expression_fields(self):
        for node in samples():
            with self.subTest(node = type(node).__name__):
                self.assertCountEqual(map(id, node.operands()), map(id, expression_fields(node)))

    def test_operands_are_in_evaluation_order(self):
        lhs, rhs = c(), c()
        args = [c(), c(), c()]
        dest, value = c(), c()

        self.assertEqual(list(MLILAdd(lhs, rhs).operands()), [lhs, rhs])
        self.assertEqual(list(MLILCall('f', args).operands()), args)
        self.assertEqual(list(MLILStoreDeref(dest, value).operands()), [dest, value])


class TestWalk(unittest.TestCase):
    '''walk() yields a node and everything below it, pre-order in evaluation order.'''

    def test_pre_order_left_to_right(self):
        a, b, d = c(), c(), c()
        add = MLILAdd(a, b)
        neg = MLILNeg(d)
        mul = MLILMul(add, neg)
        store = MLILStoreGlobal(0, mul)

        self.assertEqual(list(walk(store)), [store, mul, add, a, b, neg, d])

    def test_skip_yields_the_node_but_not_its_operand(self):
        var = MLILVar(MLILVariable('x'))
        address = MLILAddressOf(var)
        call = MLILCall('f', [address])

        self.assertEqual(list(walk(call, skip = (MLILAddressOf,))), [call, address])


class TestIterSSAReads(unittest.TestCase):
    '''iter_ssa_reads() gives (variable, reader) in evaluation order: the reader is the
    MLILVarSSA node itself (passes identity-search for it), or the phi for a phi source.'''

    def setUp(self):
        self.x = MLILVariable('x')
        self.x1 = MLILVariableSSA(self.x, 1)
        self.x2 = MLILVariableSSA(self.x, 2)

    def test_reader_is_the_variable_node(self):
        first, second = MLILVarSSA(self.x1), MLILVarSSA(self.x2)
        ret = MLILRet(MLILAdd(first, second))

        self.assertEqual(list(iter_ssa_reads(ret)), [(self.x1, first), (self.x2, second)])

    def test_phi_sources_are_read_by_the_phi(self):
        block = MediumLevelILBasicBlock(0)
        phi = MLILPhi(MLILVariableSSA(self.x, 3), [(self.x1, block), (self.x2, block)])

        self.assertEqual(list(iter_ssa_reads(phi)), [(self.x1, phi), (self.x2, phi)])

    def test_skip_excludes_a_read_under_address_of(self):
        plain, taken = MLILVarSSA(self.x1), MLILVarSSA(self.x2)
        call = MLILCall('f', [plain, MLILAddressOf(taken)])

        self.assertEqual([var for var, _ in iter_ssa_reads(call)], [self.x1, self.x2])
        self.assertEqual([var for var, _ in iter_ssa_reads(call, skip = (MLILAddressOf,))], [self.x1])


class TestWalkerRulesKept(unittest.TestCase):
    '''Rules individual passes keep on top of the shared traversal.'''

    def test_copy_propagation_does_not_count_a_read_under_address_of(self):
        # it never rewrites the operand of &, so that read is not one of its uses
        x1 = MLILVariableSSA(MLILVariable('x'), 1)
        call = MLILCall('f', [MLILVarSSA(x1), MLILAddressOf(MLILVarSSA(x1))])

        self.assertEqual(CopyPropagationPass._collect_uses(call), [x1])

    def test_call_types_are_exactly_the_three_call_classes(self):
        # passes rely on MediumLevelILCall covering exactly these three call classes
        self.assertEqual(concrete_subclasses(MediumLevelILCall), {MLILCall, MLILSyscall, MLILCallScript})

    def test_inliner_rejects_a_call_inside_an_expression(self):
        # MLIL calls are statements; a call nested in an expression would be a translator bug
        func = MediumLevelILFunction('call_in_expression', 0)
        x1 = MLILVariableSSA(MLILVariable('x'), 1)
        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILAdd(MLILCall('f', []), c())),
            MLILRet(MLILVarSSA(x1)),
        ]
        func.basic_blocks = [block]

        with self.assertRaises(ValueError):
            ExpressionInliningPass().run(func)


if __name__ == '__main__':
    unittest.main()
