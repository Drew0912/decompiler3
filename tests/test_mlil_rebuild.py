#!/usr/bin/env python3
'''Unit tests for MLILBinaryOp.rebuild()/MLILUnaryOp.rebuild() - the one path for rebuilding a
binary or unary op with new operands (previously 7 per-pass tables that had drifted apart).'''

from pathlib import Path
import inspect
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILVar,
    MLILBinaryOp, MLILUnaryOp, MLILAdd, MLILLogicalAnd, MLILLogicalNot, MLILAddressOf, MLILDeref,
    MLILCall, MLILSyscall, MLILCallScript,
)
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILSetVarSSA, MLILRet
from ir.mlil.passes.pass_ssa_sccp import SCCP
from ir.mlil.passes.pass_ssa_constant_propagation import ConstantPropagationPass
from ir.mlil.passes.pass_ssa_nnf import NNFPass


BINARY_OP_COUNT = 18
UNARY_OP_COUNT = 6
SOURCE_ADDRESS = 0x1234
SOURCE_INST_INDEX = 7
SOURCE_LLIL_INDEX = 9
OPERAND_FIELDS = {'lhs', 'rhs', 'operand'}
BINARY_OP_PARAMETERS = ['self', 'lhs', 'rhs', 'kwargs']
UNARY_OP_PARAMETERS = ['self', 'operand', 'kwargs']


def concrete_subclasses(base: type) -> list:
    '''Every leaf subclass of base, however deep.'''
    found = []
    pending = list(base.__subclasses__())
    while pending:
        cls = pending.pop()
        children = cls.__subclasses__()
        if children:
            pending.extend(children)

        else:
            found.append(cls)

    return sorted(found, key = lambda cls: cls.__name__)


def with_metadata(inst):
    inst.address = SOURCE_ADDRESS
    inst.inst_index = SOURCE_INST_INDEX
    inst.llil_index = SOURCE_LLIL_INDEX
    return inst


def non_operand_state(inst) -> dict:
    '''Every attribute except the operands. options is compared by content: a rebuilt node gets
    fresh default ILOptions, like every other MLIL rebuild (copy_metadata_from does not copy them),
    and no MLIL code sets them on an expression.'''
    state = {key: value for key, value in vars(inst).items() if key not in OPERAND_FIELDS}
    state['options'] = vars(inst.options)
    return state


class TestRebuildEveryOp(unittest.TestCase):
    '''Every concrete op rebuilds to the same type and operation with the new operands, and keeps
    its metadata and every other attribute. rebuild() calls type(self)(operands), so every
    constructor must take exactly the operands - a subclass with any extra parameter fails here
    instead of silently losing that state.'''

    def test_every_op_constructor_takes_only_its_operands(self):
        for base, expected in [(MLILBinaryOp, BINARY_OP_PARAMETERS), (MLILUnaryOp, UNARY_OP_PARAMETERS)]:
            for cls in concrete_subclasses(base):
                with self.subTest(op = cls.__name__):
                    self.assertEqual(list(inspect.signature(cls.__init__).parameters), expected)

    def test_every_binary_op_rebuilds(self):
        classes = concrete_subclasses(MLILBinaryOp)
        self.assertEqual(len(classes), BINARY_OP_COUNT, [cls.__name__ for cls in classes])

        for cls in classes:
            with self.subTest(op = cls.__name__):
                original = with_metadata(cls(MLILConst(1), MLILConst(2)))
                new_lhs, new_rhs = MLILConst(3), MLILConst(4)
                rebuilt = original.rebuild(new_lhs, new_rhs)

                self.assertIsNot(rebuilt, original)
                self.assertIs(type(rebuilt), cls)
                self.assertIs(rebuilt.lhs, new_lhs)
                self.assertIs(rebuilt.rhs, new_rhs)
                self.assertEqual(non_operand_state(rebuilt), non_operand_state(original))

    def test_every_unary_op_rebuilds(self):
        classes = concrete_subclasses(MLILUnaryOp)
        self.assertEqual(len(classes), UNARY_OP_COUNT, [cls.__name__ for cls in classes])

        for cls in classes:
            with self.subTest(op = cls.__name__):
                original = with_metadata(cls(MLILConst(1)))
                new_operand = MLILConst(2)
                rebuilt = original.rebuild(new_operand)

                self.assertIsNot(rebuilt, original)
                self.assertIs(type(rebuilt), cls)
                self.assertIs(rebuilt.operand, new_operand)
                self.assertEqual(non_operand_state(rebuilt), non_operand_state(original))


class TestPassRebuildKeepsMetadata(unittest.TestCase):
    '''A pass that rewrites an operand keeps the rewritten expression's source metadata (six of
    the seven old tables dropped it).'''

    def test_constant_propagation_keeps_rebuilt_expression_metadata(self):
        # a = 5; b = a + arg1 -> b = 5 + arg1, and the rebuilt add keeps its address
        func = MediumLevelILFunction('rebuild_metadata_test', 0)
        a = MLILVariable('a')
        b = MLILVariable('b')
        a1 = MLILVariableSSA(a, 1)
        b1 = MLILVariableSSA(b, 1)
        add = with_metadata(MLILAdd(MLILVarSSA(a1), MLILVar(MLILVariable('arg1'))))

        block = MediumLevelILBasicBlock(0)
        block.instructions = [MLILSetVarSSA(a1, MLILConst(5)), MLILSetVarSSA(b1, add), MLILRet(MLILVarSSA(b1))]
        func.basic_blocks = [block]

        ConstantPropagationPass().run(func)

        rebuilt = block.instructions[1].value
        self.assertIsNot(rebuilt, add, 'the add must have been rebuilt with the constant')
        self.assertIsInstance(rebuilt.lhs, MLILConst)
        self.assertEqual(rebuilt.address, SOURCE_ADDRESS)
        self.assertEqual(rebuilt.inst_index, SOURCE_INST_INDEX)

    def test_nnf_keeps_rebuilt_logical_op_metadata(self):
        # y = !!arg1 && arg2 -> y = arg1 && arg2: same operation, new operand, same metadata
        func = MediumLevelILFunction('nnf_metadata_test', 0)
        y1 = MLILVariableSSA(MLILVariable('y'), 1)
        arg1 = MLILVar(MLILVariable('arg1'))
        logical_and = with_metadata(MLILLogicalAnd(MLILLogicalNot(MLILLogicalNot(arg1)), MLILVar(MLILVariable('arg2'))))

        block = MediumLevelILBasicBlock(0)
        block.instructions = [MLILSetVarSSA(y1, logical_and), MLILRet(MLILVarSSA(y1))]
        func.basic_blocks = [block]

        NNFPass().run(func)

        rebuilt = block.instructions[0].value
        self.assertIsInstance(rebuilt, MLILLogicalAnd)
        self.assertIs(rebuilt.lhs, arg1, 'the double negation must have been removed')
        self.assertEqual(rebuilt.address, SOURCE_ADDRESS)
        self.assertEqual(rebuilt.inst_index, SOURCE_INST_INDEX)


class TestSCCPNeverSubstitutesUnderAddressOf(unittest.TestCase):
    '''&x names x's storage, not its value: SCCP must leave &x alone even when it knows x's
    value. Before rebuild() existed this held only because SCCP's own table had no AddressOf
    entry; it is now an explicit leaf.'''

    def run_sccp(self, make_value):
        # x = 5; y = <make_value(x)>; return y - returns what y's value became
        func = MediumLevelILFunction('sccp_address_of_test', 0)
        x = MLILVariable('x')
        y = MLILVariable('y')
        func.locals['x'] = x
        func.locals['y'] = y
        x1 = MLILVariableSSA(x, 1)
        y1 = MLILVariableSSA(y, 1)

        block = MediumLevelILBasicBlock(0)
        block.instructions = [
            MLILSetVarSSA(x1, MLILConst(5)),
            MLILSetVarSSA(y1, make_value(x1)),
            MLILRet(MLILVarSSA(y1)),
        ]
        func.basic_blocks = [block]

        SCCP(func).run()

        return block.instructions[1].value

    def test_address_of_known_constant_is_kept(self):
        value = self.run_sccp(lambda x1: MLILAddressOf(MLILVarSSA(x1)))

        self.assertIsInstance(value, MLILAddressOf)
        self.assertIsInstance(value.operand, MLILVarSSA, 'SCCP must never rewrite &x into &5')

    def test_deref_operand_is_still_substituted(self):
        # control: a pointer's value is an ordinary operand, so SCCP does substitute under *
        value = self.run_sccp(lambda x1: MLILDeref(MLILVarSSA(x1)))

        self.assertIsInstance(value, MLILDeref)
        self.assertIsInstance(value.operand, MLILConst)


class TestCallRebuildKeepsClobberFlag(unittest.TestCase):
    '''rebuild() of every call kind keeps clobbers_registers (Syscall/CallScript used to reset it
    to the default True).'''

    def test_every_call_kind_keeps_clobbers_registers(self):
        calls = [
            MLILCall('f', [MLILConst(1)], clobbers_registers = False),
            MLILSyscall(1, 2, [MLILConst(1)], clobbers_registers = False),
            MLILCallScript('module', 'func', [MLILConst(1)], clobbers_registers = False),
        ]

        for call in calls:
            with self.subTest(call = type(call).__name__):
                rebuilt = call.rebuild([MLILConst(2)])

                self.assertIs(type(rebuilt), type(call))
                self.assertFalse(rebuilt.clobbers_registers)


if __name__ == '__main__':
    unittest.main()
