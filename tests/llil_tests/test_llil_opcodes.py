#!/usr/bin/env python3
'''What the lifter makes of an opcode: each operator its own node over the values pushed, translated to its own
MLIL operation; DEBUG_LOG a debug-log node that MLIL keeps as a call.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import (
    LowLevelILAdd, LowLevelILAnd, LowLevelILBitwiseNot, LowLevelILDiv, LowLevelILEq, LowLevelILGe, LowLevelILGt,
    LowLevelILLe, LowLevelILLogicalAnd, LowLevelILLogicalOr, LowLevelILLt, LowLevelILMod, LowLevelILMul, LowLevelILNe,
    LowLevelILNeg, LowLevelILOperation, LowLevelILOr, LowLevelILSub, LowLevelILTestZero,
)
from falcom.ed9.ir.llil.llil_ext import LowLevelILDebugLog, LowLevelILFalcomOperation
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.mlil.mlil import (
    MLILAdd, MLILAnd, MLILBitwiseNot, MLILCall, MLILDiv, MLILEq, MLILGe, MLILGt, MLILLe, MLILLogicalAnd,
    MLILLogicalOr, MLILLt, MLILMod, MLILMul, MLILNe, MLILNeg, MLILOr, MLILSub, MLILTestZero,
)
from tests.shared.llil_utils import instructions_of, lift_asm
from tests.shared.scp_asm import MODULE_NAME, REG_INDEX, Asm


FIRST_VALUE = 7
SECOND_VALUE = 8
LOG_ARGC = 2


class TestDebugLogIsLifted(unittest.TestCase):
    '''DEBUG_LOG prints its arguments; the decompiled script must still print them'''

    def make_function(self):
        asm = Asm()
        asm.push_str(MODULE_NAME); asm.push_int(FIRST_VALUE); asm.debug_log(LOG_ARGC); asm.ret()
        return lift_asm(asm)

    def test_lifts_to_a_debug_log_with_its_arguments_top_of_stack_first(self):
        _, llil_func = self.make_function()

        logs = instructions_of(llil_func, LowLevelILDebugLog)

        self.assertEqual(len(logs), 1)
        self.assertEqual([arg.slot_index for arg in logs[0].args], [1, 0])
        self.assertEqual(logs[0].operation, LowLevelILFalcomOperation.LLIL_DEBUG_LOG)

    def test_survives_as_a_debug_log_call_in_mlil(self):
        parser, llil_func = self.make_function()

        mlil_func = convert_falcom_llil_to_mlil(llil_func, parser, optimize = False)

        calls = [inst for block in mlil_func.basic_blocks for inst in block.instructions
                 if isinstance(inst, MLILCall) and inst.target == DEBUG_LOG_CALL_TARGET]
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0].args), LOG_ARGC)



BINARY_OPERATORS = (
    ('add', LowLevelILAdd, MLILAdd, LowLevelILOperation.LLIL_ADD),
    ('sub', LowLevelILSub, MLILSub, LowLevelILOperation.LLIL_SUB),
    ('mul', LowLevelILMul, MLILMul, LowLevelILOperation.LLIL_MUL),
    ('div', LowLevelILDiv, MLILDiv, LowLevelILOperation.LLIL_DIV),
    ('mod', LowLevelILMod, MLILMod, LowLevelILOperation.LLIL_MOD),
    ('eq', LowLevelILEq, MLILEq, LowLevelILOperation.LLIL_EQ),
    ('ne', LowLevelILNe, MLILNe, LowLevelILOperation.LLIL_NE),
    ('gt', LowLevelILGt, MLILGt, LowLevelILOperation.LLIL_GT),
    ('ge', LowLevelILGe, MLILGe, LowLevelILOperation.LLIL_GE),
    ('lt', LowLevelILLt, MLILLt, LowLevelILOperation.LLIL_LT),
    ('le', LowLevelILLe, MLILLe, LowLevelILOperation.LLIL_LE),
    ('bitwise_and', LowLevelILAnd, MLILAnd, LowLevelILOperation.LLIL_AND),
    ('bitwise_or', LowLevelILOr, MLILOr, LowLevelILOperation.LLIL_OR),
    ('logical_and', LowLevelILLogicalAnd, MLILLogicalAnd, LowLevelILOperation.LLIL_LOGICAL_AND),
    ('logical_or', LowLevelILLogicalOr, MLILLogicalOr, LowLevelILOperation.LLIL_LOGICAL_OR),
)
UNARY_OPERATORS = (
    ('neg', LowLevelILNeg, MLILNeg, LowLevelILOperation.LLIL_NEG),
    ('not_', LowLevelILBitwiseNot, MLILBitwiseNot, LowLevelILOperation.LLIL_BITWISE_NOT),
    ('ez', LowLevelILTestZero, MLILTestZero, LowLevelILOperation.LLIL_TEST_ZERO),
)


def stored_values(func) -> list:
    '''The value of every instruction that has one (StackStore / SetVar ...), in order'''
    return [inst.value for block in func.basic_blocks for inst in block.instructions if hasattr(inst, 'value')]


class TestOperatorsKeepTheirOperands(unittest.TestCase):
    '''Each arithmetic, comparison, bitwise and logical opcode lifts to its own node over the values pushed (first
    push on the left) and translates to its own MLIL operation over the same variables'''

    def lift_and_translate(self, mnemonic: str, operand_count: int):
        asm = Asm()
        asm.push_int(FIRST_VALUE)
        if operand_count == 2:
            asm.push_int(SECOND_VALUE)

        getattr(asm, mnemonic)()
        asm.set_reg(REG_INDEX); asm.ret()
        parser, llil_func = lift_asm(asm)
        return llil_func, convert_falcom_llil_to_mlil(llil_func, parser, optimize = False)

    def test_binary_operators(self):
        for mnemonic, llil_class, mlil_class, operation in BINARY_OPERATORS:
            with self.subTest(mnemonic):
                llil_func, mlil_func = self.lift_and_translate(mnemonic, 2)

                node, = [value for value in stored_values(llil_func) if isinstance(value, llil_class)]
                self.assertEqual(node.operation, operation)
                self.assertEqual((node.lhs.slot_index, node.rhs.slot_index), (0, 1))

                mlil_node, = [value for value in stored_values(mlil_func) if isinstance(value, mlil_class)]
                self.assertEqual((mlil_node.lhs.var.name, mlil_node.rhs.var.name), ('var_s0', 'var_s1'))

    def test_unary_operators(self):
        for mnemonic, llil_class, mlil_class, operation in UNARY_OPERATORS:
            with self.subTest(mnemonic):
                llil_func, mlil_func = self.lift_and_translate(mnemonic, 1)

                node, = [value for value in stored_values(llil_func) if isinstance(value, llil_class)]
                self.assertEqual(node.operation, operation)
                self.assertEqual(node.operand.slot_index, 0)

                mlil_node, = [value for value in stored_values(mlil_func) if isinstance(value, mlil_class)]
                self.assertEqual(mlil_node.operand.var.name, 'var_s0')

if __name__ == '__main__':
    unittest.main()
