#!/usr/bin/env python3
'''What the lifter makes of an opcode: each operator its own node over the values pushed, translated to its own
MLIL operation; DEBUG_LOG a debug-log node that MLIL keeps as a call; PUSH_RAW a RawInt constant through to HLIL.'''

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
from codegen import generate_typescript
from falcom.ed9.disasm.formatter import Formatter
from falcom.ed9.disasm.stack_effects import LOCAL_SETUP_SLOTS
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_ext import LowLevelILDebugLog, LowLevelILFalcomOperation
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET, RESULT_REG_INDEX
from falcom.ed9.parser.types_scp import RawInt, ScpValue
from ir.hlil.hlil import HLILCall, HLILConst, HLILVar, iter_tree
from ir.llil import WORD_SIZE
from ir.hlil.hlil_formatter import HLILFormatter
from ir.mlil.mlil_formatter import MLILFormatter
from ir.mlil.mlil import (
    MLILAdd, MLILAnd, MLILBitwiseNot, MLILCall, MLILDiv, MLILEq, MLILGe, MLILGt, MLILLe, MLILLogicalAnd,
    MLILLogicalOr, MLILLt, MLILMod, MLILMul, MLILNe, MLILNeg, MLILOr, MLILSub, MLILTestZero,
)
from tests.shared.llil_utils import instructions_of, lift_asm
from tests.shared.scp_asm import (
    CALLEE_ID, CALLEE_NAME, CALLER_ID, MODULE_NAME, REG_INDEX, Asm, Program, main_function, returning_callee,
)


FIRST_VALUE = 7
SECOND_VALUE = 8
LOG_ARGC = 2
RAW_VALUE = 5
MERGED_VALUE = 0
# The local in slot 0, read from above a call's setup with nothing else pushed
LOCAL_UNDER_CALL_SETUP = -(LOCAL_SETUP_SLOTS + 1) * WORD_SIZE


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


class TestRawPushKeepsItsType(unittest.TestCase):
    '''Past LLIL's is_raw only a constant's type tells Raw (PUSH_RAW) from Integer, and the lifter made it an int:
    HLIL couldn't keep `.ts` from leaving out a Raw argument equal to an Integer default'''

    def test_reaches_hlil_as_a_raw_int_printed_as_a_number(self):
        asm = Asm()
        asm.push_raw(RAW_VALUE); asm.set_reg(RESULT_REG_INDEX); asm.ret()
        parser, llil_func = lift_asm(asm)
        mlil_func = convert_falcom_llil_to_mlil(llil_func, parser)
        hlil_func = convert_falcom_mlil_to_hlil(mlil_func)

        [value] = [node.value for node in iter_tree(hlil_func.body) if isinstance(node, HLILConst)]
        self.assertIs(type(value), RawInt)
        self.assertEqual(value, RAW_VALUE)
        for output, text in (('.mlil.asm', '\n'.join(MLILFormatter.format_function(mlil_func))),
                             ('.hlil.ts', '\n'.join(HLILFormatter.format_function(hlil_func))),
                             ('.ts', generate_typescript(hlil_func))):
            with self.subTest(output):
                self.assertIn(f'return {RAW_VALUE}', text)
                self.assertNotIn('RawInt', text)

    def hlil_call(self, asm: Asm, callee_argc: int) -> HLILCall:
        '''The one call in asm's function, lifted to HLIL beside a callee taking callee_argc arguments'''
        parser, llil_func = lift_asm(asm, others = (returning_callee(callee_argc),))
        hlil_func = convert_falcom_mlil_to_hlil(convert_falcom_llil_to_mlil(llil_func, parser))
        [call] = [node for node in iter_tree(hlil_func.body) if isinstance(node, HLILCall)]
        return call

    def test_call_argument_stays_raw(self):
        '''Pushed as the argument, or stored in a local first (SCCP substitutes the constant)'''
        direct = Asm()
        direct.push_raw(CALLER_ID); direct.push_raw('back'); direct.push_raw(RAW_VALUE); direct.push_int(FIRST_VALUE)
        direct.call(CALLEE_ID); direct.label('back'); direct.ret()

        local = Asm()
        local.push_raw(RAW_VALUE)
        local.push_raw(CALLER_ID); local.push_raw('back'); local.load_stack(LOCAL_UNDER_CALL_SETUP)
        local.call(CALLEE_ID); local.label('back'); local.pop(WORD_SIZE); local.ret()

        for case, asm, expected in (('direct', direct, {RAW_VALUE: RawInt, FIRST_VALUE: int}),
                                    ('through a local', local, {RAW_VALUE: RawInt})):
            with self.subTest(case):
                call = self.hlil_call(asm, len(expected))

                self.assertEqual({arg.value: type(arg.value) for arg in call.args}, expected)

    def test_raw_and_integer_constants_do_not_merge(self):
        '''A Raw 0 and an Integer 0 are different words: where they meet the variable stays (two Raw 0s fold)'''
        for case, else_push, folds in (('Raw and Integer', 'push_int', False), ('both Raw', 'push_raw', True)):
            with self.subTest(case):
                asm = Asm()
                asm.push_int(FIRST_VALUE)
                asm.get_reg(REG_INDEX); asm.jz('else')
                asm.push_raw(MERGED_VALUE); asm.pop_to(-WORD_SIZE); asm.jmp('join')
                asm.label('else'); getattr(asm, else_push)(MERGED_VALUE); asm.pop_to(-WORD_SIZE)
                asm.label('join')
                asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(LOCAL_UNDER_CALL_SETUP)
                asm.call(CALLEE_ID); asm.label('back'); asm.pop(WORD_SIZE); asm.ret()

                [arg] = self.hlil_call(asm, 1).args

                if folds:
                    self.assertIs(type(arg.value), RawInt)

                else:
                    self.assertIsInstance(arg, HLILVar)

    def test_raw_parameter_default_prints_as_a_number(self):
        '''It printed `= RawInt(0x00000005)` in .ts; the .py keeps that spelling, the one the writer takes'''
        main = Asm()
        main.ret()
        parser, functions = Program(main_function(main), returning_callee(1)).disassemble()
        [callee] = [func for func in functions if func.name == CALLEE_NAME]
        callee.params[0].default_value = ScpValue(RawInt(RAW_VALUE))

        llil_func = ED9VMLifter(parser = parser).lift_function(callee)
        hlil_func = convert_falcom_mlil_to_hlil(convert_falcom_llil_to_mlil(llil_func, parser), callee)

        self.assertIn(f'(arg1: number = {RAW_VALUE})', generate_typescript(hlil_func))
        self.assertIn(f'= {RawInt(RAW_VALUE)!r}', Formatter.format_param(0, callee.params[0]))

if __name__ == '__main__':
    unittest.main()
