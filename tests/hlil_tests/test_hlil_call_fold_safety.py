#!/usr/bin/env python3
'''CallResultFolder never folds a call result into its reader when that loses the result or reorders
the call: a later read of the same register (in the same block, in a SetVar, or in another block)
keeps the call a statement; calls folded into one expression keep their execution order; an impure
read (a global) ahead of the folded read, or a read under a native &&, keeps the call where it is.
The safe folds stay folded: a reader in the next block, a chain of calls, a return.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILFunction, MLILCall, MLILIf, MLILGoto, MLILRet, MLILConst, MLILVar, MLILVariable, MLILSetVar,
    MLILEq, MLILGt, MLILAdd, MLILLogicalAnd, MLILLoadGlobal, MLILStoreDeref,
)
from ir.hlil.hlil_formatter import HLILFormatter
from ir.hlil.mlil_to_hlil import MLILToHLILConverter
from tests.shared.ir_utils import connect

GLOBAL_SLOT = 3


def make_func(name: str, block_count: int):
    '''Function with parameter arg1, registers reg0/reg1, locals x/y and block_count empty blocks'''
    func = MediumLevelILFunction(name, 0)
    arg1 = func.get_or_create_parameter(1, 'arg1')
    reg0 = func.get_or_create_register_var(0)
    reg1 = func.get_or_create_register_var(1)
    blocks = [func.create_block() for _ in range(block_count)]
    return func, blocks, arg1, reg0, reg1, MLILVariable('x'), MLILVariable('y')


def lines_of(func: MediumLevelILFunction) -> list:
    connect(func)
    hlil = MLILToHLILConverter(func).convert()
    return [line.strip() for line in HLILFormatter.format_function(hlil)]


class TestResultReadAgain(unittest.TestCase):
    '''reg0 = f() is read by x = reg0 and then again: folding it into the first read loses reg0 for the second'''

    def test_next_call_reads_it_again(self):
        func, (body,), _, reg0, _, x, _ = make_func('read_by_call', 1)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILSetVar(x, MLILVar(reg0)),
            MLILCall('g', [MLILVar(reg0)]),
            MLILRet(MLILConst(0)),
        ]

        lines = lines_of(func)

        self.assertIn('reg0 = f();', lines)
        self.assertIn('g(reg0);', lines)

    def test_next_assignment_reads_it_again(self):
        func, (body,), _, reg0, _, x, y = make_func('read_by_setvar', 1)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILSetVar(x, MLILVar(reg0)),
            MLILSetVar(y, MLILVar(reg0)),
            MLILRet(MLILVar(y)),
        ]

        lines = lines_of(func)

        self.assertIn('reg0 = f();', lines)
        self.assertIn('y = reg0;', lines)

    def test_store_through_a_pointer_reads_it_again(self):
        func, (body,), arg1, reg0, _, x, _ = make_func('read_by_store', 1)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILSetVar(x, MLILVar(reg0)),
            MLILStoreDeref(MLILVar(arg1), MLILVar(reg0)),
            MLILRet(MLILConst(0)),
        ]

        lines = lines_of(func)

        self.assertIn('reg0 = f();', lines)
        self.assertIn('*arg1 = reg0;', lines)

    def test_a_call_in_another_block_reads_it_again(self):
        func, (entry, use, done), arg1, reg0, _, x, _ = make_func('read_in_next_block', 3)
        entry.instructions = [
            MLILCall('f', [], output = reg0),
            MLILSetVar(x, MLILVar(reg0)),
            MLILIf(MLILVar(arg1), use, done),
        ]
        use.instructions = [MLILCall('g', [MLILVar(reg0)]), MLILGoto(done)]
        done.instructions = [MLILRet(MLILConst(0))]

        lines = lines_of(func)

        self.assertIn('reg0 = f();', lines)
        self.assertIn('g(reg0);', lines)

    def test_an_assignment_in_another_block_reads_it_again(self):
        func, (entry, use, done), arg1, reg0, _, x, y = make_func('setvar_in_next_block', 3)
        entry.instructions = [
            MLILCall('f', [], output = reg0),
            MLILSetVar(x, MLILVar(reg0)),
            MLILIf(MLILVar(arg1), use, done),
        ]
        use.instructions = [MLILSetVar(y, MLILVar(reg0)), MLILGoto(done)]
        done.instructions = [MLILRet(MLILConst(0))]

        lines = lines_of(func)

        self.assertIn('reg0 = f();', lines)
        self.assertIn('y = reg0;', lines)


class TestSafeFolds(unittest.TestCase):

    def test_reader_in_the_only_successor_block_gets_the_call(self):
        func, (entry, test, big, small), _, reg0, _, _, _ = make_func('next_block_reader', 4)
        entry.instructions = [MLILCall('f', [], output = reg0), MLILGoto(test)]
        test.instructions = [MLILIf(MLILGt(MLILVar(reg0), MLILConst(0)), big, small)]
        big.instructions = [MLILRet(MLILConst(1))]
        small.instructions = [MLILRet(MLILConst(0))]

        lines = lines_of(func)

        self.assertIn('if (f() > 0) {', lines)
        self.assertNotIn('reg0 = f();', lines)

    def test_returned_result_is_returned_by_the_call(self):
        func, (body,), _, reg0, _, _, _ = make_func('return_result', 1)
        body.instructions = [MLILCall('f', [], output = reg0), MLILRet(MLILVar(reg0))]

        self.assertIn('return f();', lines_of(func))

    def test_calls_in_operand_order_fold_into_one_test(self):
        func, (body, then, done), _, reg0, reg1, _, _ = make_func('operand_order', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILCall('g', [], output = reg1),
            MLILIf(MLILEq(MLILVar(reg0), MLILVar(reg1)), then, done),
        ]
        then.instructions = [MLILRet(MLILConst(1))]
        done.instructions = [MLILRet(MLILConst(0))]

        self.assertIn('if (f() == g()) {', lines_of(func))


class TestCallOrderIsKept(unittest.TestCase):

    def test_operands_in_reverse_call_order_keep_f_before_g(self):
        func, (body, then, done), _, reg0, reg1, _, _ = make_func('reverse_order', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILCall('g', [], output = reg1),
            MLILIf(MLILEq(MLILVar(reg1), MLILVar(reg0)), then, done),
        ]
        then.instructions = [MLILRet(MLILConst(1))]
        done.instructions = [MLILRet(MLILConst(0))]

        text = '\n'.join(lines_of(func))

        self.assertLess(text.index('f()'), text.index('g()'))


class TestImpureReadAheadOfTheFold(unittest.TestCase):
    '''f() may write the global, so it has to run before GLOBALS[3] is read, as the bytecode did'''

    def test_global_inside_an_earlier_operand(self):
        func, (body, then, done), _, reg0, _, _, _ = make_func('global_in_lhs', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILIf(MLILEq(MLILAdd(MLILLoadGlobal(GLOBAL_SLOT), MLILConst(1)), MLILVar(reg0)), then, done),
        ]
        then.instructions = [MLILRet(MLILConst(1))]
        done.instructions = [MLILRet(MLILConst(0))]

        self.assertIn('reg0 = f();', lines_of(func))

    def test_global_as_an_earlier_argument(self):
        func, (body,), _, reg0, _, _, _ = make_func('global_in_args', 1)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILCall('h', [MLILLoadGlobal(GLOBAL_SLOT), MLILVar(reg0)]),
            MLILRet(MLILConst(0)),
        ]

        self.assertIn('reg0 = f();', lines_of(func))


class TestReadUnderANativeAnd(unittest.TestCase):
    '''The VM evaluates both operands of && ; HLIL's && skips the rhs, so f() would only run sometimes'''

    def test_returned_and_keeps_the_call_a_statement(self):
        func, (body,), arg1, reg0, _, _, _ = make_func('return_and', 1)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILRet(MLILLogicalAnd(MLILVar(arg1), MLILVar(reg0))),
        ]

        lines = lines_of(func)

        self.assertIn('reg0 = f();', lines)
        self.assertIn('return arg1 && reg0;', lines)


if __name__ == '__main__':
    unittest.main()
