#!/usr/bin/env python3
"""Unit tests for *(&x), the memory form of an address-taken local, in HLIL: the call result folder reads through it
and both printers fold it back to plain x"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MLILDeref, MLILSetVar, MLILVar, MLILVariable, MLILCall,
    MLILAddressOf, MLILAdd, MLILRet,
)
from ir.hlil.mlil_to_hlil import MLILToHLILConverter
from ir.hlil.hlil import (
    HLILDeref, HLILVar, HLILVariable, HLILConst, HLILAssign, HLILAddressOf,
    HLILBinaryOp, BinaryOp, HLILCall, HLILTypeKind, iter_tree,
)
from ir.hlil.hlil_formatter import HLILFormatter
from codegen.typescript import TypeScriptGenerator


class TestCallResultFolderRespectsAddressTakenDeref(unittest.TestCase):
    """reg0 = f(&x); y = x + reg0 - CallResultFolder must not fold this into
    y = x + f(&x), which would read x through the pointer before f's call actually writes
    it. _read_unsafe_to_fold (ir/hlil/call_result_folder.py) already defends a bare MLILDeref;
    the stack translator's memory form makes every address-taken read go through exactly that shape."""

    def test_fold_is_blocked_by_the_intervening_deref_read(self):
        func = MediumLevelILFunction('call_result_fold_test', 0)
        block = MediumLevelILBasicBlock(0)
        x = MLILVariable('x')
        reg0 = MLILVariable('reg0')
        y = MLILVariable('y')
        func.locals['x'] = x
        func.locals['reg0'] = reg0
        func.locals['y'] = y

        block.instructions = [
            MLILCall('f', [MLILAddressOf(MLILVar(x))], reg0),
            MLILSetVar(y, MLILAdd(MLILDeref(MLILAddressOf(MLILVar(x))), MLILVar(reg0))),
            MLILRet(MLILVar(y)),
        ]
        func.basic_blocks = [block]

        hlil_func = MLILToHLILConverter(func).convert()

        # f() must remain reachable as a statement in its own right somewhere in the
        # function - never re-inlined so that only y's assignment calls it
        f_calls = [node for node in iter_tree(hlil_func.body) if isinstance(node, HLILCall) and node.func_name == 'f']
        self.assertEqual(len(f_calls), 1)

        # y's own assignment source must NOT itself contain the call - it must read the
        # captured reg0 instead
        y_assigns = [s for s in hlil_func.body.statements
                     if isinstance(s, HLILAssign) and isinstance(s.dest, HLILVar) and s.dest.var.name == 'y']
        self.assertEqual(len(y_assigns), 1)

        self.assertFalse(any(isinstance(node, HLILCall) for node in iter_tree(y_assigns[0].src)),
                         f'f() was re-inlined into y = ...: {y_assigns[0].src}')


class TestAddressTakenCodegenBooleanCoercion(unittest.TestCase):
    """x = (a == b), for a numeric address-taken local x, must print x = int(a == b) - not
    a bare boolean - through the *(&x) fold-back path specifically, reusing the ordinary
    assignment branch's coercion rather than a second, unreimplemented copy."""

    def test_boolean_assigned_to_numeric_address_taken_local_gets_int_wrapped(self):
        x = HLILVariable('x', HLILTypeKind.INT)
        a = HLILVariable('a')
        b = HLILVariable('b')
        bool_expr = HLILBinaryOp(BinaryOp.EQ, HLILVar(a), HLILVar(b))
        assign = HLILAssign(HLILDeref(HLILAddressOf(HLILVar(x))), bool_expr)

        lines = TypeScriptGenerator._format_statement(assign)
        self.assertTrue(any('x = int(' in line for line in lines), f'{lines}')


class TestAddressTakenPrinting(unittest.TestCase):
    """*(&x) and *(&x) = v must print as plain x and x = v - never deref(addr_of(x)) /
    deref_set(addr_of(x), v) - in both the TypeScript codegen and the debug HLIL formatter."""

    def test_typescript_read_and_write_fold_back_to_plain_variable(self):
        x = HLILVariable('x', HLILTypeKind.INT)
        lowered_read = HLILDeref(HLILAddressOf(HLILVar(x)))

        self.assertEqual(TypeScriptGenerator._format_expr(lowered_read), 'x')

        assign_lines = TypeScriptGenerator._format_statement(HLILAssign(lowered_read, HLILConst(5)))
        self.assertTrue(any('x = 5' in line for line in assign_lines))
        self.assertFalse(any('deref' in line for line in assign_lines))

    def test_hlil_formatter_read_folds_back_to_plain_variable(self):
        x = HLILVariable('x')
        lowered_read = HLILDeref(HLILAddressOf(HLILVar(x)))

        self.assertEqual(HLILFormatter._format_expr(lowered_read), 'x')


if __name__ == '__main__':
    unittest.main()
