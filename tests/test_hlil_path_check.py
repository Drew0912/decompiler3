#!/usr/bin/env python3
'''Unit tests for tools/hlil_path_check.py: correct HLIL passes, and each way of losing or
inventing a path, deleting an effect or changing what a copy does is reported.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from hlil_cfg_utils import EARLY_EXIT, SHARED_LOOP, build_function, to_hlil, structure
from ir.mlil.mlil import (MediumLevelILFunction, MLILIf, MLILGoto, MLILRet, MLILConst, MLILVar, MLILCall, MLILSetVar,
                          MLILEq, MLILNe)
from ir.hlil.hlil import (HighLevelILFunction, HLILBlock, HLILIf, HLILWhile, HLILSwitch, HLILBreak, HLILContinue,
                          HLILReturn, HLILExprStmt, HLILCall, HLILConst, HLILVar, HLILVariable, HLILBinaryOp, BinaryOp,
                          iter_tree)
from hlil_path_check import check_function, FALLOFF


def connect(func: MediumLevelILFunction) -> MediumLevelILFunction:
    for block in func.basic_blocks:
        last = block.instructions[-1]
        if isinstance(last, MLILIf):
            block.add_outgoing_edge(last.true_target)
            block.add_outgoing_edge(last.false_target)

        elif isinstance(last, MLILGoto):
            block.add_outgoing_edge(last.target)

    func.renumber_instructions()
    return func


def calls_then_test(first: str, second: str) -> MediumLevelILFunction:
    '''if (first()) body(); else if (second()) body(); - both results tested as they come back'''
    func = MediumLevelILFunction('f', 0)
    reg0 = func.get_or_create_local('reg0')
    test1, test2, body, other = (func.create_block(label = label) for label in ('T1', 'T2', 'BODY', 'OTHER'))
    test1.instructions = [MLILCall(first, [], output = reg0), MLILIf(MLILVar(reg0), body, test2)]
    test2.instructions = [MLILCall(second, [], output = reg0), MLILIf(MLILVar(reg0), body, other)]
    body.instructions = [MLILCall('body', []), MLILRet(MLILConst(1))]
    other.instructions = [MLILRet(MLILConst(0))]
    return connect(func)


def returns_parameter() -> MediumLevelILFunction:
    func = MediumLevelILFunction('f', 0)
    p = func.get_or_create_parameter(1, 'p')
    func.get_or_create_parameter(2, 'q')
    block = func.create_block(label = 'B')
    block.instructions = [MLILCall('observable', []), MLILRet(MLILVar(p))]
    return connect(func)


def returns_call_result() -> MediumLevelILFunction:
    '''reg0 = value(); return reg0 - the call folds into the return'''
    func = MediumLevelILFunction('f', 0)
    reg0 = func.get_or_create_local('reg0')
    block = func.create_block(label = 'B')
    block.instructions = [MLILCall('value', [], output = reg0), MLILRet(MLILVar(reg0))]
    return connect(func)


def temporary_condition() -> MediumLevelILFunction:
    '''tmp = p == 0; if (tmp != 0) ... - ControlFlowOptimizationPass folds tmp into the if'''
    func = MediumLevelILFunction('f', 0)
    p = func.get_or_create_parameter(1, 'p')
    tmp = func.get_or_create_local('tmp')
    test, yes, no = (func.create_block(label = label) for label in ('T', 'Y', 'N'))
    test.instructions = [MLILSetVar(tmp, MLILEq(MLILVar(p), MLILConst(0))),
                         MLILIf(MLILNe(MLILVar(tmp), MLILConst(0)), yes, no)]
    yes.instructions = [MLILCall('yes', []), MLILRet(MLILConst(1))]
    no.instructions = [MLILCall('no', []), MLILRet(MLILConst(0))]
    return connect(func)


def equality_chain() -> MediumLevelILFunction:
    '''if (x == 1) one(); else if (x == 2) two(); else if (x == 3) three(); else other(); done()'''
    func = MediumLevelILFunction('f', 0)
    x = func.get_or_create_parameter(1, 'x')
    labels = ('T1', 'T2', 'T3', 'ONE', 'TWO', 'THREE', 'OTHER', 'DONE')
    t1, t2, t3, one, two, three, other, done = (func.create_block(label = label) for label in labels)
    for test, value, case, following in ((t1, 1, one, t2), (t2, 2, two, t3), (t3, 3, three, other)):
        test.instructions = [MLILIf(MLILEq(MLILVar(x), MLILConst(value)), case, following)]

    for case, name in ((one, 'one'), (two, 'two'), (three, 'three'), (other, 'other')):
        case.instructions = [MLILCall(name, []), MLILGoto(done)]

    done.instructions = [MLILCall('done', []), MLILRet(MLILConst(0))]
    return connect(func)


def find(hlil, kind):
    return [node for node in iter_tree(hlil.body) if isinstance(node, kind)]


def either_call_hlil(func: MediumLevelILFunction, op: BinaryOp) -> HighLevelILFunction:
    '''if (first() != 0 <op> second() != 0) { body(); return 1; } return 0; - calls_then_test's HLIL
    written by hand, with each call's provenance'''
    index = {inst.target: inst.inst_index for block in func.basic_blocks for inst in block.instructions
             if isinstance(inst, MLILCall)}

    def call(name: str) -> HLILCall:
        node = HLILCall(name, [])
        node.mlil_index = index[name]
        return node

    body = HLILExprStmt(call('body'))
    body.mlil_index = index['body']
    condition = HLILBinaryOp(op, HLILBinaryOp(BinaryOp.NE, call('first'), HLILConst(0)),
                             HLILBinaryOp(BinaryOp.NE, call('second'), HLILConst(0)))
    hlil = HighLevelILFunction('f')
    hlil.body = HLILBlock([HLILIf(condition, HLILBlock([body, HLILReturn(HLILConst(1))])), HLILReturn(HLILConst(0))])
    return hlil


class TestCorrectOutputPasses(unittest.TestCase):

    def assert_clean(self, func, hlil = None):
        result = check_function(func, hlil if hlil is not None else to_hlil(func))
        self.assertTrue(result.ok, (result.missing, result.extra, result.uncovered))
        self.assertEqual(result.unstructured, 0)

    def test_converter_output(self):
        self.assert_clean(build_function('f', EARLY_EXIT))

    def test_calls_folded_into_conditions(self):
        self.assert_clean(calls_then_test('first', 'second'))

    def test_constant_comparison_decided_alike_on_both_levels(self):
        blocks = {'C': ([], ('if', ('==', 1, 1), 'L', 'D')), 'L': (['live'], ('ret', 1)), 'D': (['dead'], ('ret', 0))}
        self.assert_clean(build_function('f', blocks))

    def test_temporary_an_hlil_pass_folds_away(self):
        self.assert_clean(temporary_condition())

    def test_call_folded_into_a_return(self):
        self.assert_clean(returns_call_result())

    def test_switch_from_an_equality_chain(self):
        func = equality_chain()
        hlil = to_hlil(func)
        self.assertTrue(find(hlil, HLILSwitch))
        self.assert_clean(func, hlil)

    def test_repeated_region(self):
        func, hlil = structure(SHARED_LOOP)
        self.assert_clean(func, hlil)


class TestLossesAreReported(unittest.TestCase):

    def test_deleted_call(self):
        func = build_function('f', EARLY_EXIT)
        hlil = to_hlil(func)
        for block in find(hlil, HLILBlock):
            block.statements = [s for s in block.statements
                                if not (isinstance(s, HLILExprStmt) and s.expr.func_name == 'rest')]

        self.assertTrue(check_function(func, hlil).uncovered)

    def test_call_replaced_but_provenance_kept(self):
        func = returns_parameter()
        hlil = to_hlil(func)
        stmt = find(hlil, HLILExprStmt)[0]
        stmt.expr = HLILConst(0)
        stmt.expr.mlil_index = stmt.mlil_index
        self.assertTrue(check_function(func, hlil).uncovered)

    def test_call_target_changed_but_provenance_kept(self):
        func = returns_parameter()
        hlil = to_hlil(func)
        find(hlil, HLILCall)[0].func_name = 'other'
        self.assertTrue(check_function(func, hlil).uncovered)

    def test_returned_variable_changed(self):
        func = returns_parameter()
        hlil = to_hlil(func)
        find(hlil, HLILReturn)[0].value = HLILVar(HLILVariable('q'))
        self.assertFalse(check_function(func, hlil).ok)

    def test_short_circuit_made_eager(self):
        # second() runs only when first() returned 0; evaluating both regardless invents a path
        func = calls_then_test('first', 'second')
        self.assertTrue(check_function(func, either_call_hlil(func, BinaryOp.OR)).ok)
        self.assertFalse(check_function(func, either_call_hlil(func, BinaryOp.BIT_OR)).ok)

    def test_one_wrong_copy_of_a_repeated_region(self):
        func, hlil = structure(SHARED_LOOP)
        loops = find(hlil, HLILWhile)
        self.assertEqual(len(loops), 2)

        # In the second copy only, the loop no longer repeats
        for stmt in iter_tree(loops[1].body):
            if isinstance(stmt, HLILBlock):
                stmt.statements = [HLILBreak() if isinstance(s, HLILContinue) else s for s in stmt.statements]

        self.assertFalse(check_function(func, hlil).ok)

    def test_falling_off_the_end(self):
        func = build_function('f', EARLY_EXIT)
        hlil = to_hlil(func)
        hlil.body.statements = [s for s in hlil.body.statements if not isinstance(s, HLILReturn)]
        result = check_function(func, hlil)
        self.assertTrue(any(target == FALLOFF for _, target in result.extra))


if __name__ == '__main__':
    unittest.main()
