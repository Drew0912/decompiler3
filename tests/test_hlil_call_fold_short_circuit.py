#!/usr/bin/env python3
'''Unit tests for CallResultFolder short-circuit safety: the VM evaluates both operands of
MLILLogicalAnd/Or, while HLIL's && / || short-circuit, so a call result read under their rhs is
never folded - the call stays its own statement wherever its block sits, and a run of calls keeps
its order. A read on the lhs, and a fold into a test that HLIL structuring builds itself (a funnel
chain's head, a loop test), stays folded. Every CFG gets real edges, as the funnel check reads them.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import (
    MediumLevelILFunction, MLILCall, MLILIf, MLILGoto, MLILRet, MLILConst, MLILVar,
    MLILLogicalAnd, MLILLogicalOr, MLILAddressOf,
)
from ir.hlil.hlil import HLILIf, HLILWhile, sub_blocks
from ir.hlil.mlil_to_hlil import MLILToHLILConverter
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil


def make_func(name: str, block_count: int):
    '''Function with params arg1/arg2, registers reg0/reg1 and block_count empty blocks'''
    func = MediumLevelILFunction(name, 0)
    arg1 = func.get_or_create_parameter(1, 'arg1')
    arg2 = func.get_or_create_parameter(2, 'arg2')
    reg0 = func.get_or_create_register_var(0)
    reg1 = func.get_or_create_register_var(1)
    blocks = [func.create_block() for _ in range(block_count)]
    return func, blocks, arg1, arg2, reg0, reg1


def connect(func: MediumLevelILFunction):
    '''Add the edges each block's last instruction implies (fallthrough when it is not a branch)'''
    blocks = func.basic_blocks

    for idx, block in enumerate(blocks):
        last = block.instructions[-1]

        if isinstance(last, MLILIf):
            block.add_outgoing_edge(last.true_target)
            block.add_outgoing_edge(last.false_target)

        elif isinstance(last, MLILGoto):
            block.add_outgoing_edge(last.target)

        elif not isinstance(last, MLILRet) and idx + 1 < len(blocks):
            block.add_outgoing_edge(blocks[idx + 1])


def convert(func: MediumLevelILFunction):
    connect(func)
    return MLILToHLILConverter(func).convert()


def find_statement(block, predicate):
    '''(owning block, index) of the first statement matching predicate, in pre-order'''
    for idx, stmt in enumerate(block.statements):
        if predicate(stmt):
            return block, idx

        for sub_block in sub_blocks(stmt):
            found = find_statement(sub_block, predicate)
            if found is not None:
                return found

    return None


def if_with_condition(text: str):
    return lambda stmt: isinstance(stmt, HLILIf) and str(stmt.condition) == text


class TestGatedCallInConditionalBlock(unittest.TestCase):
    '''reg0 = f() only runs when arg1 holds, then feeds the rhs of a native &&. Inside that arm
    the call still runs every time, so it must stay a statement ahead of the test even though
    its block is not reached on every path from entry.'''

    def test_call_stays_a_statement_inside_the_arm(self):
        func, (guard, body, then_block, exit_block), arg1, arg2, reg0, _ = make_func('conditional_block', 4)
        guard.instructions = [MLILIf(MLILVar(arg1), body, exit_block)]
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILIf(MLILLogicalAnd(MLILVar(arg2), MLILVar(reg0)), then_block, exit_block),
        ]
        then_block.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        hlil_func = convert(func)
        found = find_statement(hlil_func.body, if_with_condition('arg2 && reg0'))

        self.assertIsNotNone(found, 'the native && must read the captured reg0, not a folded f()')
        block, idx = found
        self.assertGreater(idx, 0)
        self.assertEqual(str(block.statements[idx - 1]), 'reg0 = f()')


class TestGatedCallInLowerIndexBlock(unittest.TestCase):
    '''The call's block comes after its reader's block in block order and is only reached when
    arg2 is false; the refusal must not depend on either.'''

    def test_call_stays_a_statement(self):
        func, (entry, reader, then_block, call_block, exit_block), arg1, arg2, reg0, _ = make_func('lower_index', 5)
        entry.instructions = [MLILIf(MLILVar(arg2), call_block, exit_block)]
        reader.instructions = [MLILIf(MLILLogicalAnd(MLILVar(arg1), MLILVar(reg0)), then_block, exit_block)]
        then_block.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        call_block.instructions = [MLILCall('f', [], output = reg0), MLILGoto(reader)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        hlil_func = convert(func)
        found = find_statement(hlil_func.body, if_with_condition('arg1 && reg0'))

        self.assertIsNotNone(found, 'the native && must read the captured reg0, not a folded f()')
        block, idx = found
        self.assertEqual(str(block.statements[idx - 1]), 'reg0 = f()')


class TestUnconditionalCallGatedByNativeAnd(unittest.TestCase):
    '''reg0 = f() runs at function entry and is read under the rhs of `arg1 && reg0`'''

    def test_call_stays_its_own_statement(self):
        func, (body, then_block, exit_block), arg1, _, reg0, _ = make_func('unconditional_gated', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILIf(MLILLogicalAnd(MLILVar(arg1), MLILVar(reg0)), then_block, exit_block),
        ]
        then_block.instructions = [MLILRet(MLILConst(1))]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert(func).body.statements

        self.assertEqual(str(statements[0]), 'reg0 = f()')
        self.assertEqual(str(statements[1].condition), 'arg1 && reg0')


class TestGateReachesThroughNestedOperators(unittest.TestCase):
    '''reg0 sits on the lhs of an inner && that is itself the rhs of ||, so it is still gated'''

    def test_call_stays_its_own_statement(self):
        func, (body, then_block, exit_block), arg1, arg2, reg0, _ = make_func('nested_gate', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILIf(MLILLogicalOr(MLILVar(arg1), MLILLogicalAnd(MLILVar(reg0), MLILVar(arg2))),
                   then_block, exit_block),
        ]
        then_block.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = [str(s) for s in convert(func).body.statements]

        self.assertEqual(statements[0], 'reg0 = f()')


class TestNestedGatedFoldInsideAnotherCallsArgument(unittest.TestCase):
    '''inner()'s result is gated by outer()'s own `arg2 && ...` argument, and outer()'s by the if's
    `arg1 && ...` - both stay statements, in the order they ran.'''

    def test_both_calls_stay_statements_in_order(self):
        func, (body, then_block, exit_block), arg1, arg2, reg0, reg1 = make_func('nested_calls', 3)
        body.instructions = [
            MLILCall('inner', [], output = reg0),
            MLILCall('outer', [MLILLogicalAnd(MLILVar(arg2), MLILVar(reg0))], output = reg1),
            MLILIf(MLILLogicalAnd(MLILVar(arg1), MLILVar(reg1)), then_block, exit_block),
        ]
        then_block.instructions = [MLILRet(MLILConst(1))]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert(func).body.statements
        rendered = [str(s) for s in statements]

        self.assertEqual(rendered[:2], ['reg0 = inner()', 'reg1 = outer(arg2 && reg0)'])
        self.assertEqual(str(statements[2].condition), 'arg1 && reg1')


class TestCallOrderKeptWhenLaterCallIsRefused(unittest.TestCase):
    '''f() and g() both feed `reg0 || reg1`; g() is gated, so f() cannot fold past it either -
    folding only f() would run it after g()'''

    def test_both_calls_stay_statements_in_order(self):
        func, (body, then_block, exit_block), _, _, reg0, reg1 = make_func('call_order', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILCall('g', [], output = reg1),
            MLILIf(MLILLogicalOr(MLILVar(reg0), MLILVar(reg1)), then_block, exit_block),
        ]
        then_block.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = [str(s) for s in convert(func).body.statements]

        self.assertEqual(statements[:2], ['reg0 = f()', 'reg1 = g()'])


class TestRefusedCallKeepsItsOwnArgumentFold(unittest.TestCase):
    '''g() is gated and stays a statement, but f() feeds g()'s ungated argument and still folds'''

    def test_inner_call_folds_into_the_refused_call(self):
        func, (body, then_block, exit_block), arg1, _, reg0, reg1 = make_func('refused_outer', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILCall('g', [MLILVar(reg0)], output = reg1),
            MLILIf(MLILLogicalOr(MLILVar(arg1), MLILVar(reg1)), then_block, exit_block),
        ]
        then_block.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert(func).body.statements

        self.assertEqual(str(statements[0]), 'reg1 = g(f())')
        self.assertEqual(str(statements[1].condition), 'arg1 || reg1')


class TestLhsReadStaysFolded(unittest.TestCase):
    '''The lhs of && always runs, so a read there still folds'''

    def test_call_is_folded(self):
        func, (body, then_block, exit_block), arg1, _, reg0, _ = make_func('lhs_read', 3)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILIf(MLILLogicalAnd(MLILVar(reg0), MLILVar(arg1)), then_block, exit_block),
        ]
        then_block.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert(func).body.statements

        self.assertEqual(str(statements[0].condition), 'f() && arg1')


class TestFunnelChainHeadStaysFolded(unittest.TestCase):
    '''Two tests sharing a body collapse into one ||. The head's test is its lhs and always
    runs, so a call folded into it stays folded.'''

    def test_call_is_folded(self):
        func, (head, link, body, exit_block), arg1, _, reg0, _ = make_func('funnel_chain', 4)
        head.instructions = [MLILCall('f', [], output = reg0), MLILIf(MLILVar(reg0), body, link)]
        link.instructions = [MLILIf(MLILVar(arg1), body, exit_block)]
        body.instructions = [MLILCall('do_x', []), MLILGoto(exit_block)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert(func).body.statements

        self.assertEqual(str(statements[0].condition), 'f() || arg1')


class TestLoopTestStaysFolded(unittest.TestCase):
    '''A call in the loop header runs once per test, and so does the recovered while condition'''

    def test_call_is_folded_into_the_while_condition(self):
        func, (entry, header, body, exit_block), _, _, reg0, _ = make_func('loop_test', 4)
        entry.instructions = [MLILGoto(header)]
        header.instructions = [MLILCall('f', [], output = reg0), MLILIf(MLILVar(reg0), body, exit_block)]
        body.instructions = [MLILCall('do_x', []), MLILGoto(header)]
        exit_block.instructions = [MLILRet(MLILConst(0))]

        connect(func)
        hlil_func = convert_falcom_mlil_to_hlil(func)
        found = find_statement(hlil_func.body, lambda stmt: isinstance(stmt, HLILWhile))

        self.assertIsNotNone(found)
        block, idx = found
        self.assertEqual(str(block.statements[idx].condition), 'f()')


class TestAddressOfReadNotFolded(unittest.TestCase):
    '''&reg0 names reg0's storage; a call result has none, so `&f()` would be wrong'''

    def test_call_stays_a_statement(self):
        func, (body,), _, _, reg0, _ = make_func('address_of', 1)
        body.instructions = [
            MLILCall('f', [], output = reg0),
            MLILCall('takes_pointer', [MLILAddressOf(MLILVar(reg0))]),
            MLILRet(MLILConst(0)),
        ]

        statements = [str(s) for s in convert(func).body.statements]

        self.assertEqual(statements[:2], ['reg0 = f()', 'takes_pointer(&reg0)'])


if __name__ == '__main__':
    unittest.main()
