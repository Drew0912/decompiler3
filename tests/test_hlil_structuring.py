#!/usr/bin/env python3
'''MLIL->HLIL structuring never silently loses or invents a path.

Each shape comes from a real loss in the sora2_1.0 corpus or is a constructed case of the same
kind, and every test runs the result against its MLIL for every parameter assignment
(hlil_cfg_utils.classify):
- merge points that are not merges: an early-exit arm (ai_chr0123_e00 CheckAlgoUse), a merge
  past the enclosing merge inside a loop (mon5027_c11 AniFieldSwarmAttack), a case falling
  into the next case's code (mp3000 TK_KUNO);
- loops: an exit through goto-only blocks (CheckAlgoUse's infinite loops), the enclosing stop
  inside that chain, a goto-only header, a loop entered again after it was emitted;
- a jump HLIL cannot express becomes an HLILUnstructured node, never a fall-through: the node's
  reachability, its handling in the passes, its rendering and the validator's report.
'''

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from hlil_cfg_utils import (EARLY_EXIT, SHARED_LOOP, SHARED_LOOP_COPY_STATEMENTS, build_function, to_hlil,
                            structure, classify, hlil_run, parameters, unstructured_nodes, calls_emitted)
from ir.hlil.hlil import (HighLevelILFunction, HLILBlock, HLILIf, HLILWhile, HLILDoWhile, HLILSwitch, HLILSwitchCase,
                          HLILBreak, HLILContinue, HLILReturn, HLILUnstructured, HLILAssign, HLILExprStmt, HLILCall,
                          HLILConst, HLILVar, HLILVariable, HLILBinaryOp, HLILUnaryOp, BinaryOp, UnaryOp,
                          constant_truth, reachable_statements, iter_tree)
from ir.hlil.hlil_formatter import HLILFormatter
from ir.hlil.structural_analysis import StructuralAnalyzer
from ir.hlil.passes.pass_control_flow_optimization import ControlFlowOptimizationPass
from ir.hlil.passes.pass_dead_code_elimination import DeadCodeEliminationPass
from ir.hlil.passes.pass_loop_recovery import LoopRecoveryPass
from codegen.typescript import generate_typescript
from ir_semantic_validator import compare_mlil_hlil

TARGET = 'loc_1'
REASON = 'region not repeatable'

# In a loop: one path breaks, the other rejoins MOVE, the enclosing if's merge
MERGE_IN_LOOP = {
    'E':     (['start'], ('goto', 'H')),
    'H':     ([], ('if', 'more', 'BODY', 'DONE')),
    'BODY':  (['info'], ('if', 'gone', 'MOVE', 'CHECK')),
    'CHECK': (['distance'], ('if', 'near', 'STOP', 'CLAMP')),
    'CLAMP': (['clamp'], ('goto', 'MOVE')),
    'STOP':  (['stop'], ('goto', 'DONE')),
    'MOVE':  (['move'], ('if', 'again', 'H', 'DONE')),
    'DONE':  (['done'], ('ret', 0)),
}

# Case 1 falls into case 2's code: the nearest shared block is not a merge
CASE_FALLTHROUGH = {
    'T1':  ([], ('if', 'k1', 'C1', 'T2')),
    'T2':  ([], ('if', 'k2', 'C2', 'T3')),
    'T3':  ([], ('if', 'k3', 'C3', 'END')),
    'C1':  (['begin1'], ('goto', 'C2')),
    'C2':  (['begin2', 'say2'], ('goto', 'END')),
    'C3':  (['say3'], ('goto', 'END')),
    'END': (['end'], ('ret', 0)),
}

# The loop's exit X only jumps on, through Y, to M - the enclosing if's merge
PASSTHROUGH_EXIT = {
    'S':     ([], ('if', 'a', 'CASE', 'OTHER')),
    'CASE':  (['init'], ('goto', 'H')),
    'H':     (['remain'], ('if', 'more', 'BODY', 'X')),
    'BODY':  (['info'], ('if', 'hit', 'R1', 'NEXT')),
    'R1':    ([], ('ret', 1)),
    'NEXT':  (['next'], ('goto', 'H')),
    'X':     ([], ('goto', 'Y')),
    'Y':     ([], ('goto', 'M')),
    'OTHER': (['other'], ('goto', 'M')),
    'M':     (['tail'], ('ret', 0)),
}

# The exit chain E -> S -> K passes through S, the enclosing if's merge
STOP_IN_EXIT_CHAIN = {
    'C': ([], ('if', 'p', 'H', 'S')),
    'H': (['header'], ('goto', 'B')),
    'B': ([], ('if', 'q', 'E', 'H')),
    'E': ([], ('goto', 'S')),
    'S': ([], ('goto', 'K')),
    'K': (['tail'], ('goto', 'R')),
    'R': ([], ('ret', 0)),
}

# A loop whose header only jumps into the body
GOTO_HEADER = {
    'E':    (['start'], ('goto', 'H')),
    'H':    ([], ('goto', 'BODY')),
    'BODY': (['work'], ('if', 'again', 'H', 'X')),
    'X':    (['end'], ('ret', 0)),
}

# The loop at L is emitted in one arm and entered again from the other
LOOP_REENTERED = {
    'C':  ([], ('if', 'p', 'L', 'A')),
    'A':  (['a'], ('if', 'q', 'L', 'R0')),
    'R0': (['r'], ('goto', 'X')),
    'L':  (['loop'], ('if', 'more', 'L', 'X')),
    'X':  (['end'], ('ret', 0)),
}

# A region repeated inside another repeated region (a random CFG): 9 statements re-emitted in all
NESTED_REPEATS = {
    'B0': (['A0'], ('if', 'p0', 'B3', 'B6')),
    'B1': (['A1'], ('if', 'p1', 'B7', 'B5')),
    'B2': (['A2'], ('ret', 2)),
    'B3': (['A3'], ('if', 'p3', 'B5', 'B1')),
    'B4': (['A4'], ('if', 'p4', 'B3', 'B8')),
    'B5': (['A5'], ('goto', 'B7')),
    'B6': (['A6'], ('if', 'p6', 'B2', 'B4')),
    'B7': (['A7'], ('ret', 7)),
    'B8': (['A8'], ('if', 'p8', 'B6', 'B2')),
}
NESTED_REPEATS_CHARGE = 9

# A constant first test funnels into S with a live second test: S's arm can run
FUNNEL_CONSTANT_FIRST = {
    'C':  ([], ('if', 0, 'S', 'F')),
    'F':  ([], ('if', 'p', 'S', 'R')),
    'S':  ([], ('if', 'r', 'L', 'D')),
    'L':  (['l'], ('if', 'q', 'L2', 'E')),
    'L2': (['l2'], ('goto', 'L')),
    'D':  (['d'], ('goto', 'L2')),
    'E':  ([], ('ret', 0)),
    'R':  ([], ('ret', 1)),
}

# 1 == 1 always takes the first arm: nothing in S's arm can run
CONSTANT_COMPARE = {
    'C':  ([], ('if', ('==', 1, 1), 'R', 'S')),
    'R':  ([], ('ret', 9)),
    'S':  ([], ('if', 'r', 'L', 'D')),
    'L':  (['l'], ('if', 'q', 'L2', 'E')),
    'L2': (['tail'], ('goto', 'L')),
    'E':  ([], ('ret', 0)),
    'D':  (['dead'], ('goto', 'L2')),
}


def var(name: str) -> HLILVar:
    return HLILVar(HLILVariable(name))


def node() -> HLILUnstructured:
    return HLILUnstructured(TARGET, REASON)


def function(*statements) -> HighLevelILFunction:
    func = HighLevelILFunction('f')
    func.body = HLILBlock(list(statements))
    return func


class TestSelfLoopBody(unittest.TestCase):

    def test_self_loop_holds_only_its_header(self):
        # 0 -> 1, 1 -> 1 (self back edge), 1 -> 2 -> 3
        analyzer = StructuralAnalyzer(4, {0: [1], 1: [1, 2], 2: [3], 3: []})
        self.assertEqual(analyzer.get_loop_info(1).body, {1})


class TestMergePoints(unittest.TestCase):

    def assert_same_runs(self, blocks: dict, emitted_once: str):
        func = build_function('f', blocks)
        hlil = to_hlil(func)
        self.assertEqual(classify(func, hlil), ('ok', None))
        self.assertEqual(unstructured_nodes(hlil, reachable_only = False), [])
        self.assertEqual(calls_emitted(hlil, emitted_once), 1)

    def test_target_reached_conditionally_is_the_merge(self):
        self.assert_same_runs(EARLY_EXIT, 'rest')

    def test_merge_stays_inside_the_loop_and_before_the_enclosing_merge(self):
        self.assert_same_runs(MERGE_IN_LOOP, 'move')

    def test_block_other_paths_bypass_is_not_a_merge(self):
        self.assert_same_runs(CASE_FALLTHROUGH, 'end')


class TestLoopExitsAndHeaders(unittest.TestCase):

    def test_exit_through_goto_only_blocks_breaks(self):
        func = build_function('f', PASSTHROUGH_EXIT)
        self.assertEqual(classify(func, to_hlil(func)), ('ok', None))

    def test_code_after_the_loop_stops_at_the_enclosing_merge(self):
        func = build_function('f', STOP_IN_EXIT_CHAIN)
        hlil = to_hlil(func)
        self.assertEqual(classify(func, hlil), ('ok', None))
        self.assertEqual(calls_emitted(hlil, 'tail'), 1)

    def test_goto_only_header_starts_its_loop(self):
        func = build_function('f', GOTO_HEADER)
        hlil = to_hlil(func)
        self.assertEqual(classify(func, hlil), ('ok', None))
        self.assertTrue(any(isinstance(n, (HLILWhile, HLILDoWhile)) for n in iter_tree(hlil.body)))

    def test_loop_entered_again_is_repeated(self):
        func = build_function('f', LOOP_REENTERED)
        hlil = to_hlil(func)
        self.assertEqual(classify(func, hlil), ('ok', None))
        self.assertEqual(calls_emitted(hlil, 'loop'), 2)


class TestUnstructuredNodes(unittest.TestCase):

    def test_repeated_region_within_the_limits(self):
        func, hlil = structure(SHARED_LOOP)
        self.assertEqual(classify(func, hlil), ('ok', None))
        self.assertEqual(calls_emitted(hlil, 'A3'), 2)

    def test_budget_counts_nested_statements(self):
        func, hlil = structure(SHARED_LOOP, clone_budget = SHARED_LOOP_COPY_STATEMENTS - 1)
        self.assertEqual(classify(func, hlil)[0], 'loud')
        self.assertEqual([n.reason for n in unstructured_nodes(hlil)],
                         [f'{SHARED_LOOP_COPY_STATEMENTS} statements over budget'])

    def test_region_repeated_inside_another_is_charged_once(self):
        func, hlil = structure(NESTED_REPEATS, clone_budget = NESTED_REPEATS_CHARGE)
        self.assertEqual(classify(func, hlil), ('ok', None))

        func, hlil = structure(NESTED_REPEATS, clone_budget = NESTED_REPEATS_CHARGE - 1)
        self.assertEqual(classify(func, hlil)[0], 'loud')

    def test_region_over_the_block_cap(self):
        func, hlil = structure(SHARED_LOOP, max_region_blocks = 0)
        self.assertEqual(classify(func, hlil)[0], 'loud')
        self.assertEqual([n.reason for n in unstructured_nodes(hlil)], ['region not repeatable'])

    def test_loop_entered_again_over_budget(self):
        func, hlil = structure(LOOP_REENTERED, clone_budget = 0)
        self.assertEqual(classify(func, hlil)[0], 'loud')

    def test_node_a_run_stops_at_is_reachable(self):
        func, hlil = structure(FUNNEL_CONSTANT_FIRST, clone_budget = 0)
        self.assertNotEqual(classify(func, hlil)[0], 'wrong')

        hit = set()
        names = parameters(func)
        for bits in range(2 ** len(names)):
            env = {name: bool(bits >> i & 1) for i, name in enumerate(names)}
            _, end = hlil_run(hlil, env)
            if end[0] == 'unstructured':
                hit.add(end[1])

        self.assertTrue(hit)
        self.assertLessEqual(hit, {n.target for n in unstructured_nodes(hlil)})

    def test_node_under_a_constant_condition_is_unreachable(self):
        func, hlil = structure(CONSTANT_COMPARE, clone_budget = 0)
        self.assertEqual(classify(func, hlil), ('ok', None))
        self.assertNotEqual(unstructured_nodes(hlil, reachable_only = False), [])
        self.assertEqual(unstructured_nodes(hlil), [])


class TestSafetyNetWithoutMergeValidity(unittest.TestCase):
    '''With merge points back to the bare heuristic, the converter's own checks - a fall-out only to
    the innermost merge at the same loop depth, an arm starting at the enclosing stop falling out
    too - keep every shape loud or correct'''

    def test_heuristic_merges_never_give_a_wrong_run(self):
        def heuristic_only(analyzer, cond_block, true_target, false_target, stop = None):
            return analyzer._heuristic_merge_point(cond_block, true_target, false_target)

        with mock.patch.object(StructuralAnalyzer, 'find_merge_point', heuristic_only):
            for name, blocks in (('case fall-through', CASE_FALLTHROUGH), ('merge in loop', MERGE_IN_LOOP),
                                 ('early exit', EARLY_EXIT)):
                with self.subTest(shape = name):
                    func = build_function('f', blocks)
                    self.assertNotEqual(classify(func, to_hlil(func))[0], 'wrong')


class TestNodeInPasses(unittest.TestCase):

    def test_dead_code_elimination_stops_at_the_node(self):
        func = DeadCodeEliminationPass().run(function(node(), HLILExprStmt(HLILCall('after', []))))
        self.assertEqual([type(s) for s in func.body.statements], [HLILUnstructured])

    def test_condition_is_not_inlined_past_the_node(self):
        # tmp = p == 0; if (tmp != 0) { <node> } - whatever the node jumps to may read tmp
        assign = HLILAssign(var('tmp'), HLILBinaryOp(BinaryOp.EQ, var('p'), HLILConst(0)))
        test = HLILIf(HLILBinaryOp(BinaryOp.NE, var('tmp'), HLILConst(0)), HLILBlock([node()]))
        func = ControlFlowOptimizationPass().run(function(assign, test))
        self.assertIsInstance(func.body.statements[0], HLILAssign)

    def test_loop_holding_the_node_is_not_rewritten(self):
        # while (1) { if (c) { f(); <node> } else { break } } would otherwise become while (c)
        body = HLILBlock([HLILIf(var('c'), HLILBlock([HLILExprStmt(HLILCall('f', [])), node()]),
                                 HLILBlock([HLILBreak()]))])
        func = LoopRecoveryPass().run(function(HLILWhile(HLILConst(1), body)))
        self.assertIsInstance(func.body.statements[0].condition, HLILConst)


class TestNodeRendering(unittest.TestCase):

    def test_typescript_throws_and_the_case_gets_no_break(self):
        switch = HLILSwitch(var('x'), [HLILSwitchCase([HLILConst(1)], HLILBlock([node()])),
                                       HLILSwitchCase(None, HLILBlock([HLILReturn(HLILConst(0))]))])
        lines = [line.strip() for line in generate_typescript(function(switch, node())).splitlines()]
        throw = f'throw new Error("unstructured: {TARGET}");'

        self.assertEqual(lines.count(throw), 2)
        self.assertNotEqual(lines[lines.index(throw) + 1], 'break;')
        self.assertEqual(lines[-2], throw)

    def test_formatter_shows_a_goto(self):
        lines = [line.strip() for line in HLILFormatter.format_function(function(node()))]
        self.assertIn(f'goto {TARGET}; // unstructured ({REASON})', lines)


class TestNodeReportedByTheValidator(unittest.TestCase):

    def hard_fails(self, blocks: dict) -> list:
        func, hlil = structure(blocks, clone_budget = 0)
        return [v.explanation for v in compare_mlil_hlil(func, hlil).hard_fail_violations]

    def test_reachable_node_is_a_hard_fail(self):
        self.assertTrue(any('unstructured_jump' in e for e in self.hard_fails(LOOP_REENTERED)))

    def test_unreachable_node_is_not(self):
        self.assertFalse(any('unstructured_jump' in e for e in self.hard_fails(CONSTANT_COMPARE)))


class TestConstantTruth(unittest.TestCase):

    def test_constants_and_comparisons_of_constants(self):
        self.assertIs(constant_truth(HLILConst(1)), True)
        self.assertIs(constant_truth(HLILConst(0)), False)
        self.assertIs(constant_truth(HLILBinaryOp(BinaryOp.EQ, HLILConst(1), HLILConst(1))), True)
        self.assertIs(constant_truth(HLILBinaryOp(BinaryOp.LT, HLILConst(2), HLILConst(1))), False)
        self.assertIs(constant_truth(HLILUnaryOp(UnaryOp.NOT, HLILConst(0))), True)

    def test_logical_operators_decided_by_one_side(self):
        self.assertIs(constant_truth(HLILBinaryOp(BinaryOp.OR, var('c'), HLILConst(1))), True)
        self.assertIs(constant_truth(HLILBinaryOp(BinaryOp.AND, var('c'), HLILConst(0))), False)
        self.assertIsNone(constant_truth(HLILBinaryOp(BinaryOp.AND, var('c'), HLILConst(1))))

    def test_anything_else_is_unknown(self):
        self.assertIsNone(constant_truth(var('c')))
        self.assertIsNone(constant_truth(HLILBinaryOp(BinaryOp.EQ, var('c'), HLILConst(1))))

    def test_floats_decide_nothing(self):
        # A float's truth and comparisons in the VM are unverified
        self.assertIsNone(constant_truth(HLILConst(0.5)))
        self.assertIsNone(constant_truth(HLILBinaryOp(BinaryOp.LT, HLILConst(0.5), HLILConst(1))))
        self.assertIsNone(constant_truth(HLILBinaryOp(BinaryOp.LT, HLILConst(1), HLILConst(0.5))))


class TestReachableStatements(unittest.TestCase):

    def reached(self, *statements) -> list:
        return [s.expr.func_name for s in reachable_statements(HLILBlock(list(statements)))
                if isinstance(s, HLILExprStmt)]

    def call(self, name: str) -> HLILExprStmt:
        return HLILExprStmt(HLILCall(name, []))

    def test_nothing_after_a_terminal(self):
        self.assertEqual(self.reached(self.call('a'), HLILReturn(), self.call('b')), ['a'])
        self.assertEqual(self.reached(node(), self.call('b')), [])

    def test_constant_condition_prunes_an_arm(self):
        dead_if = HLILIf(HLILConst(0), HLILBlock([self.call('dead')]), HLILBlock([self.call('live')]))
        self.assertEqual(self.reached(dead_if, self.call('after')), ['live', 'after'])

    def test_code_after_an_endless_loop_needs_a_break(self):
        endless = HLILWhile(HLILConst(1), HLILBlock([self.call('body')]))
        self.assertEqual(self.reached(endless, self.call('after')), ['body'])

        leaves = HLILWhile(HLILConst(1), HLILBlock([self.call('body'), HLILBreak()]))
        self.assertEqual(self.reached(leaves, self.call('after')), ['body', 'after'])

    def test_do_while_condition_is_reached_through_continue(self):
        # do { if (c) continue; return; } while (c) - the condition can end the loop
        body = HLILBlock([HLILIf(var('c'), HLILBlock([HLILContinue()])), HLILReturn()])
        self.assertEqual(self.reached(HLILDoWhile(var('c'), body), self.call('after')), ['after'])


if __name__ == '__main__':
    unittest.main()
