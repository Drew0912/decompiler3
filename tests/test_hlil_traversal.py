#!/usr/bin/env python3
'''Unit tests for the shared HLIL tree walkers in ir/hlil/hlil.py - expr_children, stmt_children,
read_children, iter_tree, contains_escaping_exit and sole_statement - which the passes and the
converter are built on instead of each hand-listing the node kinds.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.hlil import (
    BinaryOp,
    UnaryOp,
    ControlFlowOptimizationPass,
    HighLevelILFunction,
    HLILAddressOf,
    HLILAssign,
    HLILBinaryOp,
    HLILBlock,
    HLILBreak,
    HLILCall,
    HLILComment,
    HLILConst,
    HLILContinue,
    HLILDeref,
    HLILDoWhile,
    HLILExprStmt,
    HLILExternCall,
    HLILIf,
    HLILInstruction,
    HLILReturn,
    HLILSwitch,
    HLILSwitchCase,
    HLILSyscall,
    HLILUnaryOp,
    HLILUnstructured,
    HLILVar,
    HLILVariable,
    HLILWhile,
    contains_bare_break,
    contains_escaping_exit,
    iter_tree,
    read_children,
    sole_statement,
    split_else_if_arm,
    stmt_children,
)
from ir.hlil.mlil_to_hlil import MLILToHLILConverter

FIRST_CASE_VALUE = 1
SECOND_CASE_VALUE = 2
THIRD_CASE_VALUE = 3
FIRST_VALUE = 1
SECOND_VALUE = 2
TRUE_CONDITION = 1
LINE_NUMBER = 3
LOOP_LABEL = 'outer'


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


def var(name: str) -> HLILVar:
    return HLILVar(HLILVariable(name))


def c(value) -> HLILConst:
    return HLILConst(value)


def samples() -> list:
    '''One instance of every concrete HLIL node type, with distinct child nodes.'''
    return [
        var('x'), c(FIRST_VALUE),
        HLILBinaryOp(BinaryOp.ADD, c(FIRST_VALUE), c(SECOND_VALUE)),
        HLILUnaryOp(UnaryOp.NEG, c(FIRST_VALUE)),
        HLILAddressOf(var('x')), HLILDeref(var('p')),
        HLILCall('f', [c(FIRST_VALUE), c(SECOND_VALUE)]),
        HLILSyscall('sys', 'cmd', [c(FIRST_VALUE)]),
        HLILExternCall('m:g', [c(FIRST_VALUE)]),
        HLILBlock([HLILBreak(), HLILContinue()]),
        HLILIf(c(TRUE_CONDITION), HLILBlock(), HLILBlock()), HLILIf(c(TRUE_CONDITION), HLILBlock()),
        HLILWhile(c(TRUE_CONDITION), HLILBlock()), HLILDoWhile(c(TRUE_CONDITION), HLILBlock()),
        HLILSwitch(var('x'), [HLILSwitchCase([c(FIRST_CASE_VALUE), c(SECOND_CASE_VALUE)], HLILBlock()),
                              HLILSwitchCase(None, HLILBlock())]),
        HLILBreak(LOOP_LABEL), HLILContinue(), HLILReturn(c(FIRST_VALUE)), HLILReturn(),
        HLILAssign(var('x'), c(FIRST_VALUE)), HLILExprStmt(HLILCall('f', [])), HLILComment('note'),
        HLILUnstructured('loc_1', 'region not repeatable'),
    ]


def held_nodes(node) -> list:
    '''Every HLIL node a node holds in a field - lists, and switch cases' labels and bodies, included.'''
    found = []
    for value in vars(node).values():
        for item in (value if isinstance(value, list) else [value]):
            if isinstance(item, HLILSwitchCase):
                found.extend(item.values or [])
                found.append(item.body)

            elif isinstance(item, HLILInstruction):
                found.append(item)

    return found


def ids(nodes) -> list:
    return [id(node) for node in nodes]


class TestChildrenCoverEveryNode(unittest.TestCase):
    '''stmt_children is the one list of a node's children: every node type must return exactly the
    nodes it holds. A new node type fails here until it has a sample and an entry in stmt_children
    (a statement) or expr_children (an expression).'''

    def test_every_node_type_has_a_sample(self):
        sampled = {type(node) for node in samples()}
        missing = concrete_subclasses(HLILInstruction) - sampled
        self.assertEqual(missing, set(), [cls.__name__ for cls in missing])

    def test_stmt_children_are_exactly_the_held_nodes(self):
        for node in samples():
            with self.subTest(node = type(node).__name__):
                self.assertCountEqual(ids(stmt_children(node)), ids(held_nodes(node)))

    def test_read_children_drop_only_a_plain_assignment_target(self):
        for node in samples():
            with self.subTest(node = type(node).__name__):
                expected = [node.src] if isinstance(node, HLILAssign) else stmt_children(node)
                self.assertEqual(ids(read_children(node)), ids(expected))


class TestSourceOrder(unittest.TestCase):

    def test_statement_children_are_in_source_order(self):
        cond, true_block, false_block, body = c(TRUE_CONDITION), HLILBlock(), HLILBlock(), HLILBlock()
        dest, src = var('x'), c(SECOND_VALUE)

        if_stmt = HLILIf(cond, true_block, false_block)

        self.assertEqual(ids(stmt_children(if_stmt)), ids([cond, true_block, false_block]))
        self.assertEqual(ids(stmt_children(HLILDoWhile(cond, body))), ids([body, cond]))
        self.assertEqual(ids(stmt_children(HLILAssign(dest, src))), ids([dest, src]))

    def test_switch_gives_each_case_labels_then_body(self):
        scrutinee, first, second = var('x'), c(FIRST_CASE_VALUE), c(SECOND_CASE_VALUE)
        first_body, default_body = HLILBlock(), HLILBlock()
        switch = HLILSwitch(scrutinee, [HLILSwitchCase([first, second], first_body),
                                        HLILSwitchCase(None, default_body)])

        self.assertEqual(ids(stmt_children(switch)), ids([scrutinee, first, second, first_body, default_body]))

    def test_a_store_through_a_pointer_reads_the_pointer(self):
        dest, src = HLILDeref(var('p')), c(FIRST_VALUE)
        self.assertEqual(ids(read_children(HLILAssign(dest, src))), ids([dest, src]))


class TestIterTree(unittest.TestCase):

    def test_pre_order_with_optional_children_absent(self):
        cond, value = var('c'), var('v')
        ret, bare_ret = HLILReturn(value), HLILReturn()
        true_block = HLILBlock([ret, bare_ret])
        if_stmt = HLILIf(cond, true_block)

        self.assertEqual(ids(iter_tree(if_stmt)), ids([if_stmt, cond, true_block, ret, value, bare_ret]))

    def test_exclude_skips_the_whole_subtree(self):
        inner = HLILExprStmt(HLILCall('f', [var('x')]))
        outer = HLILExprStmt(var('y'))
        block = HLILBlock([inner, outer])

        self.assertEqual(ids(iter_tree(block, exclude = (id(inner),))), ids([block, outer, outer.expr]))

    def test_children_function_decides_what_is_visited(self):
        dest = var('x')
        assign = HLILAssign(dest, c(FIRST_VALUE))

        self.assertIn(id(dest), ids(iter_tree(assign)))
        self.assertNotIn(id(dest), ids(iter_tree(assign, read_children)))


class TestContainsEscapingExit(unittest.TestCase):
    '''A loop owns a bare break and a bare continue, a switch only a bare break; a labeled exit
    counts only with include_labeled.'''

    def if_(self, *body) -> HLILIf:
        return HLILIf(c(TRUE_CONDITION), HLILBlock(list(body)))

    def loop(self, *body) -> HLILWhile:
        return HLILWhile(c(TRUE_CONDITION), HLILBlock(list(body)))

    def do_loop(self, *body) -> HLILDoWhile:
        return HLILDoWhile(c(TRUE_CONDITION), HLILBlock(list(body)))

    def switch(self, *body) -> HLILSwitch:
        return HLILSwitch(var('x'), [HLILSwitchCase([c(FIRST_CASE_VALUE)], HLILBlock(list(body)))])

    def test_rules(self):
        labeled_break, labeled_continue = HLILBreak(LOOP_LABEL), HLILContinue(LOOP_LABEL)
        cases = [
            # (description, statement, exit_type, include_labeled, expected)
            ('bare break at top', HLILBreak(), HLILBreak, False, True),
            ('bare break in an if', self.if_(HLILBreak()), HLILBreak, False, True),
            ('bare break in a loop', self.loop(HLILBreak()), HLILBreak, False, False),
            ('bare break in a do-while', self.do_loop(HLILBreak()), HLILBreak, False, False),
            ('bare break in a switch', self.switch(HLILBreak()), HLILBreak, False, False),
            ('bare continue in a switch', self.switch(HLILContinue()), HLILContinue, False, True),
            ('bare continue in a loop', self.loop(HLILContinue()), HLILContinue, False, False),
            ('labeled break at top, not counted', labeled_break, HLILBreak, False, False),
            ('labeled break at top, counted', labeled_break, HLILBreak, True, True),
            ('labeled break in a loop, not counted', self.loop(labeled_break), HLILBreak, False, False),
            ('labeled break in a loop, counted', self.loop(labeled_break), HLILBreak, True, True),
            ('labeled continue in a switch in a loop', self.loop(self.switch(labeled_continue)),
             HLILContinue, True, True),
            ('break is not a continue', HLILBreak(), HLILContinue, True, False),
        ]
        for description, stmt, exit_type, include_labeled, expected in cases:
            with self.subTest(description):
                self.assertEqual(contains_escaping_exit(HLILBlock([stmt]), exit_type, include_labeled), expected)

        self.assertFalse(contains_escaping_exit(None, HLILBreak, include_labeled = True))

    def test_contains_bare_break_is_the_break_rule(self):
        for block in (HLILBlock([HLILBreak()]), HLILBlock([HLILBreak(LOOP_LABEL)])):
            with self.subTest(block = repr(block.statements)):
                self.assertEqual(contains_bare_break(block), contains_escaping_exit(block, HLILBreak))


class TestSoleStatement(unittest.TestCase):

    def test_the_one_non_comment_statement(self):
        inner = HLILIf(c(TRUE_CONDITION), HLILBlock())

        self.assertIsNone(sole_statement(None))
        self.assertIsNone(sole_statement(HLILBlock()))
        self.assertIsNone(sole_statement(HLILBlock([HLILComment('note')])))
        self.assertIsNone(sole_statement(HLILBlock([inner, HLILBreak()])))
        self.assertIs(sole_statement(HLILBlock([HLILComment('note'), inner])), inner)

    def test_split_else_if_arm_keeps_the_comments(self):
        comment, inner = HLILComment(f'line({LINE_NUMBER})'), HLILIf(c(TRUE_CONDITION), HLILBlock())
        comments, arm = split_else_if_arm(HLILBlock([comment, inner]))

        self.assertEqual(ids(comments), ids([comment]))
        self.assertIs(arm, inner)
        self.assertIsNone(split_else_if_arm(HLILBlock([HLILBreak()])))


class TestWalkerUsers(unittest.TestCase):

    def test_declared_locals_are_in_first_use_order(self):
        body = HLILBlock([
            HLILAssign(var('b'), var('a')),
            HLILSwitch(var('c'), [HLILSwitchCase([var('d')], HLILBlock([HLILExprStmt(var('e'))]))]),
        ])

        self.assertEqual(MLILToHLILConverter._collect_used_var_names(body), ['b', 'a', 'c', 'd', 'e'])

    def test_control_flow_optimization_reaches_into_a_do_while(self):
        # A chain of equality tests becomes a switch wherever it sits - a do-while body included
        def link(value, rest):
            return HLILIf(HLILBinaryOp(BinaryOp.EQ, var('x'), c(value)),
                          HLILBlock([HLILExprStmt(HLILCall(f'case_{value}', []))]), rest)

        chain = link(FIRST_CASE_VALUE, HLILBlock([link(SECOND_CASE_VALUE, HLILBlock([link(THIRD_CASE_VALUE, None)]))]))
        loop = HLILDoWhile(var('running'), HLILBlock([chain]))
        func = HighLevelILFunction('f')
        func.add_statement(loop)

        ControlFlowOptimizationPass().run(func)

        self.assertIsInstance(sole_statement(loop.body), HLILSwitch)


if __name__ == '__main__':
    unittest.main()
