#!/usr/bin/env python3
"""The logic check's post-dominators (tools/logic_check/post_dominators.py): Cooper-Harvey-Kennedy on the reversed
graph, control dependence, a control flow's loops"""

from pathlib import Path
from typing import Callable
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from logic_check.post_dominators import EXIT, ControlFlow, control_dependence, exit_blocks, immediate_post_dominators


class TestPostDominators(unittest.TestCase):
    """Cooper-Harvey-Kennedy on the reversed graph, control dependence read off its tree, and a control flow's loops
    and dependence within one iteration"""

    @classmethod
    def graph(cls, edges: dict) -> tuple[list, Callable]:
        return list(edges), lambda block: edges[block]

    @classmethod
    def flow(cls, edges: dict, branches: dict) -> ControlFlow:
        """The control flow from edges' first block; branches: block -> (address, true target, false target)"""
        return ControlFlow(next(iter(edges)), edges.__getitem__,
                           lambda block: [other for other in edges if block in edges[other]], branches.get)

    def assert_iteration(self, edges: dict, branches: dict, dependence: dict, innermost_header: dict) -> ControlFlow:
        flow = self.flow(edges, branches)
        self.assertEqual(flow.iteration_dependence, dependence)
        self.assertEqual(flow.innermost_header, innermost_header)
        return flow

    def test_diamond(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual({block: ipdom[block] for block in blocks}, {'a': 'd', 'b': 'd', 'c': 'd', 'd': EXIT})

        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, branches, ipdom)
        self.assertEqual(dependence, {'a': frozenset(), 'b': {(1, 't')}, 'c': {(1, 'f')}, 'd': frozenset()})

    def test_loop_bodies_are_natural_loops(self):
        self.assertEqual(self.flow({'e': ['h'], 'h': ['b', 'x'], 'b': ['h'], 'x': []}, {}).loop_bodies,
                         {'h': {'h', 'b'}})
        # Two entries into a cycle: the edge back to `a` is no loop's, neither of its ends dominates the other
        self.assertEqual(self.flow({'e': ['a', 'b'], 'a': ['b'], 'b': ['a', 'x'], 'x': []}, {}).loop_bodies, {})

    def test_iteration_of_a_loop(self):
        """do (if head: then) while test: test runs in every iteration, over the whole graph again only under its own
        true arm"""
        flow = self.assert_iteration(
            {'entry': ['head'], 'head': ['then', 'test'], 'then': ['test'], 'test': ['head', 'done'], 'done': []},
            {'head': (1, 'then', 'test'), 'test': (2, 'head', 'done')},
            {'entry': set(), 'head': {(2, 't')}, 'then': {(1, 't')}, 'test': set(), 'done': set()},
            {'then': 'head', 'test': 'head'})
        self.assertEqual(flow.dependence['test'], {(2, 't')})

    def test_iteration_of_nested_loops(self):
        """while outer: (do (if inner: then) while test): the inner loop's blocks within its own iteration, its header
        within the outer loop's"""
        flow = self.assert_iteration(
            {'entry': ['outer'], 'outer': ['inner', 'done'], 'inner': ['then', 'test'], 'then': ['test'],
             'test': ['inner', 'latch'], 'latch': ['outer'], 'done': []},
            {'outer': (1, 'inner', 'done'), 'inner': (2, 'then', 'test'), 'test': (3, 'inner', 'latch')},
            {'entry': set(), 'outer': {(1, 't')}, 'inner': {(1, 't'), (3, 't')}, 'then': {(2, 't')}, 'test': set(),
             'latch': {(1, 't')}, 'done': set()},
            {'inner': 'outer', 'then': 'inner', 'test': 'inner', 'latch': 'outer'})
        self.assertEqual(flow.dependence['test'], {(1, 't'), (3, 't')})

    def test_iteration_of_a_loop_with_one_way_out(self):
        """while 1: (if head: continue); work; if work: break: work runs in an iteration only under head's false arm,
        though over the whole graph every way out of the loop passes it (skipping_loop_function)"""
        flow = self.assert_iteration(
            {'entry': ['head'], 'head': ['skip', 'work'], 'skip': ['head'], 'work': ['done', 'next'],
             'next': ['head'], 'done': []},
            {'head': (1, 'skip', 'work'), 'work': (2, 'done', 'next')},
            {'entry': set(), 'head': {(1, 't'), (2, 'f')}, 'skip': {(1, 't')}, 'work': {(1, 'f')},
             'next': {(2, 'f')}, 'done': set()},
            {'skip': 'head', 'work': 'head', 'next': 'head'})
        self.assertEqual(flow.dependence['work'], {(2, 'f')})

    def test_iteration_of_an_endless_loop(self):
        """if entry: (while 1: (if head: then else other)): both back edges end the iteration, no edge leaves it"""
        self.assert_iteration(
            {'entry': ['head', 'done'], 'head': ['then', 'other'], 'then': ['head'], 'other': ['head'], 'done': []},
            {'entry': (1, 'head', 'done'), 'head': (2, 'then', 'other')},
            {'entry': set(), 'head': {(1, 't'), (2, 't'), (2, 'f')}, 'then': {(2, 't')}, 'other': {(2, 'f')},
             'done': {(1, 'f')}},
            {'then': 'head', 'other': 'head'})

    def test_iteration_in_an_irreducible_region(self):
        """A cycle entered at a and at b is no natural loop: its blocks keep their whole-graph dependence"""
        flow = self.assert_iteration(
            {'entry': ['a', 'b'], 'a': ['b'], 'b': ['a', 'done'], 'done': []},
            {'entry': (1, 'a', 'b'), 'b': (2, 'a', 'done')},
            {'entry': set(), 'a': {(1, 't'), (2, 't')}, 'b': {(2, 't')}, 'done': set()},
            {})
        self.assertEqual(flow.iteration_dependence, flow.dependence)

    def test_loop_test_controls_the_body_and_itself(self):
        blocks, successors = self.graph({'entry': ['head'], 'head': ['body', 'exit'], 'body': ['head'], 'exit': []})
        branches = lambda block: (2, 'body', 'exit') if block == 'head' else None
        dependence = control_dependence(blocks, branches, immediate_post_dominators(blocks, successors))
        self.assertEqual(dependence['body'], {(2, 't')})
        self.assertEqual(dependence['head'], {(2, 't')})
        self.assertEqual(dependence['exit'], frozenset())

    def test_endless_loop_still_has_a_post_dominator(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['b'], 'c': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual(ipdom['b'], EXIT)
        self.assertEqual(ipdom['a'], EXIT)

    def test_endless_region_exit_by_start_address(self):
        """A region entered at two blocks: the block with the lowest start gets the EXIT edge, whatever the order"""
        blocks, successors = self.graph({'e': ['c', 'b'], 'c': ['b'], 'b': ['c']})
        start = {'e': 0, 'b': 1, 'c': 2}.get
        self.assertEqual(exit_blocks(blocks, successors, start), {'b'})
        self.assertEqual(exit_blocks(blocks, successors), {'c'})

    def test_block_before_an_endless_loop_keeps_its_guard(self):
        """d runs only on a's true arm, and every path ends in the endless loop e"""
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['e'], 'd': ['e'], 'e': ['e']})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual(ipdom['d'], 'e')
        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, branches, ipdom)
        self.assertEqual(dependence['d'], {(1, 't')})
        self.assertEqual(dependence['e'], frozenset())


if __name__ == '__main__':
    unittest.main()
