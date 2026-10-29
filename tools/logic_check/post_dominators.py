"""Dominators, post-dominators and control dependence over any layer's control-flow graph

Immediate dominators by Cooper, Harvey and Kennedy's iterative algorithm ("A Simple, Fast Dominance Algorithm", 2001);
post-dominators by the same on the reversed graph, rooted at a virtual EXIT; then the branches each block runs under
(Ferrante, Ottenstein and Warren's control dependence, read off the post-dominator tree), over the whole graph or
within one iteration of a block's innermost loop; a graph's ControlFlow builds each of them once, when first read"""

from typing import Callable, Hashable, Sequence
import functools

from ir.core import reverse_post_order

EXIT = 'exit'
TRUE_ARM, FALSE_ARM = 't', 'f'    # an arm's polarity: the branch's true or false target


def exit_blocks(blocks: Sequence, successors: Callable, exit_rank: Callable | None = None) -> set:
    """The blocks given an edge to EXIT: those without a successor, and of each region that reaches none of them and
    that no edge leaves (an endless loop) its block of the lowest exit_rank(block), the same on every layer, ties (and
    no exit_rank) by the order of blocks. Only the region gets the edge, so a block on the way into it keeps its
    post-dominators and its guards"""
    ends = {block for block in blocks if not successors(block)}
    predecessors = {block: [] for block in blocks}
    for block in blocks:
        for successor in successors(block):
            predecessors[successor].append(block)

    reaching = set(ends)
    pending = list(ends)
    while pending:
        for predecessor in predecessors[pending.pop()]:
            if predecessor not in reaching:
                reaching.add(predecessor)
                pending.append(predecessor)

    position = {block: index for index, block in enumerate(blocks)}
    rank = (lambda block: (exit_rank(block), position[block])) if exit_rank else position.__getitem__
    exits = set(ends)
    for component in strongly_connected_components([block for block in blocks if block not in reaching], successors):
        members = set(component)
        if all(successor in members for block in component for successor in successors(block)):
            exits.add(min(component, key=rank))

    return exits


def strongly_connected_components(blocks: Sequence, successors: Callable) -> list[list]:
    """Tarjan's strongly connected components of the graph over blocks (edges leaving blocks ignored), iterative"""
    inside = set(blocks)
    index, low = {}, {}
    stack, on_stack, components = [], set(), []
    for root in blocks:
        if root in index:
            continue

        index[root] = low[root] = len(index)
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(successors(root)))]
        while work:
            node, edges = work[-1]
            for successor in edges:
                if successor not in inside:
                    continue
                if successor not in index:
                    index[successor] = low[successor] = len(index)
                    stack.append(successor)
                    on_stack.add(successor)
                    work.append((successor, iter(successors(successor))))
                    break
                if successor in on_stack:
                    low[node] = min(low[node], index[successor])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    components.append(component)

    return components


def immediate_post_dominators(blocks: Sequence, successors: Callable,
                              exit_rank: Callable | None = None) -> dict[Hashable, Hashable]:
    """Each block's immediate post-dominator (EXIT's is EXIT); exit_rank as exit_blocks takes it"""
    exits = exit_blocks(blocks, successors, exit_rank)
    reversed_successors = {EXIT: list(exits)}
    for block in blocks:
        reversed_successors.setdefault(block, [])
        for successor in successors(block):
            reversed_successors.setdefault(successor, []).append(block)

    order = reverse_post_order(EXIT, lambda node: reversed_successors[node])
    reversed_predecessors = {block: [*successors(block), *((EXIT,) if block in exits else ())] for block in blocks}
    return immediate_dominators(order, reversed_predecessors.__getitem__)


def immediate_dominators(order: Sequence, predecessors: Callable) -> dict[Hashable, Hashable]:
    """Each block's immediate dominator over blocks in reverse post-order from order[0], the root (its own)"""
    number = {node: index for index, node in enumerate(order)}
    idom = {order[0]: order[0]}

    def intersect(a, b):
        while a is not b:
            while number[a] > number[b]:
                a = idom[a]
            while number[b] > number[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for node in order[1:]:
            new = None
            for predecessor in predecessors(node):
                if predecessor in idom:
                    new = predecessor if new is None else intersect(predecessor, new)
            if idom.get(node) is not new:
                idom[node] = new
                changed = True

    return idom


def control_dependence(blocks: Sequence, branches: Callable, ipdom: dict) -> dict[Hashable, frozenset]:
    """block -> the (branch address, TRUE_ARM / FALSE_ARM) it runs under directly. branches(block) is (address, true
    target, false target) for a block ending in a two-way branch, else None; ipdom the blocks' immediate
    post-dominators (immediate_post_dominators). A block depends on an arm when it post-dominates the arm's target but
    not, strictly, the branch: the post-dominator tree's path from the target up to the branch's own immediate
    post-dominator"""
    dependence = {}
    for block in blocks:
        branch = branches(block)
        if branch is None:
            continue

        address, true_target, false_target = branch
        if true_target is false_target:
            continue

        stop = ipdom[block]
        for target, polarity in ((true_target, TRUE_ARM), (false_target, FALSE_ARM)):
            runner = target
            while runner is not stop:
                if runner is EXIT:
                    raise RuntimeError(f'branch 0x{address:X}: its post-dominator does not post-dominate a target')
                dependence.setdefault(runner, set()).add((address, polarity))
                runner = ipdom[runner]

    return {block: frozenset(dependence.get(block, ())) for block in blocks}


def back_edges(order: Sequence, successors: Callable) -> list[tuple]:
    """(source, header) of each edge that goes back in order, a reverse post-order"""
    position = {block: index for index, block in enumerate(order)}
    return [(source, target) for source in order for target in successors(source)
            if position[target] <= position[source]]


def loop_bodies(order: Sequence, predecessors: Callable, edges: list[tuple],
                dominates: Callable) -> dict[Hashable, set]:
    """header -> its loop's blocks, those reaching a back edge (edges: back_edges over order) into it without passing
    it. Natural loops only: the header dominates (dominates(header, source)) the edge's source. A retreating edge into
    a block that does not (an irreducible region's entry) has no body: walking back from its source would pass the
    header and reach the function's entry, and two such edges would contain each other's header"""
    reachable = set(order)
    latches = {}
    for source, header in edges:
        if dominates(header, source):
            latches.setdefault(header, []).append(source)
    bodies = {}
    for header, sources in latches.items():
        body, pending = {header}, list(sources)
        while pending:
            block = pending.pop()
            if block not in body:
                body.add(block)
                pending.extend(predecessor for predecessor in predecessors(block) if predecessor in reachable)
        bodies[header] = body
    return bodies


def iteration_dependence(order: Sequence, successors: Callable, branches: Callable, bodies: dict,
                         innermost_header: dict, whole: dict) -> dict[Hashable, frozenset]:
    """block -> the (branch address, TRUE_ARM / FALSE_ARM) it runs under directly within one iteration of its
    innermost loop (innermost_header; bodies: header -> its loop's blocks). Control dependence over the loop's blocks,
    its back edges and exits ending the iteration, so an arm the block misses in this iteration is one it depends on
    even where a later iteration reaches it; a block in no loop, and a loop's header (in its enclosing loop), its
    whole-graph dependence (whole) over the blocks around it. Only natural loops (loop_bodies) count: a block in an
    irreducible region outside any of them has its whole-graph dependence"""
    dependence = {block: whole[block] for block in order if block not in innermost_header}
    for header, body in bodies.items():
        end = IterationEnd()

        def inside(target):
            """target within the iteration, or its end: a back edge to the header, an edge out of the loop"""
            return target if target in body and target is not header else end

        def iteration_successors(block):
            return [] if block is end else list(dict.fromkeys(map(inside, successors(block))))

        def iteration_branch(block):
            branch = None if block is end else branches(block)
            return None if branch is None else (branch[0], inside(branch[1]), inside(branch[2]))

        members = [*(block for block in order if block in body), end]
        local = control_dependence(members, iteration_branch, immediate_post_dominators(members, iteration_successors))
        dependence.update((block, local[block]) for block in members if innermost_header.get(block) is header)
    return dependence


class IterationEnd:
    """The end of one iteration of a loop, where its back edges and exits lead (iteration_dependence)"""


class ControlFlow:
    """A graph's control-flow facts, each built once, when first read: from entry, successors(block),
    predecessors(block), branches(block) as control_dependence takes it, and exit_rank as exit_blocks does. Its readers
    share the facts, so they only read them; and the facts hold for the graph as it is while one analysis runs
    (evaluation.analyze), which keeps none past its end: a layer may be converted after its analysis"""

    def __init__(self, entry, successors: Callable, predecessors: Callable, branches: Callable,
                 exit_rank: Callable | None = None):
        self.entry = entry
        self.successors = successors
        self.predecessors = predecessors
        self.branches = branches
        self.exit_rank = exit_rank

    @functools.cached_property
    def order(self) -> list:
        """The blocks reached from entry, in reverse post-order"""
        return reverse_post_order(self.entry, self.successors)

    @functools.cached_property
    def position(self) -> dict:
        """block -> its index in order"""
        return {block: index for index, block in enumerate(self.order)}

    @functools.cached_property
    def dominators(self) -> dict:
        """Each block's immediate dominator (the entry's its own)"""
        return immediate_dominators(self.order, self.predecessors)

    @functools.cached_property
    def dominator_span(self) -> dict:
        """block -> (first, last) of its dominator subtree's numbers, a pre-order of the dominator tree"""
        children = {block: [] for block in self.order}
        for block in self.order[1:]:
            children[self.dominators[block]].append(block)
        span, number, pending = {}, 0, [(self.order[0], False)]
        while pending:
            block, done = pending.pop()
            if done:
                span[block] = (span[block], number - 1)
                continue
            span[block] = number
            number += 1
            pending.append((block, True))
            pending.extend((child, False) for child in reversed(children[block]))
        return span

    def dominates(self, a, b) -> bool:
        return self.dominator_span[a][0] <= self.dominator_span[b][0] <= self.dominator_span[a][1]

    @functools.cached_property
    def post_dominators(self) -> dict:
        """Each block's immediate post-dominator, an endless region's EXIT edge by exit_rank"""
        return immediate_post_dominators(self.order, self.successors, self.exit_rank)

    @functools.cached_property
    def back_edges(self) -> list[tuple]:
        return back_edges(self.order, self.successors)

    @functools.cached_property
    def loop_bodies(self) -> dict:
        return loop_bodies(self.order, self.predecessors, self.back_edges, self.dominates)

    @functools.cached_property
    def dependence(self) -> dict:
        """block -> the arms it runs under directly over the whole graph"""
        return control_dependence(self.order, self.branches, self.post_dominators)

    @functools.cached_property
    def innermost_header(self) -> dict:
        """block -> the header of the innermost loop whose iteration it runs in (a header: its enclosing loop's)"""
        bodies = self.loop_bodies
        innermost = {}
        for header in sorted(bodies, key=lambda header: len(bodies[header]), reverse=True):
            for block in bodies[header]:
                if block is not header:
                    innermost[block] = header
        return innermost

    @functools.cached_property
    def iteration_dependence(self) -> dict:
        """block -> the arms it runs under directly within one iteration of its innermost loop"""
        return iteration_dependence(self.order, self.successors, self.branches, self.loop_bodies,
                                    self.innermost_header, self.dependence)
