"""Dominators, post-dominators and control dependence over any layer's control-flow graph

Immediate dominators by Cooper, Harvey and Kennedy's iterative algorithm ("A Simple, Fast Dominance Algorithm", 2001);
post-dominators by the same on the reversed graph, rooted at a virtual EXIT; then the branches each block runs under
(Ferrante, Ottenstein and Warren's control dependence, read off the post-dominator tree), over the whole graph or
within one iteration of a block's innermost loop"""

from typing import Callable, Hashable, Sequence

from ir.core import reverse_post_order

EXIT = 'exit'


def exit_blocks(blocks: Sequence, successors: Callable, start: Callable | None = None) -> set:
    """The blocks given an edge to EXIT: those without a successor, and of each region that reaches none of them and
    that no edge leaves (an endless loop) its block of the lowest start(block), the same on every layer, ties (and no
    start) by the order of blocks. Only the region gets the edge, so a block on the way into it keeps its
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
    rank = (lambda block: (start(block), position[block])) if start else position.__getitem__
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
                              start: Callable | None = None) -> dict[Hashable, Hashable]:
    """Each block's immediate post-dominator (EXIT's is EXIT); start as exit_blocks takes it"""
    exits = exit_blocks(blocks, successors, start)
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


def control_dependence(blocks: Sequence, successors: Callable, branches: Callable,
                       start: Callable | None = None) -> dict[Hashable, frozenset]:
    """block -> the (branch address, 't' / 'f') it runs under directly. branches(block) is (address, true target,
    false target) for a block ending in a two-way branch, else None; start as exit_blocks takes it. A block depends on
    an arm when it post-dominates the arm's target but not, strictly, the branch: the post-dominator tree's path from
    the target up to the branch's own immediate post-dominator"""
    ipdom = immediate_post_dominators(blocks, successors, start)
    dependence = {}
    for block in blocks:
        branch = branches(block)
        if branch is None:
            continue

        address, true_target, false_target = branch
        if true_target is false_target:
            continue

        stop = ipdom[block]
        for target, polarity in ((true_target, 't'), (false_target, 'f')):
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


def loop_bodies(order: Sequence, successors: Callable, predecessors: Callable) -> dict[Hashable, set]:
    """header -> its loop's blocks, those reaching a back edge (back_edges) into it without passing it"""
    reachable = set(order)
    latches = {}
    for source, header in back_edges(order, successors):
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


def iteration_dependence(order: Sequence, successors: Callable, predecessors: Callable, branches: Callable,
                         start: Callable | None = None) -> tuple[dict, dict, dict]:
    """(block -> the (branch address, 't' / 'f') it runs under directly within one iteration of its innermost loop,
    block -> that loop's header, header -> its loop's blocks). Control dependence over the loop's blocks, its back
    edges and exits ending the
    iteration, so an arm the block misses in this iteration is one it depends on even where a later iteration reaches
    it; a block in no loop, and a loop's header (in its enclosing loop), as control_dependence gives them over the
    blocks around it"""
    bodies = loop_bodies(order, successors, predecessors)
    region = {}                 # block -> the header of the innermost loop whose iteration it runs in
    for header in sorted(bodies, key=lambda header: len(bodies[header]), reverse=True):
        for block in bodies[header]:
            if block is not header:
                region[block] = header

    whole = control_dependence(order, successors, branches, start)
    dependence = {block: whole[block] for block in order if block not in region}
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
        local = control_dependence(members, iteration_successors, iteration_branch)
        dependence.update((block, local[block]) for block in members if region.get(block) is header)
    return dependence, region, bodies


class IterationEnd:
    """The end of one iteration of a loop, where its back edges and exits lead (iteration_dependence)"""
