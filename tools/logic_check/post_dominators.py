"""Post-dominators and control dependence over any layer's control-flow graph

Immediate post-dominators by Cooper, Harvey and Kennedy's iterative algorithm ("A Simple, Fast Dominance Algorithm",
2001) on the reversed graph, rooted at a virtual EXIT; then the branches each block runs under (Ferrante, Ottenstein
and Warren's control dependence, read off the post-dominator tree)"""

from typing import Callable, Hashable, Sequence

from ir.core import reverse_post_order

EXIT = 'exit'


def exit_blocks(blocks: Sequence, successors: Callable) -> set:
    """The blocks given an edge to EXIT: those without a successor, and of each region that reaches none of them and
    that no edge leaves (an endless loop) its first block in the order of blocks, the same way on every layer. Only the
    region gets the edge, so a block on the way into it keeps its post-dominators and its guards"""
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
    exits = set(ends)
    for component in strongly_connected_components([block for block in blocks if block not in reaching], successors):
        members = set(component)
        if all(successor in members for block in component for successor in successors(block)):
            exits.add(min(component, key=position.__getitem__))

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


def immediate_post_dominators(blocks: Sequence, successors: Callable) -> dict[Hashable, Hashable]:
    """Each block's immediate post-dominator (EXIT's is EXIT)"""
    exits = exit_blocks(blocks, successors)
    reversed_successors = {EXIT: list(exits)}
    for block in blocks:
        reversed_successors.setdefault(block, [])
        for successor in successors(block):
            reversed_successors.setdefault(successor, []).append(block)

    order = reverse_post_order(EXIT, lambda node: reversed_successors[node])
    number = {node: index for index, node in enumerate(order)}
    reversed_predecessors = {block: [*successors(block), *((EXIT,) if block in exits else ())] for block in blocks}
    ipdom = {EXIT: EXIT}

    def intersect(a, b):
        while a is not b:
            while number[a] > number[b]:
                a = ipdom[a]
            while number[b] > number[a]:
                b = ipdom[b]
        return a

    changed = True
    while changed:
        changed = False
        for node in order[1:]:
            new = None
            for predecessor in reversed_predecessors[node]:
                if predecessor in ipdom:
                    new = predecessor if new is None else intersect(predecessor, new)
            if ipdom.get(node) is not new:
                ipdom[node] = new
                changed = True

    return ipdom


def control_dependence(blocks: Sequence, successors: Callable, branches: Callable) -> dict[Hashable, frozenset]:
    """block -> the (branch address, 't' / 'f') it runs under directly. branches(block) is (address, true target,
    false target) for a block ending in a two-way branch, else None. A block depends on an arm when it post-dominates
    the arm's target but not, strictly, the branch: the post-dominator tree's path from the target up to the branch's
    own immediate post-dominator"""
    ipdom = immediate_post_dominators(blocks, successors)
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
