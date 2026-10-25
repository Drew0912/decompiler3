"""Control-flow graph orders, over any block type: the caller names a block's successors"""

from typing import Callable, Sequence

__all__ = ['reverse_post_order']


def reverse_post_order[Block](entry: Block, successors: Callable[[Block], Sequence[Block]]) -> list[Block]:
    """Every block reachable from entry, in reverse post-order of a depth-first walk over successors(block) in their
    order: each block but entry comes after at least one of its predecessors"""
    visited = set()
    postorder = []
    stack = [(entry, False)]

    while stack:
        block, processed = stack.pop()

        if processed:
            postorder.append(block)
            continue

        if block in visited:
            continue

        visited.add(block)
        stack.append((block, True))

        for succ in reversed(successors(block)):
            if succ not in visited:
                stack.append((succ, False))

    return list(reversed(postorder))
