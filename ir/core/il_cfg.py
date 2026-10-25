"""Control-flow graphs: the IL layers' block base, reverse post-order over any block type (the caller names a block's
successors) and the Graphviz DOT writer the layers' formatters share"""

from typing import Callable, Sequence

from .il_base import ILInstruction, Terminal

__all__ = ['ILBasicBlock', 'reverse_post_order', 'CFGDotFormatter']


class ILBasicBlock:
    """A basic block of an IL function: its instructions and its control-flow edges, each edge kept on both ends"""

    def __init__(self, index: int, start: int, label: str):
        self.index = index
        self.start = start
        self.label = label
        self.instructions: list[ILInstruction] = []
        self.incoming_edges: list[ILBasicBlock] = []
        self.outgoing_edges: list[ILBasicBlock] = []

    def add_instruction(self, inst: ILInstruction):
        self.instructions.append(inst)

    def add_outgoing_edge(self, target: ILBasicBlock):
        if target not in self.outgoing_edges:
            self.outgoing_edges.append(target)
        if self not in target.incoming_edges:
            target.incoming_edges.append(self)

    @property
    def has_terminal(self) -> bool:
        return bool(self.instructions) and isinstance(self.instructions[-1], Terminal)


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


class CFGDotFormatter:
    """A function's CFG as Graphviz DOT, one node per block; a layer's formatter names its branch classes (DOT_IF,
    DOT_GOTO, DOT_RETURN) and gives a node's header (_dot_header) and lines (_dot_lines)"""

    DOT_IF: type
    DOT_GOTO: type
    DOT_RETURN: type

    DOT_RULE_WIDTH = 40   # the rule under a node's header

    # Edge kind -> the attributes after its label
    DOT_EDGE_STYLES = {
        'true'         : ', color=green',
        'false'        : ', color=red',
        'goto'         : ', color=blue',
        'fall-through' : ', style=dashed',
    }

    @classmethod
    def _dot_header(cls, func, block: ILBasicBlock) -> str:
        raise NotImplementedError

    @classmethod
    def _dot_lines(cls, block: ILBasicBlock) -> list[str]:
        raise NotImplementedError

    @classmethod
    def _dot_edge_kind(cls, last_inst: ILInstruction | None, target: ILBasicBlock) -> str:
        """A branch's edge is its true or its false target: the CFG builders add no other"""
        if isinstance(last_inst, cls.DOT_IF):
            return 'true' if target == last_inst.true_target else 'false'

        if isinstance(last_inst, cls.DOT_GOTO):
            return 'goto'

        return 'fall-through'

    @classmethod
    def to_dot(cls, func) -> str:
        """Graphviz DOT for the CFG of func (either layer's function): the entry block green, a block that returns
        blue"""
        lines = [
            f'digraph "{func.name}" {{',
            '    rankdir=TB;',
            '    node [shape=box, fontname="Courier New", fontsize=10];',
            '    edge [fontname="Courier New", fontsize=9];',
            '',
        ]

        for block in func.basic_blocks:
            body = ''.join(line.replace('\\', '\\\\').replace('"', '\\"') + '\\l' for line in cls._dot_lines(block))
            label = f'{cls._dot_header(func, block)}\\l{'-' * cls.DOT_RULE_WIDTH}\\l{body}'

            if block.index == 0:
                style = ', style=filled, fillcolor=lightgreen'
            elif block.has_terminal and isinstance(block.instructions[-1], cls.DOT_RETURN):
                style = ', style=filled, fillcolor=lightblue'
            else:
                style = ''

            lines.append(f'    {block.block_name} [label="{label}"{style}];')

        lines.append('')

        for block in func.basic_blocks:
            last_inst = block.instructions[-1] if block.instructions else None

            for target in block.outgoing_edges:
                kind = cls._dot_edge_kind(last_inst, target)
                style = cls.DOT_EDGE_STYLES[kind]
                lines.append(f'    {block.block_name} -> {target.block_name} [label="{kind}"{style}];')

        lines.append('}')
        return '\n'.join(lines)
