"""Basic Block representation"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dc3 import default_indent, IntEnum2

if TYPE_CHECKING:
    from .instruction import Instruction


class BranchKind(IntEnum2):
    """Type of control flow edge"""

    UNCONDITIONAL   = 0     # JMP, CALL return
    TRUE            = 1     # Conditional branch taken
    FALSE           = 2     # Conditional branch not taken


@dataclass(eq=False)
class BasicBlock:
    """Basic block in control flow graph, compared and hashed by identity"""

    offset          : int                                                   # Starting offset
    name            : str                 = ''                              # Block label (e.g., 'loc_1234')
    instructions    : 'list[Instruction]' = field(default_factory=list)
    succs           : list[BasicBlock]  = field(default_factory=list)     # All successors
    true_succs      : list[BasicBlock]  = field(default_factory=list)     # True branch successors
    false_succs     : list[BasicBlock]  = field(default_factory=list)     # False branch successors

    def __post_init__(self):
        if not self.name:
            self.name = f'loc_{self.offset:X}'

    @property
    def terminal(self) -> 'Instruction | None':
        """Terminal instruction (last instruction in block)"""
        return self.instructions[-1] if self.instructions else None

    def add_branch(self, target: BasicBlock, kind: BranchKind | None = None):
        """Add a branch to target block"""
        if target not in self.succs:
            self.succs.append(target)

        if kind == BranchKind.TRUE and target not in self.true_succs:
            self.true_succs.append(target)
        elif kind == BranchKind.FALSE and target not in self.false_succs:
            self.false_succs.append(target)

    def insert_branch(self, target: BasicBlock) -> BasicBlock:
        """Insert branch at beginning of successors list"""
        if target not in self.succs:
            self.succs.insert(0, target)

        return target

    def __str__(self) -> str:
        indent = default_indent()
        lines = [f'BasicBlock {self.name} @ 0x{self.offset:X}']
        for inst in self.instructions:
            lines.append(f'{indent}{inst.offset:08X}: {inst}')

        if self.succs:
            succ_names = ', '.join(b.name for b in self.succs)
            lines.append(f'{indent}→ {succ_names}')

        return '\n'.join(lines)
