"""Basic Block representation"""

from common import *
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .instruction import Instruction


class BranchKind(IntEnum2):
    """Type of control flow edge"""
    UNCONDITIONAL   = 0     # JMP, CALL return
    TRUE            = 1     # Conditional branch taken
    FALSE           = 2     # Conditional branch not taken


@dataclass
class BasicBlock:
    """Basic block in control flow graph"""
    start_offset    : int                                                  # Starting offset
    name            : str                 = ''                              # Block label (e.g., 'loc_1234')
    end_offset      : int                 = 0                               # End offset (exclusive, 0 means unset)
    instructions    : list['Instruction'] = field(default_factory = list)
    succs           : list['BasicBlock']  = field(default_factory = list)   # All successors
    true_succs      : list['BasicBlock']  = field(default_factory = list)   # True branch successors
    false_succs     : list['BasicBlock']  = field(default_factory = list)   # False branch successors
    preds           : list['BasicBlock']  = field(default_factory = list)   # All predecessors

    def __post_init__(self):
        if not self.name:
            self.name = f'loc_{self.start_offset:X}'

    @property
    def offset(self) -> int:
        """Alias for start_offset (for backward compatibility)"""
        return self.start_offset

    @property
    def computed_end_offset(self) -> int:
        """End offset (exclusive) - computed from instructions if end_offset not set"""
        if self.end_offset:
            return self.end_offset
        if self.instructions:
            last = self.instructions[-1]
            return last.offset + last.size
        return self.start_offset

    @property
    def terminal(self) -> 'Instruction | None':
        """Terminal instruction (last instruction in block)"""
        return self.instructions[-1] if self.instructions else None

    def add_branch(self, target: 'BasicBlock', kind: BranchKind | None = None) -> 'BasicBlock':
        """Add a branch to target block (maintains bidirectional edges)"""
        if target not in self.succs:
            self.succs.append(target)

        if kind == BranchKind.TRUE and target not in self.true_succs:
            self.true_succs.append(target)

        elif kind == BranchKind.FALSE and target not in self.false_succs:
            self.false_succs.append(target)

        # Maintain bidirectional edge
        if self not in target.preds:
            target.preds.append(self)

        return target

    def insert_branch(self, target: 'BasicBlock') -> 'BasicBlock':
        """Insert branch at beginning of successors list"""
        if target not in self.succs:
            self.succs.insert(0, target)

        # Maintain bidirectional edge
        if self not in target.preds:
            target.preds.append(self)

        return target

    def __str__(self) -> str:
        indent = default_indent()
        lines = [f'BasicBlock {self.name} @ 0x{self.start_offset:X}']
        for inst in self.instructions:
            lines.append(f'{indent}{inst.offset:08X}: {inst}')

        if self.succs:
            succ_names = ', '.join(b.name for b in self.succs)
            lines.append(f'{indent}→ {succ_names}')

        return '\n'.join(lines)
