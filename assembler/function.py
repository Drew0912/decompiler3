"""A disassembled function: its control flow graph from the entry block, and the code no branch reaches"""

from dataclasses import dataclass, field

from .basic_block import BasicBlock
from .instruction import SYNTHETIC_INSTRUCTION_SIZE, Instruction


@dataclass(eq=False, repr=False, slots=True)
class Function:
    """Compared and hashed by identity; slots, so a misspelt attribute raises instead of being set"""

    name                : str = ''
    offset              : int = 0
    entry_block         : BasicBlock | None = None
    unreachable_blocks  : list[BasicBlock] = field(default_factory=list)   # linearly decoded, not linked into the CFG

    def reachable_instructions(self) -> list[Instruction]:
        """Reachable instructions in offset order, deduplicated and without the synthetic fall-through jumps"""
        instructions = {}
        for block in self.entry_block.reachable_blocks():
            for inst in block.instructions:
                # Synthetic fall-through jumps have no bytes and can share an offset with a real instruction
                if inst.size == SYNTHETIC_INSTRUCTION_SIZE:
                    continue

                instructions.setdefault(inst.offset, inst)

        return [instructions[offset] for offset in sorted(instructions)]

    def unreachable_instructions(self) -> list[Instruction]:
        """The decoded unreachable code, block by block"""
        return [inst for block in self.unreachable_blocks for inst in block.instructions]

    def code_instructions(self) -> list[Instruction]:
        """Reachable instructions and the decoded unreachable code, in offset order"""
        return sorted(self.reachable_instructions() + self.unreachable_instructions(), key=lambda inst: inst.offset)
