"""The dead code the everyday decompile drops (bytes no branch reaches), and which of it is the compiler's own
boilerplate: the parser logs each function's at DEBUG when all of it is, else at INFO (docs/falcom/ed9/ED9_FORMAT.md,
Dead code)"""

from dataclasses import dataclass
import logging

from assembler import Instruction
from ..assembler.opcode_table import ED9Opcode

AFTER_TERMINATOR    = (ED9Opcode.RETURN, ED9Opcode.CALL_SCRIPT_NO_RETURN, ED9Opcode.JMP)
AFTER_TAIL_CALL     = (ED9Opcode.CALL_SCRIPT_NO_RETURN,)
AFTER_RETURN        = (ED9Opcode.RETURN,)

# The compiler's output where nothing reaches it, line markers left out, by the reachable instruction it may follow:
# trailing line markers and a statement's closing JMP after a terminator, its closing POP (POP JMP) after a RETURN,
# the function's closing return 0 after a tail call
BOILERPLATE = {
    ()                                                                          : AFTER_TERMINATOR,
    (ED9Opcode.JMP,)                                                            : AFTER_TERMINATOR,
    (ED9Opcode.POP,)                                                            : AFTER_RETURN,
    (ED9Opcode.POP, ED9Opcode.JMP)                                              : AFTER_RETURN,
    (ED9Opcode.PUSH_RAW, ED9Opcode.SET_REG, ED9Opcode.POP, ED9Opcode.RETURN)    : AFTER_TAIL_CALL,
    (ED9Opcode.PUSH_RAW, ED9Opcode.SET_REG, ED9Opcode.RETURN)                   : AFTER_TAIL_CALL,
}
BLOCKS_NAMED        = 3     # an INFO line names this many blocks that aren't boilerplate, then counts the rest


@dataclass(frozen=True, slots=True)
class DroppedBlock:
    """Bytes [start, end) no branch reaches, decoded linearly; instructions None when they aren't whole instructions"""

    start           : int
    end             : int
    after           : Instruction | None                # the reachable instruction right before it
    instructions    : tuple[Instruction, ...] | None

    def shape(self) -> tuple[int, ...]:
        """Its opcodes without the line markers"""
        return tuple(inst.opcode for inst in self.instructions if inst.opcode != ED9Opcode.DEBUG_SET_LINENO)

    def is_boilerplate(self) -> bool:
        if self.instructions is None or self.after is None:
            return False

        return self.after.opcode in BOILERPLATE.get(self.shape(), ())

    def shape_text(self) -> str:
        """A boilerplate block's mnemonics without the line markers: 'line markers' when it holds nothing else"""
        mnemonics = [inst.mnemonic for inst in self.instructions if inst.opcode != ED9Opcode.DEBUG_SET_LINENO]
        return ' '.join(mnemonics) or 'line markers'

    def description(self) -> str:
        """Where a block that isn't boilerplate starts, what it holds and what it follows"""
        after = '' if self.after is None else f', after {self.after.mnemonic}'
        if self.instructions is None:
            return f'{self.end - self.start} bytes from 0x{self.start:X}, not whole instructions{after}'

        count = len(self.instructions)
        return f'{count} instruction{'' if count == 1 else 's'} from 0x{self.start:X}{after}'


def dropped_code_message(blocks: list[DroppedBlock]) -> tuple[int, str]:
    """One function's dropped blocks as a log level and line: DEBUG naming the boilerplate's shapes when every block is
    boilerplate, else INFO naming the blocks that aren't"""
    size = sum(block.end - block.start for block in blocks)
    others = [block for block in blocks if not block.is_boilerplate()]
    if not others:
        shapes = ', '.join(dict.fromkeys(block.shape_text() for block in blocks))
        return logging.DEBUG, f'{size} unreachable bytes not decompiled (compiler boilerplate: {shapes})'

    named = '; '.join(block.description() for block in others[:BLOCKS_NAMED])
    more = f'; {len(others) - BLOCKS_NAMED} more' if len(others) > BLOCKS_NAMED else ''
    return logging.INFO, f'{size} unreachable bytes not decompiled ({named}{more})'
