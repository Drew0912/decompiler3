"""Trailing comments of the LLIL DSL (.py): what each stack slot holds, read from the parser's StackLayout, in one
column"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from common.utils import display_width
from ir.llil import WORD_SIZE
from .ed9_optable import ED9Opcode

if TYPE_CHECKING:
    from .instruction import Instruction
    from ..parser.types_parser import StackLayout

__all__ = (
    'CommentOptions',
    'append_comment',
    'instruction_comments',
    'label_comments',
)

COMMENT_COLUMN  = 32    # display column of every trailing comment, after the indent
MIN_COMMENT_GAP = 2     # spaces before the comment of a line that reaches the column

GLOBAL_VAR_INDEX_COMMENT    = 'global var'                       # + the index, on LOAD_GLOBAL/SET_GLOBAL and GLOBAL_VAR
UNREACHABLE_TARGET_COMMENT  = 'jumped to by unreachable code'    # on a label in reachable code

# Offset opcodes that read or write through the slot (*) or push its address (&)
SLOT_PREFIXES = {
    ED9Opcode.LOAD_STACK_DEREF  : '*',
    ED9Opcode.POP_TO_DEREF      : '*',
    ED9Opcode.PUSH_STACK_OFFSET : '&',
}


@dataclass(frozen = True)
class CommentOptions:
    """Which optional comments the .py gets"""
    stack_slots     : bool = True   # each offset opcode's slot and what it holds, addressed locals, POP's slots, sp at labels


def instruction_comments(layout: 'StackLayout | None', inst: 'Instruction') -> list[str]:
    """The stack comments of one instruction; none where the layout has no state (unreachable code, a function without
    a layout)"""
    if layout is None or inst.offset not in layout.sp_before:
        return []

    comments = []
    ref = layout.slot_refs.get(inst.offset)
    if ref is not None:
        comments.append(f'{SLOT_PREFIXES.get(inst.opcode, "")}{ref}')

    if inst.offset in layout.local_slots:
        comments.append(f'slot {layout.local_slots[inst.offset]} (local)')

    if inst.opcode == ED9Opcode.POP:
        count = inst.operands[0].value // WORD_SIZE
        comments.append(f'{count} slot' if count == 1 else f'{count} slots')

    return comments


def label_comments(layout: 'StackLayout | None', offset: int) -> list[str]:
    """The depth at a label; none where the layout has no state"""
    if layout is None or offset not in layout.sp_before:
        return []

    return [f'sp = {layout.sp_before[offset]}']


def append_comment(text: str, comments: list[str]) -> str:
    """text with its comments at COMMENT_COLUMN, counted in display columns (CJK characters take two)"""
    if not comments:
        return text

    gap = max(COMMENT_COLUMN - display_width(text), MIN_COMMENT_GAP)
    return f'{text}{" " * gap}# {", ".join(comments)}'
