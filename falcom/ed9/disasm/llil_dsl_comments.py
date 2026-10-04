"""Comments of the LLIL DSL (.py): the global var index, what each stack slot holds and which argument each push
becomes (read from the parser's StackLayout), float bits and function ids; trailing comments share one column"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from common.utils import display_width
from ir.llil import WORD_SIZE
from .ed9_optable import ED9Opcode, ED9OperandType
from ..parser.types_scp import ScpValue

if TYPE_CHECKING:
    from .instruction import Instruction
    from ..parser.types_parser import Function, StackLayout

__all__ = (
    'CommentOptions',
    'append_comment',
    'function_comments',
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
    float_bits      : bool = False  # PUSH_FLOAT's float32 bits and stored word
    function_ids    : bool = False  # a line above each function with its table index and code offset
    call_args       : bool = False  # the argument each push becomes, numbered like the callee (arg1 = the last push)


def function_comments(func: 'Function', options: CommentOptions) -> list[str]:
    """The comment lines above a function; none for a function without a table index (hand-built)"""
    if not options.function_ids or func.index is None:
        return []

    return [f'# id: 0x{func.index:04X} offset: 0x{func.offset:X}']


def instruction_comments(layout: 'StackLayout | None', inst: 'Instruction', options: CommentOptions) -> list[str]:
    """Every trailing comment of an instruction line, in order: the global var index, the stack parts, the call
    arguments, the float bits. The stack and argument parts need the layout's state, so unreachable code gets none"""
    comments = []
    if inst.operands and inst.operands[0].descriptor.type == ED9OperandType.GlobalVar:
        comments.append(f'{GLOBAL_VAR_INDEX_COMMENT} {inst.operands[0].value}')

    has_state = layout is not None and inst.offset in layout.sp_before
    if has_state and options.stack_slots:
        comments.extend(stack_comments(layout, inst))

    if has_state and options.call_args and inst.offset in layout.arg_numbers:
        arguments = ', '.join(f'arg{number}' for number in layout.arg_numbers[inst.offset])
        slot_shown = options.stack_slots and inst.offset in layout.slot_refs
        comments.append(f'passed as {arguments}' if slot_shown else arguments)

    if options.float_bits and inst.opcode == ED9Opcode.PUSH_FLOAT:
        comments.append(ScpValue.float_bits_text(inst.operands[0].value))

    return comments


def stack_comments(layout: 'StackLayout', inst: 'Instruction') -> list[str]:
    """The slot an offset opcode addresses and what it holds, the opening of an addressed local, POP's slot count"""
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


def label_comments(layout: 'StackLayout | None', offset: int, options: CommentOptions) -> list[str]:
    """The depth at a label; none where the layout has no state or the stack comments are off"""
    if not options.stack_slots or layout is None or offset not in layout.sp_before:
        return []

    return [f'sp = {layout.sp_before[offset]}']


def append_comment(text: str, comments: list[str]) -> str:
    """text with its comments at COMMENT_COLUMN, counted in display columns (CJK characters take two)"""
    if not comments:
        return text

    gap = max(COMMENT_COLUMN - display_width(text), MIN_COMMENT_GAP)
    return f'{text}{" " * gap}# {", ".join(comments)}'
