"""Formatter for ED9 VM disassembly output"""

from typing import TYPE_CHECKING, Callable
from dataclasses import dataclass

from dc3 import default_indent
from ir.llil.llil import default_label_for_addr
from assembler.instruction import SYNTHETIC_INSTRUCTION_SIZE
from assembler.instruction_table import OperandType
from .llil_dsl_comments import (
    UNREACHABLE_TARGET_COMMENT, CommentOptions, append_comment, function_comments, instruction_comments, label_comments,
)
from ..structs.scp_types import ScpValue

if TYPE_CHECKING:
    from assembler.basic_block import BasicBlock
    from assembler.instruction import Instruction
    from ..parser.parser_types import Function, FunctionParam, StackLayout

__all__ = (
    'Formatter',
    'FormatterContext',
)

UNREACHABLE_CODE_BEGIN      = '# --- unreachable code ---'
UNREACHABLE_CODE_END        = '# --- end unreachable code ---'


@dataclass
class FormatterContext:
    """Context for formatter with callbacks"""

    get_func_name_from_func_id: Callable[[int], str | None] | None = None  # func_id -> func_name
    get_global_name_from_index: Callable[[int], str | None] | None = None  # global var index -> name
    comments: CommentOptions = CommentOptions()                             # which optional comments the .py gets


class Formatter:
    """Format disassembled code for output"""

    def __init__(self, context: FormatterContext):
        self.context = context
        self.indent = default_indent()
        self.formatted_offsets: set[int] = set()
        self.formatted_labels: set[str] = set()
        self.unreachable_targets: set[int] = set()   # offsets unreachable code branches to - each needs a label
        self.referenced_offsets: set[int] = set()    # offsets real reachable-code operands point at - each needs a label
        self.layout: StackLayout | None = None       # the stack and argument comments' source
        self.call_debug_argc: dict[int, int] = {}    # CALL offset -> args its debug record keeps, off the compiler's rule
        self.call_unrecorded: set[int] = set()       # CALL offsets without a debug record

    def format_entry_block(self, entry_block: 'BasicBlock', unreachable_blocks: 'list[BasicBlock]' = (),
                           layout: 'StackLayout | None' = None, call_debug_argc: dict[int, int] | None = None,
                           call_unrecorded: set[int] | None = None) -> list[str]:
        """Format blocks starting from entry block (without function header), plus unreachable blocks in offset order;
        layout gives the stack and argument comments, call_debug_argc the CALLs that write their debug_argc,
        call_unrecorded those that write debug_record=False"""
        self.formatted_offsets.clear()
        self.formatted_labels.clear()
        self.unreachable_targets = {target for block in unreachable_blocks for target in self.branch_targets(block)}
        self.layout = layout
        self.call_debug_argc = call_debug_argc or {}
        self.call_unrecorded = call_unrecorded or set()

        # Collect reachable blocks and every offset a real instruction's Offset operand points at -
        # only those offsets earn a label, so a JMP/POP_JMP_*/PUSH_RET_ADDR/PUSH_CALLER_FRAME target
        # always resolves, and the synthetic fall-through block after a conditional branch (referenced by
        # nothing) does not
        reachable_blocks = self.collect_blocks(entry_block)
        self.referenced_offsets = self.find_referenced_offsets(entry_block, reachable_blocks=reachable_blocks)

        blocks = reachable_blocks + list(unreachable_blocks)
        unreachable = set(unreachable_blocks)

        blocks.sort(key=lambda b: b.offset)

        lines = []
        for block in blocks:
            if block in unreachable:
                block_lines = [UNREACHABLE_CODE_BEGIN, *self.format_block(block, unreachable=True),
                               UNREACHABLE_CODE_END]
            else:
                block_lines = self.format_block(block)

            lines.extend(self.indent + line if line else line for line in block_lines)
            if lines and lines[-1] != '':
                lines.append('')

        if lines and lines[-1] == '':
            lines.pop()

        return lines

    def format_function(self, func: 'Function') -> list[str]:
        """Format a complete function with header"""
        lines = function_comments(func, self.context.comments)
        param_str = ', '.join(self.format_param(i, param) for i, param in enumerate(func.params))
        decorator = 'LLILCommonCode' if func.is_common_func else 'LLILCode'
        lines.append(f'@scena.{decorator}()')
        lines.append(f'def {func.name}({param_str}):')
        lines.extend(self.format_entry_block(func.entry_block, func.unreachable_blocks, func.stack_layout,
                                             func.call_debug_argc, func.call_unrecorded))

        return lines

    def format_block(self, block: 'BasicBlock', unreachable: bool = False) -> list[str]:
        """Format block instructions"""
        lines = []

        if not block.instructions:
            return lines

        # Generate label only when this block's start is actually referenced by something
        if not unreachable and block.offset in self.referenced_offsets:
            lines.extend(self._format_label_once(block.offset))

        for inst in block.instructions:
            # Synthetic fall-through JMP added when a block is split - not in the bytecode
            if inst.size == SYNTHETIC_INSTRUCTION_SIZE:
                continue

            if inst.offset in self.formatted_offsets:
                continue

            self.formatted_offsets.add(inst.offset)

            # Branch target of unreachable code that no block label covers
            if inst.offset in self.unreachable_targets:
                lines.extend(self._format_label_once(inst.offset, () if unreachable else (UNREACHABLE_TARGET_COMMENT,)))

            formatted = inst.descriptor.format_instruction(inst, self.context)
            debug_argc = self.call_debug_argc.get(inst.offset)
            if debug_argc is not None:
                # Inside the CALL's parentheses: CALL(f) -> CALL(f, debug_argc=2)
                formatted = f'{formatted[:-1]}, debug_argc={debug_argc})'
            elif inst.offset in self.call_unrecorded:
                formatted = f'{formatted[:-1]}, debug_record=False)'

            lines.append(append_comment(formatted, instruction_comments(self.layout, inst, self.context.comments)))

        return lines

    @classmethod
    def format_param(cls, index: int, param: 'FunctionParam') -> str:
        """'argN: Type' or 'argN: Type = default' for one parameter (1-indexed, matching the DSL's
        own param naming) - shared by format_function and the common-function generator, which must
        render parameters identically since a divergent-signature function stays inline precisely
        when this rendering would differ"""
        text = f'arg{index + 1}: {param.type.get_python_type()}'
        if param.default_value is not None:
            default = param.default_value.value
            default_text = ScpValue.float_literal(default) if isinstance(default, float) else repr(default)
            text += f' = {default_text}'

        return text

    @classmethod
    def reachable_instructions(cls, entry_block: 'BasicBlock') -> list['Instruction']:
        """Reachable instructions in offset order, deduplicated and with synthetic fall-through
        JMPs removed - the flat view of collect_blocks() that ScpParser.get_instructions and the
        common-function generator both need instead of walking blocks themselves"""
        instructions = {}
        for block in cls.collect_blocks(entry_block):
            for inst in block.instructions:
                # Synthetic fall-through JMPs have no bytes and can share an offset with a real instruction
                if inst.size == SYNTHETIC_INSTRUCTION_SIZE:
                    continue

                instructions.setdefault(inst.offset, inst)

        return [instructions[offset] for offset in sorted(instructions)]

    @classmethod
    def find_referenced_offsets(cls, entry_block: 'BasicBlock', *,
                                reachable_blocks: 'list[BasicBlock] | None' = None) -> set[int]:
        """Offsets a real (non-synthetic) Offset operand points at, among reachable blocks - each
        one needs a label. Each starts a reachable block, as every branch target and return address does"""
        if reachable_blocks is None:
            reachable_blocks = cls.collect_blocks(entry_block)

        return {target for block in reachable_blocks for target in cls.branch_targets(block, real_only=True)}

    @classmethod
    def collect_blocks(cls, entry: 'BasicBlock') -> list['BasicBlock']:
        """Collect all blocks reachable from entry"""
        blocks = []
        visited = set()
        todo = [entry]

        while todo:
            block = todo.pop()
            if block.offset in visited:
                continue

            visited.add(block.offset)
            blocks.append(block)
            todo.extend(block.succs)

        return blocks

    @classmethod
    def branch_targets(cls, block: 'BasicBlock', real_only: bool = False) -> list[int]:
        """Offset operands of a block's instructions (real_only skips synthetic fall-through jumps)"""
        return [
            operand.value
            for inst in block.instructions
            if not real_only or inst.size != SYNTHETIC_INSTRUCTION_SIZE
            for operand in inst.operands
            if operand.descriptor.type == OperandType.Offset
        ]

    def _format_label_once(self, offset: int, notes: tuple[str, ...] = ()) -> list[str]:
        """A label with the depth there, notes and a blank line, added to formatted_labels; [] if already there"""
        name = default_label_for_addr(offset)
        if name in self.formatted_labels:
            return []

        self.formatted_labels.add(name)
        return [
            f'def _{name}(): pass',
            append_comment(f"label('{name}')", [*label_comments(self.layout, offset, self.context.comments), *notes]),
            '',
        ]
