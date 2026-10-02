"""Formatter for ED9 VM disassembly output"""

from common import *
from typing import TYPE_CHECKING, Callable
from dataclasses import dataclass

from .instruction import SYNTHETIC_INSTRUCTION_SIZE
from .instruction_table import OperandType
from .ed9_optable import ED9OperandType

if TYPE_CHECKING:
    from .basic_block import BasicBlock
    from .instruction import Instruction
    from ..parser.types_parser import Function, FunctionParam

__all__ = (
    'Formatter',
    'FormatterContext',
)

UNREACHABLE_CODE_BEGIN      = '# --- unreachable code ---'
UNREACHABLE_CODE_END        = '# --- end unreachable code ---'
UNREACHABLE_TARGET_COMMENT  = '  # jumped to by unreachable code'
GLOBAL_VAR_INDEX_COMMENT    = '  # global var'


@dataclass
class FormatterContext:
    """Context for formatter with callbacks"""
    get_func_name_from_func_id: Callable[[int], str | None] | None = None  # func_id -> func_name
    get_global_name_from_index: Callable[[int], str | None] | None = None  # global var index -> name


class Formatter:
    """Format disassembled code for output"""

    def __init__(self, context: FormatterContext, indent: str | None = None):
        self.context = context
        self.indent = indent if indent is not None else default_indent()
        self.formatted_offsets: set[int] = set()
        self.formatted_labels: set[str] = set()
        self.unreachable_targets: set[int] = set()   # offsets unreachable code branches to - each needs a label
        self.referenced_offsets: set[int] = set()    # offsets real reachable-code operands point at - each needs a label

    def format_entry_block(self, entry_block: 'BasicBlock', unreachable_blocks: 'list[BasicBlock]' = ()) -> list[str]:
        """Format blocks starting from entry block (without function header), plus unreachable blocks in offset order"""
        # Reset formatted tracking
        self.formatted_offsets.clear()
        self.formatted_labels.clear()
        self.unreachable_targets = {target for block in unreachable_blocks for target in self.branch_targets(block)}

        # Collect reachable blocks and every offset a real instruction's Offset operand points at -
        # only those offsets earn a label, so a JMP/POP_JMP_*/PUSH_RET_ADDR/PUSH_CALLER_FRAME target
        # (or debug_argc key, which is always one of those) always resolves, and the synthetic
        # fall-through block after a conditional branch (referenced by nothing) does not.
        reachable_blocks = self.collect_blocks(entry_block)
        self.referenced_offsets = self.find_referenced_offsets(entry_block, reachable_blocks = reachable_blocks)

        # The disassembler always splits a block when something jumps into its middle, so a
        # referenced offset should always be some block's start. Assert that invariant here for an
        # immediate signal if it ever breaks; format_block's per-instruction loop still emits an
        # inline label at the actual reference point regardless, so a reference can never go
        # undefined even if this assert is stripped (-O) or the invariant is ever wrong.
        block_start_offsets = {block.offset for block in reachable_blocks}
        assert self.referenced_offsets <= block_start_offsets, \
            f'referenced offset(s) not at a block start: {sorted(self.referenced_offsets - block_start_offsets)}'

        # Collect all blocks
        blocks = reachable_blocks + list(unreachable_blocks)
        unreachable_ids = {id(block) for block in unreachable_blocks}  # BasicBlock is an unhashable dataclass

        # Sort by offset
        blocks.sort(key = lambda b: b.offset)

        # Format all blocks
        lines = []
        for block in blocks:
            if id(block) in unreachable_ids:
                block_lines = [UNREACHABLE_CODE_BEGIN, *self.format_block(block, unreachable = True), UNREACHABLE_CODE_END]

            else:
                block_lines = self.format_block(block)

            lines.extend(self.indent + line if line else line for line in block_lines)
            if lines and lines[-1] != '':
                lines.append('')

        # Remove trailing empty line
        if lines and lines[-1] == '':
            lines.pop()

        return lines

    def format_function(self, func: 'Function') -> list[str]:
        """Format a complete function with header"""
        lines = []
        param_str = ', '.join(self.format_param(i, param) for i, param in enumerate(func.params))
        decorator = 'LLILCommonCode' if func.is_common_func else 'LLILCode'

        if func.call_debug_argc:
            lines.append(f'@scena.{decorator}(debug_argc = {{')
            lines.extend(f"{self.indent}'{label}': {argc}," for label, argc in func.call_debug_argc.items())
            lines.append('})')

        else:
            lines.append(f'@scena.{decorator}()')

        lines.append(f'def {func.name}({param_str}):')

        block_lines = self.format_entry_block(func.entry_block, func.unreachable_blocks)
        lines.extend(block_lines)

        return lines

    def format_block(self, block: 'BasicBlock', unreachable: bool = False) -> list[str]:
        """Format block instructions"""
        lines = []

        if not block.instructions:
            return lines

        # Generate label only when this block's start is actually referenced by something
        label_name = f'loc_{block.offset:X}'
        if not unreachable and block.offset in self.referenced_offsets and label_name not in self.formatted_labels:
            self.formatted_labels.add(label_name)
            lines.extend(self._format_label(label_name))
            lines.append('')

        # Format instructions
        for inst in block.instructions:
            # Synthetic fall-through JMP added when a block is split - not in the bytecode
            if inst.size == SYNTHETIC_INSTRUCTION_SIZE:
                continue

            if inst.offset in self.formatted_offsets:
                continue

            self.formatted_offsets.add(inst.offset)

            # Branch target of unreachable code that no block label covers
            target_label = f'loc_{inst.offset:X}'
            if inst.offset in self.unreachable_targets and target_label not in self.formatted_labels:
                self.formatted_labels.add(target_label)
                comment = '' if unreachable else UNREACHABLE_TARGET_COMMENT
                lines.extend(self._format_label(target_label, comment))
                lines.append('')

            # Fallback for the (census-verified, never-observed) case where a referenced offset
            # is not a block start - see the assert in format_entry_block. Not gated on
            # `unreachable` (unlike the primary label above): a referenced offset could in
            # principle only be reachable via the unreachable_blocks list rather than succs, so
            # this must still fire there too for the "never go undefined" guarantee to hold.
            if inst.offset in self.referenced_offsets and target_label not in self.formatted_labels:
                self.formatted_labels.add(target_label)
                lines.extend(self._format_label(target_label))
                lines.append('')

            # Format instruction with context
            formatted = inst.descriptor.format_instruction(inst, self.context)

            if inst.operands and inst.operands[0].descriptor.type == ED9OperandType.GlobalVar:
                formatted += f'{GLOBAL_VAR_INDEX_COMMENT} {inst.operands[0].value}'

            lines.append(formatted)

        return lines

    @classmethod
    def format_param(cls, index: int, param: 'FunctionParam') -> str:
        """'argN: Type' or 'argN: Type = default' for one parameter (1-indexed, matching the DSL's
        own param naming) - shared by format_function and the common-function generator, which must
        render parameters identically since a divergent-signature function stays inline precisely
        when this rendering would differ."""
        text = f'arg{index + 1}: {param.type.get_python_type()}'
        if param.default_value is not None:
            text += f' = {param.default_value.value!r}'

        return text

    @classmethod
    def reachable_instructions(cls, entry_block: 'BasicBlock') -> list['Instruction']:
        """Reachable instructions in offset order, deduplicated and with synthetic fall-through
        JMPs removed - the flat view of collect_blocks() that ScpParser.get_instructions and the
        common-function generator both need instead of walking blocks themselves."""
        instructions = {}
        for block in cls.collect_blocks(entry_block):
            for inst in block.instructions:
                # Synthetic fall-through JMPs have no bytes and can share an offset with a real instruction
                if inst.size == SYNTHETIC_INSTRUCTION_SIZE:
                    continue

                instructions.setdefault(inst.offset, inst)

        return [instructions[offset] for offset in sorted(instructions)]

    @classmethod
    def find_referenced_offsets(cls, entry_block: 'BasicBlock', *, reachable_blocks: 'list[BasicBlock] | None' = None) -> set[int]:
        """Offsets a real (non-synthetic) Offset operand points at, among reachable blocks - each
        one needs a label. Every one is guaranteed to land on some reachable block's start (see the
        assert in format_entry_block, which computes this same set for its own use)."""
        if reachable_blocks is None:
            reachable_blocks = cls.collect_blocks(entry_block)

        return {target for block in reachable_blocks for target in cls.branch_targets(block, real_only = True)}

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

    def _format_label(self, name: str, comment: str = '') -> list[str]:
        """Format a label"""
        return [
            f'def _{name}(): pass',
            f"label('{name}'){comment}",
        ]
