"""Formatter for ED9 VM disassembly output"""

from common import *
from typing import TYPE_CHECKING, Callable
from dataclasses import dataclass

from .instruction_table import OperandType
from .ed9_optable import ED9OperandType

if TYPE_CHECKING:
    from .basic_block import BasicBlock
    from .instruction import Instruction
    from ..parser.types_parser import Function

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

    def format_entry_block(self, entry_block: 'BasicBlock', unreachable_blocks: 'list[BasicBlock]' = ()) -> list[str]:
        """Format blocks starting from entry block (without function header), plus unreachable blocks in offset order"""
        # Reset formatted tracking
        self.formatted_offsets.clear()
        self.formatted_labels.clear()
        self.unreachable_targets = {target for block in unreachable_blocks for target in self.branch_targets(block)}

        # Collect all blocks
        blocks = self.collect_blocks(entry_block) + list(unreachable_blocks)
        unreachable_ids = {id(block) for block in unreachable_blocks}  # BasicBlock is an unhashable dataclass

        # Sort by offset
        blocks.sort(key = lambda b: b.offset)

        # Format all blocks
        lines = []
        for block in blocks:
            if id(block) in unreachable_ids:
                block_lines = [UNREACHABLE_CODE_BEGIN, *self.format_block(block, gen_label = False, unreachable = True), UNREACHABLE_CODE_END]

            else:
                block_lines = self.format_block(block, gen_label = block is not entry_block)

            lines.extend(self.indent + line for line in block_lines)
            if lines and lines[-1] != '':
                lines.append('')

        # Remove trailing empty line
        if lines and lines[-1] == '':
            lines.pop()

        return lines

    def format_function(self, func: 'Function') -> list[str]:
        """Format a complete function with header"""
        lines = []
        param_names = []
        for i, param in enumerate(func.params):
            param_name = f'arg{i + 1}: {param.type.get_python_type()}'
            if param.default_value is not None:
                param_name += f' = {param.default_value.value!r}'

            param_names.append(param_name)

        param_str = ', '.join(param_names)
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

    def format_block(self, block: 'BasicBlock', gen_label: bool = True, unreachable: bool = False) -> list[str]:
        """Format block instructions"""
        lines = []

        if not block.instructions:
            return lines

        # Generate label if needed
        if gen_label and block.name and block.name not in self.formatted_labels:
            self.formatted_labels.add(block.name)
            lines.extend(self._format_label(block.name))
            lines.append('')

        # Format instructions
        for inst in block.instructions:
            # Synthetic fall-through JMP added when a block is split - not in the bytecode
            if inst.size == 0:
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

            # Format instruction with context
            formatted = inst.descriptor.format_instruction(inst, self.context)

            if inst.operands and inst.operands[0].descriptor.type == ED9OperandType.GlobalVar:
                formatted += f'{GLOBAL_VAR_INDEX_COMMENT} {inst.operands[0].value}'

            lines.append(formatted)

        return lines

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
    def branch_targets(cls, block: 'BasicBlock') -> list[int]:
        """Offset operands of a block's instructions"""
        return [operand.value for inst in block.instructions for operand in inst.operands if operand.descriptor.type == OperandType.Offset]

    def _format_label(self, name: str, comment: str = '') -> list[str]:
        """Format a label"""
        return [
            f'def _{name}(): pass',
            # '',
            f"label('{name}'){comment}",
        ]
