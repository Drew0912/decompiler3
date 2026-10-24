"""The statement printer HLIL's two text outputs share: the debug dump (hlil_formatter.py) and the TypeScript
generator (codegen/typescript.py)"""

from typing import List, Optional, Tuple

from dc3 import default_indent
from .hlil import *


class HLILStatementPrinter:
    """Statements and blocks as text; a subclass prints expressions its own way (_format_expr) and fills in the
    statements whose text differs (_format_assign, _format_unstructured, and where it differs, _if_arms and
    CASE_BLOCKS)"""

    # Whether a switch case's body is a block of its own: `case 1: {` ... `}`
    CASE_BLOCKS = False

    @classmethod
    def _format_expr(cls, expr: HLILExpression) -> str:
        raise NotImplementedError

    @classmethod
    def _format_assign(cls, stmt: HLILAssign) -> str:
        raise NotImplementedError

    @classmethod
    def _format_unstructured(cls, stmt: HLILUnstructured) -> List[str]:
        raise NotImplementedError

    @classmethod
    def _if_arms(cls, stmt: HLILIf) -> Tuple[HLILExpression, HLILBlock, Optional[HLILBlock]]:
        """The condition and arms an if prints with"""
        return stmt.condition, stmt.true_block, stmt.false_block

    @classmethod
    def _format_block(cls, block: HLILBlock, indent: int = 0) -> List[str]:
        return [line for stmt in block.statements for line in cls._format_statement(stmt, indent)]

    @classmethod
    def _format_if_chain(cls, stmt: HLILIf, indent: int) -> List[str]:
        """if / else if / else"""
        indent_str = default_indent() * indent
        condition, true_block, false_block = cls._if_arms(stmt)
        lines = [f'{indent_str}if ({cls._format_expr(condition)}) {{']
        lines.extend(cls._format_block(true_block, indent + 1))

        while false_block and false_block.statements:
            # else { [comments] single if } -> [comments] else if
            arm = split_else_if_arm(false_block)
            if arm is None:
                lines.append(f'{indent_str}}} else {{')
                lines.extend(cls._format_block(false_block, indent + 1))
                break

            comments, inner_if = arm
            for comment in comments:
                lines.extend(cls._format_statement(comment, indent))

            lines.append(f'{indent_str}}} else if ({cls._format_expr(inner_if.condition)}) {{')
            lines.extend(cls._format_block(inner_if.true_block, indent + 1))
            false_block = inner_if.false_block

        lines.append(f'{indent_str}}}')
        return lines

    @classmethod
    def _format_switch(cls, stmt: HLILSwitch, indent: int) -> List[str]:
        indent_str = default_indent() * indent
        case_indent = indent_str + default_indent()
        lines = [f'{indent_str}switch ({cls._format_expr(stmt.scrutinee)}) {{']

        for case in stmt.cases:
            # Labels sharing a body stack; with CASE_BLOCKS the last one opens the block
            if case.is_default():
                labels = ['default:']
            else:
                labels = [f'case {cls._format_expr(value)}:' for value in case.values]

            if cls.CASE_BLOCKS:
                labels[-1] += ' {'

            lines.extend(f'{case_indent}{label}' for label in labels)
            lines.extend(cls._format_block(case.body, indent + 2))

            # A break unless the case ends in a terminal statement - an empty case included, which would otherwise
            # fall through into the next case instead of doing nothing
            last_stmt = case.body.statements[-1] if case.body.statements else None
            if not isinstance(last_stmt, TERMINAL_STATEMENTS):
                lines.append(f'{case_indent}{default_indent()}break;')

            if cls.CASE_BLOCKS:
                lines.append(f'{case_indent}}}')

        lines.append(f'{indent_str}}}')
        return lines

    @classmethod
    def _format_statement(cls, stmt: HLILStatement, indent: int = 0) -> List[str]:
        indent_str = default_indent() * indent
        lines = []

        if isinstance(stmt, HLILIf):
            lines.extend(cls._format_if_chain(stmt, indent))
        elif isinstance(stmt, HLILWhile):
            # while (condition) { ... }, optionally labeled
            cond_str = cls._format_expr(stmt.condition)
            label_prefix = f'{stmt.label}: ' if stmt.label else ''
            lines.append(f'{indent_str}{label_prefix}while ({cond_str}) {{')
            lines.extend(cls._format_block(stmt.body, indent + 1))
            lines.append(f'{indent_str}}}')
        elif isinstance(stmt, HLILDoWhile):
            # do { ... } while (condition);, optionally labeled
            cond_str = cls._format_expr(stmt.condition)
            label_prefix = f'{stmt.label}: ' if stmt.label else ''
            lines.append(f'{indent_str}{label_prefix}do {{')
            lines.extend(cls._format_block(stmt.body, indent + 1))
            lines.append(f'{indent_str}}} while ({cond_str});')
        elif isinstance(stmt, HLILSwitch):
            lines.extend(cls._format_switch(stmt, indent))
        elif isinstance(stmt, (HLILBreak, HLILContinue)):
            keyword = 'break' if isinstance(stmt, HLILBreak) else 'continue'
            label = f' {stmt.label}' if stmt.label else ''
            lines.append(f'{indent_str}{keyword}{label};')
        elif isinstance(stmt, HLILReturn):
            if stmt.value is not None:
                value_str = cls._format_expr(stmt.value)
                lines.append(f'{indent_str}return {value_str};')
            else:
                lines.append(f'{indent_str}return;')
        elif isinstance(stmt, HLILUnstructured):
            lines.extend(f'{indent_str}{line}' for line in cls._format_unstructured(stmt))
        elif isinstance(stmt, HLILAssign):
            lines.append(f'{indent_str}{cls._format_assign(stmt)}')
        elif isinstance(stmt, HLILExprStmt):
            expr_str = cls._format_expr(stmt.expr)
            lines.append(f'{indent_str}{expr_str};')
        elif isinstance(stmt, HLILComment):
            lines.append(f'{indent_str}// {stmt.text}')
        elif isinstance(stmt, HLILBlock):
            # Nested block
            lines.append(f'{indent_str}{{')
            lines.extend(cls._format_block(stmt, indent + 1))
            lines.append(f'{indent_str}}}')
        else:
            lines.append(f'{indent_str}// {stmt}')

        return lines
