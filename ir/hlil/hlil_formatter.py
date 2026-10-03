'''HLIL Formatter - Format HLIL for debugging'''

from common import *
from typing import List
from .hlil import *


class HLILFormatter:
    '''Format HLIL functions for debugging'''

    @classmethod
    def _format_expr(cls, expr: HLILExpression) -> str:
        '''Format an HLIL expression'''
        if isinstance(expr, HLILVar):
            return str(expr.var)  # Use __str__ to handle GLOBAL/REG properly

        elif isinstance(expr, HLILConst):
            # Handle different constant types
            if isinstance(expr.value, str):
                return f'"{expr.value}"'

            elif isinstance(expr.value, bool):
                return 'true' if expr.value else 'false'

            else:
                return str(expr.value)

        elif isinstance(expr, HLILBinaryOp):
            lhs_str = cls._format_expr(expr.lhs)
            rhs_str = cls._format_expr(expr.rhs)

            # Add parentheses if needed based on precedence
            if isinstance(expr.lhs, HLILBinaryOp) and needs_parentheses(expr.lhs.op, expr.op, True):
                lhs_str = f'({lhs_str})'

            if isinstance(expr.rhs, HLILBinaryOp) and needs_parentheses(expr.rhs.op, expr.op, False):
                rhs_str = f'({rhs_str})'

            return f'{lhs_str} {BINARY_OP_STR[expr.op]} {rhs_str}'

        elif isinstance(expr, HLILUnaryOp):
            operand = cls._format_expr(expr.operand)
            # Add parentheses around binary operands for clarity
            if isinstance(expr.operand, HLILBinaryOp):
                operand = f'({operand})'
            return f'{UNARY_OP_STR[expr.op]}{operand}'

        elif isinstance(expr, HLILAddressOf):
            operand = cls._format_expr(expr.operand)
            return f'&{operand}'

        elif isinstance(expr, HLILDeref):
            # *(&x) - ir/mlil/mlil_ssa.py's memory-form lowering of address-taken local x -
            # folds back to plain x, same convention as codegen/typescript.py
            unwrapped = unwrap_address_taken_var(expr)
            if unwrapped is not None:
                return cls._format_expr(unwrapped)

            operand = cls._format_expr(expr.operand)
            if isinstance(expr.operand, HLILBinaryOp):
                operand = f'({operand})'
            return f'*{operand}'

        elif isinstance(expr, HLILCall):
            args = ', '.join(cls._format_expr(arg) for arg in expr.args)
            return f'{expr.func_name}({args})'

        elif isinstance(expr, HLILSyscall):
            args = [
                f'{expr.subsystem}',
                f'{expr.cmd}',
                *[cls._format_expr(arg) for arg in expr.args],
            ]
            return f'syscall({', '.join(args)})'

        elif isinstance(expr, HLILExternCall):
            args = ', '.join(cls._format_expr(arg) for arg in expr.args)
            return f'{expr.target}({args})'

        else:
            # Fallback
            return str(expr)

    @classmethod
    def format_function(cls, func: HighLevelILFunction) -> List[str]:
        '''Format an HLIL function for debugging'''
        lines = []

        # Function header (simple, no types)
        params = ', '.join(p.name for p in func.parameters) if func.parameters else ''
        lines.append(f'function {func.name}({params}) {{')

        # Variables (simple declarations)
        if func.variables:
            for var in func.variables:
                lines.append(f'{default_indent()}var {var.name}')
            lines.append('')

        # Function body
        body_lines = cls._format_block(func.body, indent = 1)
        lines.extend(body_lines)

        lines.append('}')
        return lines

    @classmethod
    def _format_block(cls, block: HLILBlock, indent: int = 0) -> List[str]:
        '''Format a block of statements'''
        lines = []

        for stmt in block.statements:
            stmt_lines = cls._format_statement(stmt, indent)
            lines.extend(stmt_lines)

        return lines

    @classmethod
    def _format_if_chain(cls, if_stmt: HLILIf, indent: int) -> List[str]:
        '''Format if / else-if / else chain'''
        indent_str = default_indent() * indent
        lines = []

        # First if
        cond_str = cls._format_expr(if_stmt.condition)
        lines.append(f'{indent_str}if ({cond_str}) {{')
        lines.extend(cls._format_block(if_stmt.true_block, indent + 1))

        # Walk through else-if chain
        current_else = if_stmt.false_block
        while current_else and current_else.statements:
            # else { [comments] single if } -> [comments] else if, matching the TS codegen
            arm = split_else_if_arm(current_else)

            if arm is not None:
                comments, nested_if = arm

                for comment in comments:
                    lines.extend(cls._format_statement(comment, indent))

                cond_str = cls._format_expr(nested_if.condition)
                lines.append(f'{indent_str}}} else if ({cond_str}) {{')
                lines.extend(cls._format_block(nested_if.true_block, indent + 1))
                current_else = nested_if.false_block

            else:
                # Final else block
                lines.append(f'{indent_str}}} else {{')
                lines.extend(cls._format_block(current_else, indent + 1))
                break

        lines.append(f'{indent_str}}}')
        return lines

    @classmethod
    def _format_statement(cls, stmt: HLILStatement, indent: int = 0) -> List[str]:
        '''Format a statement'''
        indent_str = default_indent() * indent
        lines = []

        if isinstance(stmt, HLILIf):
            # if (condition) { ... } [else if (...) { ... }]* [else { ... }]
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
            # switch (scrutinee) { ... }
            scrutinee_str = cls._format_expr(stmt.scrutinee)
            lines.append(f'{indent_str}switch ({scrutinee_str}) {{')
            case_indent = default_indent()
            case_body_indent = default_indent() * 2
            for case in stmt.cases:
                if case.is_default():
                    lines.append(f'{indent_str}{case_indent}default:')
                else:
                    for value in case.values:
                        lines.append(f'{indent_str}{case_indent}case {cls._format_expr(value)}:')
                lines.extend(cls._format_block(case.body, indent + 2))

                # Add break unless the case ends in a terminal statement - an empty case
                # included, which would otherwise read as sharing the next case's body
                last_stmt = case.body.statements[-1] if case.body.statements else None
                if not isinstance(last_stmt, TERMINAL_STATEMENTS):
                    lines.append(f'{indent_str}{case_body_indent}break;')

            lines.append(f'{indent_str}}}')

        elif isinstance(stmt, HLILBreak):
            if stmt.label:
                lines.append(f'{indent_str}break {stmt.label};')
            else:
                lines.append(f'{indent_str}break;')

        elif isinstance(stmt, HLILContinue):
            if stmt.label:
                lines.append(f'{indent_str}continue {stmt.label};')
            else:
                lines.append(f'{indent_str}continue;')

        elif isinstance(stmt, HLILReturn):
            if stmt.value is not None:
                value_str = cls._format_expr(stmt.value)
                lines.append(f'{indent_str}return {value_str};')
            else:
                lines.append(f'{indent_str}return;')

        elif isinstance(stmt, HLILUnstructured):
            lines.append(f'{indent_str}goto {stmt.target}; // unstructured ({stmt.reason})')

        elif isinstance(stmt, HLILAssign):
            dest_str = cls._format_expr(stmt.dest)
            src_str = cls._format_expr(stmt.src)
            lines.append(f'{indent_str}{dest_str} = {src_str};')

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
