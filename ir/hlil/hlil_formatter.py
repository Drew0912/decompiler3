"""HLIL Formatter - Format HLIL for debugging"""

from typing import List

from dc3 import default_indent
from .hlil import *
from .statement_printer import HLILStatementPrinter


class HLILFormatter(HLILStatementPrinter):
    """Format HLIL functions for debugging"""

    @classmethod
    def _format_expr(cls, expr: HLILExpression) -> str:
        """Format an HLIL expression"""
        if isinstance(expr, HLILVar):
            return str(expr.var)  # Use __str__ to handle GLOBAL/REG properly
        elif isinstance(expr, HLILConst):
            # The constant's own text: quoted strings, true/false, hex constants unsigned as in the .ts
            return str(expr)
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
            if unary_operand_needs_parentheses(expr.op, expr.operand, operand):
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
            args = [str(expr.subsystem), str(expr.cmd), *[cls._format_expr(arg) for arg in expr.args]]
            return f'syscall({', '.join(args)})'
        elif isinstance(expr, HLILExternCall):
            args = ', '.join(cls._format_expr(arg) for arg in expr.args)
            return f'{expr.target}({args})'
        else:
            # Fallback
            return str(expr)

    @classmethod
    def format_function(cls, func: HighLevelILFunction) -> List[str]:
        """Format an HLIL function for debugging"""
        lines = []

        # Function header (simple, no types)
        params = ', '.join(p.name for p in func.parameters)
        lines.append(f'function {func.name}({params}) {{')

        # Variables (simple declarations)
        if func.variables:
            for var in func.variables:
                lines.append(f'{default_indent()}var {var.name}')
            lines.append('')

        lines.extend(cls._format_block(func.body, indent=1))
        lines.append('}')
        return lines

    @classmethod
    def _format_assign(cls, stmt: HLILAssign) -> str:
        return f'{cls._format_expr(stmt.dest)} = {cls._format_expr(stmt.src)};'

    @classmethod
    def _format_unstructured(cls, stmt: HLILUnstructured) -> List[str]:
        return [f'goto {stmt.target}; // unstructured ({stmt.reason})']
