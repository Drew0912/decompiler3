"""HLIL Formatter - the .hlil.ts text: the bytecode's high-level form, not TypeScript (the suffix is for editors)"""

from dc3 import default_indent
from .hlil import *
from .statement_printer import HLILStatementPrinter

# Logic recovered from jumps; `&&` and `||` here are the VM's eager ops
RECOVERED_LOGIC_NAMES = {BinaryOp.AND_THEN: 'andThen', BinaryOp.OR_ELSE: 'orElse'}


class HLILFormatter(HLILStatementPrinter):
    """Format HLIL functions as .hlil.ts"""

    @classmethod
    def _format_expr(cls, expr: HLILExpression) -> str:
        """Format an HLIL expression"""
        test, negated = strip_truth_test(expr)
        if negated:
            return cls._format_not(test)
        if test is not expr:
            return cls._format_expr(test)

        if isinstance(expr, HLILVar):
            return str(expr.var)  # Use __str__ to handle GLOBAL/REG properly
        elif isinstance(expr, HLILConst):
            # The constant's own text: quoted strings, true/false, hex constants unsigned as in the .ts
            return str(expr)
        elif isinstance(expr, HLILBinaryOp):
            if expr.op in RECOVERED_LOGIC_NAMES:
                operands = ', '.join(cls._format_expr(operand) for operand in cls._chain_operands(expr))
                return f'{RECOVERED_LOGIC_NAMES[expr.op]}({operands})'

            lhs_str = cls._format_expr(expr.lhs)
            rhs_str = cls._format_expr(expr.rhs)

            # Add parentheses if needed based on precedence
            if cls._operand_needs_parentheses(expr.lhs, expr.op, True):
                lhs_str = f'({lhs_str})'

            if cls._operand_needs_parentheses(expr.rhs, expr.op, False):
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
            # *(&x) - the memory form of address-taken local x (the stack translator's, and
            # ir/mlil_ssa/mlil_ssa.py's lowering) - folds back to plain x, same convention as codegen/typescript.py
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
    def _is_recovered_logic(cls, expr: HLILExpression) -> bool:
        return isinstance(expr, HLILBinaryOp) and expr.op in RECOVERED_LOGIC_NAMES

    @classmethod
    def _format_not(cls, test: HLILExpression) -> str:
        text = cls._format_expr(test)
        if not cls._is_recovered_logic(test) and unary_operand_needs_parentheses(UnaryOp.NOT, test, text):
            text = f'({text})'
        return f'!{text}'

    @classmethod
    def _operand_needs_parentheses(cls, operand: HLILExpression, parent_op: BinaryOp, is_left: bool) -> bool:
        """By the node it prints: a truth test prints what it tests, a recovered op prints as a call"""
        test, negated = strip_truth_test(operand)
        return (not negated and isinstance(test, HLILBinaryOp) and not cls._is_recovered_logic(test)
                and needs_parentheses(test.op, parent_op, is_left))

    @classmethod
    def format_function(cls, func: HighLevelILFunction) -> list[str]:
        """Format an HLIL function as .hlil.ts"""
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
    def _format_unstructured(cls, stmt: HLILUnstructured) -> list[str]:
        return [f'goto {stmt.target}; // unstructured ({stmt.reason})']
