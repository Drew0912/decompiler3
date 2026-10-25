"""TypeScript Code Generator - HLIL to production TypeScript"""

import math
from typing import Iterator, List, Optional, Tuple

from dc3 import default_indent, quote_string
from ir.core import constant_values_equal, is_int_zero
from ir.hlil import *


# HLIL type hint -> TypeScript type (any other: any)
TYPESCRIPT_TYPES = {
    HLILTypeKind.INT        : 'number',
    HLILTypeKind.FLOAT      : 'number',
    HLILTypeKind.NUMBER     : 'number',
    HLILTypeKind.STRING     : 'string',
    HLILTypeKind.BOOL       : 'boolean',
    HLILTypeKind.VOID       : 'void',
    HLILTypeKind.POINTER    : 'Pointer',
}


class TypeScriptGenerator(HLILStatementPrinter):
    CASE_BLOCKS = True

    _current_func: 'HighLevelILFunction' = None
    _callee_defaults: dict[str, tuple] = {}  # local callee name -> each parameter's default (None: none)
    _written_argc: dict[int, int] = {}       # local CALL offset -> args its debug record keeps (round trip)

    @classmethod
    def _format_type(cls, type_hint) -> str:
        return TYPESCRIPT_TYPES.get(type_hint, 'any')

    @classmethod
    def _format_float(cls, value: float) -> str:
        """A float as a TypeScript number: a non-finite value has no literal"""
        if math.isnan(value):
            return 'NaN'

        if math.isinf(value):
            return 'Infinity' if value > 0 else '-Infinity'

        return str(value)

    @classmethod
    def _format_default_value(cls, value) -> str:
        """Format default value as TypeScript literal"""
        if isinstance(value, str):
            return quote_string(value)
        elif isinstance(value, float):
            return cls._format_float(value)
        elif isinstance(value, int):
            return str(value)
        elif value is None:
            return 'null'
        else:
            raise TypeError(f'Unknown default value type: {type(value).__name__}')

    @classmethod
    def _format_call_args(cls, func_name: str, args: list, address: int) -> str:
        """The call's arguments without its trailing defaults"""
        return ', '.join(cls._format_expr(arg) for arg in cls._without_trailing_defaults(func_name, args, address))

    @classmethod
    def _without_trailing_defaults(cls, func_name: str, args: list, address: int) -> list:
        """args without the longest tail of constants that are the callee's defaults (the original compiler's own
        rule; the signature prints them), but never fewer than the call's debug record keeps (the author wrote them;
        round trip only, by the CALL's offset). The larger count, not the record's: a record that keeps fewer passes
        an address-taken local HLIL shows as a variable. A new list: the call keeps every argument"""
        defaults = cls._callee_defaults.get(func_name)
        if defaults is None or len(defaults) != len(args):
            return args

        kept = len(args)
        for arg, default in zip(reversed(args), reversed(defaults)):
            if not (isinstance(arg, HLILConst) and default is not None and constant_values_equal(arg.value, default)):
                break

            kept -= 1

        return args[:max(kept, cls._written_argc.get(address, 0))]

    @classmethod
    def _return_values(cls, block: HLILBlock) -> Iterator[HLILExpression]:
        """The values block's returns give, in source order, through the blocks its statements own (sub_blocks)"""
        for stmt in block.statements:
            if isinstance(stmt, HLILReturn):
                if stmt.value is not None:
                    yield stmt.value
            else:
                for child in sub_blocks(stmt):
                    yield from cls._return_values(child)

    @classmethod
    def _infer_return_type(cls, block: HLILBlock) -> str:
        """The type of the first value a return gives: a string or boolean constant's, else number; void if none"""
        value = next(cls._return_values(block), None)
        if value is None:
            return 'void'

        if isinstance(value, HLILConst) and isinstance(value.value, bool):
            return 'boolean'

        if isinstance(value, HLILConst) and isinstance(value.value, str):
            return 'string'

        return 'number'

    @classmethod
    def _is_number_var(cls, expr: HLILExpression) -> bool:
        if not isinstance(expr, HLILVar):
            return False

        hint = expr.var.type_hint

        # Fallback: look up from function's variable list
        if hint is None and cls._current_func:
            for var in cls._current_func.variables:
                if var.name == expr.var.name:
                    hint = var.type_hint
                    break

        # Pointer aliases number in the generated header
        return hint in (HLILTypeKind.INT, HLILTypeKind.FLOAT, HLILTypeKind.NUMBER, HLILTypeKind.POINTER)

    @classmethod
    def _format_var_assignment(cls, dest: HLILVar, src: HLILExpression) -> str:
        """Format `dest = src;`, wrapping src in int(...) when assigning a boolean expression
        to a numeric variable. Shared by the ordinary HLILAssign path and the address-taken
        *(&x) = v fold-back path, so both get the same coercion instead of it being
        reimplemented (and possibly missed) at a second call site."""
        dest_str = cls._format_expr(dest)
        src_str = cls._format_expr(src)

        if is_boolean_expr(src) and cls._is_number_var(dest):
            src_str = f'int({src_str})'

        return f'{dest_str} = {src_str};'

    @classmethod
    def _zero_comparison(cls, expr: HLILExpression) -> tuple[bool, HLILExpression] | None:
        """How a comparison with 0 simplifies, if it does: (negated, node) - it prints node's text, after a ! when
        negated. (bool) != 0 -> bool, (!x) == 0 -> x, (bool) == 0 -> !bool, !(x == 0) -> x, !(x != 0) -> !x"""
        if isinstance(expr, HLILBinaryOp):
            if not (isinstance(expr.rhs, HLILConst) and is_int_zero(expr.rhs.value) and is_boolean_expr(expr.lhs)):
                return None

            if expr.op == BinaryOp.NE:
                return False, expr.lhs

            if expr.op == BinaryOp.EQ:
                # Double negation elimination
                if isinstance(expr.lhs, HLILUnaryOp) and expr.lhs.op == UnaryOp.NOT:
                    return False, expr.lhs.operand

                return True, expr.lhs

            return None

        if isinstance(expr, HLILUnaryOp) and expr.op == UnaryOp.NOT and isinstance(expr.operand, HLILBinaryOp):
            inner = expr.operand
            if not (isinstance(inner.rhs, HLILConst) and is_int_zero(inner.rhs.value)):
                return None

            if inner.op == BinaryOp.EQ:
                return False, inner.lhs

            if inner.op == BinaryOp.NE:
                return True, inner.lhs

        return None

    @classmethod
    def _format_zero_comparison(cls, negated: bool, node: HLILExpression) -> str:
        text = cls._format_expr(node)
        if not negated:
            return text

        if cls._unary_operand_needs_parentheses(UnaryOp.NOT, node, text):
            text = f'({text})'
        return f'!{text}'

    @classmethod
    def _printed_node(cls, expr: HLILExpression) -> HLILExpression:
        """The node whose operator heads expr's text: a comparison with 0 prints as another node's
        ((a || b) != 0 prints a || b), and an operand is parenthesized by what it prints"""
        simplified = cls._zero_comparison(expr)
        if simplified is None:
            return expr

        negated, node = simplified
        return HLILUnaryOp(UnaryOp.NOT, node) if negated else cls._printed_node(node)

    @classmethod
    def _operand_needs_parentheses(cls, operand: HLILExpression, parent_op: BinaryOp, is_left: bool) -> bool:
        """By the operand and by the node it prints - today's parentheses all stay"""
        return any(isinstance(node, HLILBinaryOp) and needs_parentheses(node.op, parent_op, is_left)
                   for node in (operand, cls._printed_node(operand)))

    @classmethod
    def _unary_operand_needs_parentheses(cls, op: UnaryOp, operand: HLILExpression, operand_text: str) -> bool:
        """By the operand and by the node it prints - today's parentheses all stay"""
        return (unary_operand_needs_parentheses(op, operand, operand_text)
                or isinstance(cls._printed_node(operand), HLILBinaryOp))

    @classmethod
    def _format_expr(cls, expr: HLILExpression) -> str:
        if isinstance(expr, HLILVar):
            return str(expr.var)
        elif isinstance(expr, HLILConst):
            # The constant's own text, but a float as a TypeScript number
            return cls._format_float(expr.value) if isinstance(expr.value, float) else str(expr)
        elif isinstance(expr, HLILBinaryOp):
            # A comparison of two int constants prints its value, by the rule HLIL decides constant
            # conditions with (constant_truth: floats decide nothing). Any other op with two constant
            # operands (e.g. a compile-time 5 / 2) falls through to the plain BINARY_OP_STR rendering below.
            if expr.op in COMPARISON_OPS:
                truth = constant_truth(expr)
                if truth is not None:
                    return 'true' if truth else 'false'

            simplified = cls._zero_comparison(expr)
            if simplified is not None:
                return cls._format_zero_comparison(*simplified)

            lhs_str = cls._format_expr(expr.lhs)
            rhs_str = cls._format_expr(expr.rhs)

            # Add parentheses if needed based on precedence
            if cls._operand_needs_parentheses(expr.lhs, expr.op, True):
                lhs_str = f'({lhs_str})'

            if cls._operand_needs_parentheses(expr.rhs, expr.op, False):
                rhs_str = f'({rhs_str})'

            return f'{lhs_str} {BINARY_OP_STR[expr.op]} {rhs_str}'
        elif isinstance(expr, HLILUnaryOp):
            simplified = cls._zero_comparison(expr)
            if simplified is not None:
                return cls._format_zero_comparison(*simplified)

            operand = cls._format_expr(expr.operand)
            if cls._unary_operand_needs_parentheses(expr.op, expr.operand, operand):
                operand = f'({operand})'
            return f'{UNARY_OP_STR[expr.op]}{operand}'
        elif isinstance(expr, HLILAddressOf):
            operand = cls._format_expr(expr.operand)
            return f'addr_of({operand})'
        elif isinstance(expr, HLILDeref):
            unwrapped = unwrap_address_taken_var(expr)
            if unwrapped is not None:
                return cls._format_expr(unwrapped)

            operand = cls._format_expr(expr.operand)
            return f'deref({operand})'
        elif isinstance(expr, HLILCall):
            args = cls._format_call_args(expr.func_name, expr.args, expr.address)
            return f'{expr.func_name}({args})'
        elif isinstance(expr, HLILSyscall):
            args = [str(expr.subsystem), str(expr.cmd), *[cls._format_expr(arg) for arg in expr.args]]
            return f'syscall({', '.join(args)})'
        elif isinstance(expr, HLILExternCall):
            args = [
                quote_string(expr.target, "'"),
                *[cls._format_expr(arg) for arg in expr.args],
            ]
            return f'extern_call({', '.join(args)})'
        else:
            # Fallback
            return str(expr)

    @classmethod
    def _format_parameter(cls, param: HLILVariable) -> str:
        text = f'{param.name}: {cls._format_type(param.type_hint)}'
        if param.default_value is not None:
            text += f' = {cls._format_default_value(param.default_value)}'

        return text

    @classmethod
    def generate_function(cls, func: HighLevelILFunction) -> List[str]:
        cls._current_func = func
        lines = []

        # Function signature with types
        params = ', '.join(cls._format_parameter(param) for param in func.parameters)
        return_type = cls._infer_return_type(func.body)
        lines.append(f'function {func.name}({params}): {return_type} {{')

        # Variable declarations with types
        if func.variables:
            for var in func.variables:
                var_type = cls._format_type(var.type_hint)
                lines.append(f'{default_indent()}let {var.name}: {var_type};')
            lines.append('')

        lines.extend(cls._format_block(func.body, indent=1))
        lines.append('}')
        return lines

    @classmethod
    def _if_arms(cls, stmt: HLILIf) -> Tuple[HLILExpression, HLILBlock, Optional[HLILBlock]]:
        """Arm order is decided in HLIL (BranchOrderNormalizationPass), so that this output and the HLIL dump agree -
        only an empty then-arm is still worth rewriting here, negated as the HLIL passes negate"""
        true_empty = not stmt.true_block or not stmt.true_block.statements
        if true_empty and stmt.false_block and stmt.false_block.statements:
            return negate_condition(stmt.condition), stmt.false_block, None

        return stmt.condition, stmt.true_block, stmt.false_block

    @classmethod
    def _format_unstructured(cls, stmt: HLILUnstructured) -> List[str]:
        # A jump HLIL could not express: say so, and end this path instead of falling through
        return [f'// {stmt}', f'throw new Error("unstructured: {stmt.target}");']

    @classmethod
    def _format_assign(cls, stmt: HLILAssign) -> str:
        if not isinstance(stmt.dest, HLILDeref):
            return cls._format_var_assignment(stmt.dest, stmt.src)

        # *(&x) = v - address-taken local x's own lowered write - folds back to plain
        # x = v, through the same _format_var_assignment ordinary assignment uses, so it
        # gets the same boolean-to-int coercion rather than a second, unreimplemented copy
        unwrapped = unwrap_address_taken_var(stmt.dest)
        if unwrapped is not None:
            return cls._format_var_assignment(unwrapped, stmt.src)

        # A genuine store through some other pointer - TypeScript has no *ptr syntax,
        # so this is a deref_set() call, matching the addr_of() convention for &var
        ptr_str = cls._format_expr(stmt.dest.operand)
        src_str = cls._format_expr(stmt.src)
        return f'deref_set({ptr_str}, {src_str});'


def generate_typescript_header() -> str:
    return """// VM state
const GLOBALS: any[] = [];
const REGS: any[] = new Array(16);

// Out-parameter type: a stack address the callee writes through
type Pointer = number;

// Intrinsic function: address-of operator (for output parameters)
function addr_of<T>(value: T): T { return value; }

// Intrinsic functions: pointer dereference (read/write through an out-parameter)
function deref<T>(ptr: T): T { return ptr; }
function deref_set<T>(ptr: T, value: T): void { }

// Intrinsic function: boolean/number to int conversion
function int(b: number | boolean): number { return +b; }

// Placeholder function: external script call
function extern_call(target: string, ...args: any[]): any { return undefined; }

// Placeholder function: system call
function syscall(subsystem: number, cmd: number, ...args: any[]): any { return undefined; }

// Placeholder function: VM debug print (DEBUG_LOG opcode)
const debug = { log(...args: any[]): void {} };

"""


def generate_typescript(func: HighLevelILFunction, callee_defaults: dict[str, tuple] | None = None,
                        written_argc: dict[int, int] | None = None) -> str:
    """func's TypeScript; with callee_defaults (local callee name -> each parameter's default as the lifter converts
    it, None where there is none) a call leaves out its trailing arguments equal to them, but with written_argc
    (local CALL offset -> args its debug record keeps: Function.call_written_argc, round trip only) never the ones its
    author wrote"""
    TypeScriptGenerator._callee_defaults = callee_defaults or {}
    TypeScriptGenerator._written_argc = written_argc or {}
    try:
        lines = TypeScriptGenerator.generate_function(func)
    finally:
        TypeScriptGenerator._callee_defaults = {}
        TypeScriptGenerator._written_argc = {}

    return '\n'.join(lines)
