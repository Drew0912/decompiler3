'''TypeScript Code Generator - HLIL to production TypeScript'''

from common import *
from typing import List, Optional
from ir.hlil import *

# Constant folding at codegen time only covers comparisons (arithmetic/bitwise/logical constant
# pairs are printed literally via BINARY_OP_STR instead - see the isinstance(HLILBinaryOp) branch
# below). Matches ir/hlil/passes/pass_branch_order_normalization.py's _COMPARISON_OPS.
_COMPARISON_OPS = (BinaryOp.EQ, BinaryOp.NE, BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE)


class TypeScriptGenerator:
    _current_func: 'HighLevelILFunction' = None
    _signature_db = None  # FormatSignatureDB for arg formatting

    @classmethod
    def set_signature_db(cls, db):
        '''Set signature database for formatting'''
        cls._signature_db = db

    @classmethod
    def _format_type(cls, type_hint) -> str:
        '''Map HLIL type to TypeScript'''
        if not type_hint:
            return 'any'

        # Handle HLILTypeKind enum
        if isinstance(type_hint, HLILTypeKind):
            type_map = {
                HLILTypeKind.INT: 'number',
                HLILTypeKind.FLOAT: 'number',
                HLILTypeKind.STRING: 'string',
                HLILTypeKind.BOOL: 'boolean',
                HLILTypeKind.VOID: 'void',
            }
            return type_map.get(type_hint, 'any')

        # Handle string type hints (from FalcomTypeInferencePass)
        if isinstance(type_hint, str):
            type_map = {
                'int': 'number',
                'float': 'number',
                'number': 'number',
                'bool': 'boolean',
                'string': 'string',
                'void': 'void',
            }
            return type_map.get(type_hint.lower(), type_hint)

        return 'any'

    @classmethod
    def _format_default_value(cls, value) -> str:
        '''Format default value as TypeScript literal'''
        if isinstance(value, str):
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'

        elif isinstance(value, float):
            return format_float(value)

        elif isinstance(value, int):
            return str(value)

        elif value is None:
            return 'null'

        else:
            raise TypeError(f'Unknown default value type: {type(value).__name__}')

    @classmethod
    def _format_call_args(cls, func_name: str, args: list) -> str:
        '''Format call arguments, using signature hints if available'''
        if cls._signature_db:
            sig = cls._signature_db.get_function(func_name)
            if sig:
                return cls._format_call_args_with_sig(args, sig.params)

        return ', '.join(cls._format_expr(arg) for arg in args)

    @classmethod
    def _format_call_args_with_sig(cls, args: list, params: list) -> str:
        '''Format call arguments with parameter hints'''
        formatted = []
        has_variadic = params and params[-1].variadic
        fixed_count = len(params) - 1 if has_variadic else len(params)

        for i, arg in enumerate(args):
            if i < fixed_count and params[i].format:
                formatted_arg = cls._format_arg_with_hint(arg, params[i].format)
                formatted.append(formatted_arg)

            else:
                formatted.append(cls._format_expr(arg))

        return ', '.join(formatted)

    @classmethod
    def _format_arg_with_hint(cls, arg, format_hint: str) -> str:
        '''Format argument with format hint (hex, enum, etc.)'''
        if isinstance(arg, HLILConst) and isinstance(arg.value, int):
            formatted = cls._signature_db.format_value(arg.value, format_hint)
            if formatted:
                return formatted

        return cls._format_expr(arg)

    @classmethod
    def _infer_return_type(cls, block: HLILBlock) -> str:
        '''Infer return type from return statements'''
        # Recursively search for return statements
        def find_returns(blk: HLILBlock) -> List[HLILReturn]:
            returns = []
            for stmt in blk.statements:
                if isinstance(stmt, HLILReturn):
                    returns.append(stmt)

                else:
                    for child in sub_blocks(stmt):
                        returns.extend(find_returns(child))

            return returns

        returns = find_returns(block)

        # If no return statements or all returns are void
        if not returns or all(r.value is None for r in returns):
            return 'void'

        # Check if any return has a value
        for ret in returns:
            if ret.value is not None:
                # Try to infer type from the value
                if isinstance(ret.value, HLILConst):
                    val = ret.value.value
                    if isinstance(val, bool):
                        return 'boolean'
                    elif isinstance(val, int):
                        return 'number'
                    elif isinstance(val, float):
                        return 'number'
                    elif isinstance(val, str):
                        return 'string'

                # Default to number for most return values
                return 'number'

        return 'void'

    @classmethod
    def _needs_parentheses(cls, child_op: str, parent_op: str, is_left: bool) -> bool:
        # Operator precedence (lower number = lower precedence)
        precedence = {
            '||': 1,
            '&&': 2,
            '|': 3,
            '^': 4,
            '&': 5,
            '==': 6, '!=': 6,
            '<': 7, '<=': 7, '>': 7, '>=': 7,
            '<<': 8, '>>': 8,
            '+': 9, '-': 9,
            '*': 10, '/': 10, '%': 10,
        }

        child_prec = precedence.get(child_op, 100)
        parent_prec = precedence.get(parent_op, 100)

        # Need parentheses if child has lower precedence
        if child_prec < parent_prec:
            return True

        # For same precedence, only right operand needs parentheses for non-associative ops
        if child_prec == parent_prec and not is_left:
            # Non-associative: -, /, %
            if parent_op in {'-', '/', '%'}:
                return True

        return False

    BOOLEAN_BINARY_OPS = {
        BinaryOp.EQ, BinaryOp.NE,
        BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE,
        BinaryOp.AND, BinaryOp.OR,
    }

    @classmethod
    def _is_boolean_expr(cls, expr: HLILExpression) -> bool:
        if isinstance(expr, HLILBinaryOp):
            return expr.op in cls.BOOLEAN_BINARY_OPS

        elif isinstance(expr, HLILUnaryOp):
            return expr.op == UnaryOp.NOT

        return False

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

        if isinstance(hint, HLILTypeKind):
            return hint in (HLILTypeKind.INT, HLILTypeKind.FLOAT)

        elif isinstance(hint, str):
            return hint.lower() in ('int', 'float', 'number')

        return False

    @classmethod
    def _format_var_assignment(cls, dest: HLILVar, src: HLILExpression, indent_str: str) -> str:
        '''Format `dest = src;`, wrapping src in int(...) when assigning a boolean expression
        to a numeric variable. Shared by the ordinary HLILAssign path and the address-taken
        *(&x) = v fold-back path, so both get the same coercion instead of it being
        reimplemented (and possibly missed) at a second call site.'''
        dest_str = cls._format_expr(dest)
        src_str = cls._format_expr(src)

        if cls._is_boolean_expr(src) and cls._is_number_var(dest):
            src_str = f'int({src_str})'

        return f'{indent_str}{dest_str} = {src_str};'

    @classmethod
    def _format_expr(cls, expr: HLILExpression) -> str:
        if isinstance(expr, HLILVar):
            var = expr.var
            if var.kind == VariableKind.GLOBAL:
                return f'GLOBALS[{var.index}]'

            elif var.kind == VariableKind.REG:
                return f'REGS[{var.index}]'

            else:
                return var.name

        elif isinstance(expr, HLILConst):
            # Handle different constant types
            if isinstance(expr.value, str):
                return quote_string(expr.value)

            elif isinstance(expr.value, bool):
                return 'true' if expr.value else 'false'

            elif isinstance(expr.value, float):
                return format_float(expr.value)

            elif isinstance(expr.value, int) and expr.is_hex:
                # Display as unsigned 32-bit hex
                unsigned = expr.value & 0xFFFFFFFF
                return f'0x{unsigned:08X}'

            else:
                return str(expr.value)

        elif isinstance(expr, HLILBinaryOp):
            # Constant folding for comparison operators only - an arithmetic/bitwise/logical op
            # with two constant operands (e.g. a compile-time 5 / 2) falls through to the plain
            # BINARY_OP_STR rendering below instead of hitting the comparison-only match below.
            if isinstance(expr.lhs, HLILConst) and isinstance(expr.rhs, HLILConst) and expr.op in _COMPARISON_OPS:
                lhs_val, rhs_val = expr.lhs.value, expr.rhs.value

                match expr.op:
                    case BinaryOp.EQ:
                        result = lhs_val == rhs_val

                    case BinaryOp.NE:
                        result = lhs_val != rhs_val

                    case BinaryOp.LT:
                        result = lhs_val < rhs_val

                    case BinaryOp.LE:
                        result = lhs_val <= rhs_val

                    case BinaryOp.GT:
                        result = lhs_val > rhs_val

                    case BinaryOp.GE:
                        result = lhs_val >= rhs_val

                return 'true' if result else 'false'

            # Simplify boolean comparisons with 0
            # (bool_expr) != 0 -> bool_expr
            # (bool_expr) == 0 -> !bool_expr
            # (!x) == 0 -> x (double negation elimination)
            if isinstance(expr.rhs, HLILConst) and expr.rhs.value == 0:
                if cls._is_boolean_expr(expr.lhs):
                    if expr.op == BinaryOp.NE:
                        # (bool) != 0 -> bool
                        return cls._format_expr(expr.lhs)

                    elif expr.op == BinaryOp.EQ:
                        # (!x) == 0 -> x (double negation elimination)
                        if isinstance(expr.lhs, HLILUnaryOp) and expr.lhs.op == UnaryOp.NOT:
                            return cls._format_expr(expr.lhs.operand)

                        # (bool) == 0 -> !bool
                        inner = cls._format_expr(expr.lhs)
                        # Add parentheses if inner is any binary expression (! has higher precedence)
                        if isinstance(expr.lhs, HLILBinaryOp):
                            inner = f'({inner})'
                        return f'!{inner}'

            lhs_str = cls._format_expr(expr.lhs)
            rhs_str = cls._format_expr(expr.rhs)
            op_str = BINARY_OP_STR[expr.op]

            # Add parentheses if needed based on precedence
            if isinstance(expr.lhs, HLILBinaryOp):
                if cls._needs_parentheses(BINARY_OP_STR[expr.lhs.op], op_str, True):
                    lhs_str = f'({lhs_str})'

            if isinstance(expr.rhs, HLILBinaryOp):
                if cls._needs_parentheses(BINARY_OP_STR[expr.rhs.op], op_str, False):
                    rhs_str = f'({rhs_str})'

            return f'{lhs_str} {op_str} {rhs_str}'

        elif isinstance(expr, HLILUnaryOp):
            # Simplify !(x == 0) -> x and !(x != 0) -> !x
            if expr.op == UnaryOp.NOT and isinstance(expr.operand, HLILBinaryOp):
                inner = expr.operand
                if isinstance(inner.rhs, HLILConst) and inner.rhs.value == 0:
                    if inner.op == BinaryOp.EQ:
                        # !(x == 0) -> x
                        return cls._format_expr(inner.lhs)

                    elif inner.op == BinaryOp.NE:
                        # !(x != 0) -> x == 0 -> !x
                        lhs_str = cls._format_expr(inner.lhs)
                        if isinstance(inner.lhs, HLILBinaryOp):
                            lhs_str = f'({lhs_str})'
                        return f'!{lhs_str}'

            operand = cls._format_expr(expr.operand)
            # Add parentheses around binary operands to avoid precedence issues
            if isinstance(expr.operand, HLILBinaryOp):
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
            args = cls._format_call_args(expr.func_name, expr.args)
            return f'{expr.func_name}({args})'

        elif isinstance(expr, HLILSyscall):
            # Don't replace syscalls in common functions (they are the wrappers themselves)
            is_common = cls._current_func and cls._current_func.is_common_func
            sig = cls._signature_db.get_syscall(expr.subsystem, expr.cmd) if cls._signature_db and not is_common else None
            if sig:
                args = cls._format_call_args_with_sig(expr.args, sig.params)
                return f'{sig.name}({args})'

            else:
                args = [
                    f'{expr.subsystem}',
                    f'{expr.cmd}',
                    *[cls._format_expr(arg) for arg in expr.args],
                ]
                return f'syscall({", ".join(args)})'

        elif isinstance(expr, HLILExternCall):
            args = [
                f"'{expr.target}'",
                *[cls._format_expr(arg) for arg in expr.args],
            ]
            return f'extern_call({', '.join(args)})'

        else:
            # Fallback
            return str(expr)

    @classmethod
    def generate_function(cls, func: HighLevelILFunction) -> List[str]:
        cls._current_func = func
        lines = []

        # Function signature with types
        if func.parameters:
            params = ', '.join(
                f'{p.name}: {cls._format_type(p.type_hint)} = {cls._format_default_value(p.default_value)}' if p.default_value is not None else f'{p.name}: {cls._format_type(p.type_hint)}'
                for p in func.parameters
            )
        else:
            params = ''

        return_type = cls._infer_return_type(func.body)
        lines.append(f'function {func.name}({params}): {return_type} {{')

        # Variable declarations with types
        if func.variables:
            for var in func.variables:
                var_type = cls._format_type(var.type_hint)
                lines.append(f'{default_indent()}let {var.name}: {var_type};')
            lines.append('')

        # Function body
        body_lines = cls._generate_block(func.body, indent=1)
        lines.extend(body_lines)

        lines.append('}')
        return lines

    @classmethod
    def _generate_block(cls, block: HLILBlock, indent: int = 0) -> List[str]:
        lines = []

        for stmt in block.statements:
            stmt_lines = cls._generate_statement(stmt, indent)
            lines.extend(stmt_lines)

        return lines

    NEGATION_MAP = {
        BinaryOp.EQ: BinaryOp.NE,
        BinaryOp.NE: BinaryOp.EQ,
        BinaryOp.LT: BinaryOp.GE,
        BinaryOp.GE: BinaryOp.LT,
        BinaryOp.GT: BinaryOp.LE,
        BinaryOp.LE: BinaryOp.GT,
    }

    @classmethod
    def _negate_condition_str(cls, cond: HLILExpression) -> str:
        '''Format negated condition as string'''
        if isinstance(cond, HLILBinaryOp):
            if cond.op in cls.NEGATION_MAP:
                lhs = cls._format_expr(cond.lhs)
                rhs = cls._format_expr(cond.rhs)
                negated_op = BINARY_OP_STR[cls.NEGATION_MAP[cond.op]]
                return f'{lhs} {negated_op} {rhs}'

        # Fallback: wrap original in !()
        return f'!({cls._format_expr(cond)})'

    @classmethod
    def _generate_statement(cls, stmt: HLILStatement, indent: int = 0) -> List[str]:
        indent_str = default_indent() * indent
        lines = []

        if isinstance(stmt, HLILIf):
            condition = stmt.condition
            true_block = stmt.true_block
            false_block = stmt.false_block

            # Arm order is decided in HLIL (BranchOrderNormalizationPass) so that
            # this output and the HLIL dump agree - only an empty then-branch is
            # still worth rewriting here
            false_has_content = false_block and false_block.statements
            true_empty = not true_block or not true_block.statements

            if true_empty and false_has_content:
                cond_str = cls._negate_condition_str(condition)
                true_block, false_block = false_block, None

            else:
                cond_str = cls._format_expr(condition)

            lines.append(f'{indent_str}if ({cond_str}) {{')
            lines.extend(cls._generate_block(true_block, indent + 1))

            while false_block and false_block.statements:
                # else { [comments] single if } -> [comments] else if
                arm = split_else_if_arm(false_block)

                if arm is not None:
                    comments, inner_if = arm

                    for comment in comments:
                        lines.extend(cls._generate_statement(comment, indent))

                    inner_cond = cls._format_expr(inner_if.condition)
                    lines.append(f'{indent_str}}} else if ({inner_cond}) {{')
                    lines.extend(cls._generate_block(inner_if.true_block, indent + 1))
                    false_block = inner_if.false_block

                else:
                    lines.append(f'{indent_str}}} else {{')
                    lines.extend(cls._generate_block(false_block, indent + 1))
                    break

            lines.append(f'{indent_str}}}')

        elif isinstance(stmt, HLILWhile):
            # while (condition) { ... }, optionally labeled
            cond_str = cls._format_expr(stmt.condition)
            label_prefix = f'{stmt.label}: ' if stmt.label else ''
            lines.append(f'{indent_str}{label_prefix}while ({cond_str}) {{')
            lines.extend(cls._generate_block(stmt.body, indent + 1))
            lines.append(f'{indent_str}}}')

        elif isinstance(stmt, HLILDoWhile):
            # do { ... } while (condition);, optionally labeled
            cond_str = cls._format_expr(stmt.condition)
            label_prefix = f'{stmt.label}: ' if stmt.label else ''
            lines.append(f'{indent_str}{label_prefix}do {{')
            lines.extend(cls._generate_block(stmt.body, indent + 1))
            lines.append(f'{indent_str}}} while ({cond_str});')

        elif isinstance(stmt, HLILSwitch):
            # switch (scrutinee) { ... }
            scrutinee_str = cls._format_expr(stmt.scrutinee)
            lines.append(f'{indent_str}switch ({scrutinee_str}) {{')
            case_indent = default_indent()
            case_body_indent = default_indent() * 2
            for case in stmt.cases:
                if case.is_default():
                    lines.append(f'{indent_str}{case_indent}default: {{')
                else:
                    # Labels sharing a body stack, only the last one opens the block
                    for value in case.values[:-1]:
                        lines.append(f'{indent_str}{case_indent}case {cls._format_expr(value)}:')

                    lines.append(f'{indent_str}{case_indent}case {cls._format_expr(case.values[-1])}: {{')
                lines.extend(cls._generate_block(case.body, indent + 2))

                # Add break if case doesn't end with return/break/continue - including an
                # empty case body (no last statement at all), which otherwise falls through
                # into the next case instead of doing nothing
                last_stmt = case.body.statements[-1] if case.body.statements else None
                if not isinstance(last_stmt, (HLILReturn, HLILBreak, HLILContinue)):
                    lines.append(f'{indent_str}{case_body_indent}break;')

                lines.append(f'{indent_str}{case_indent}}}')

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

        elif isinstance(stmt, HLILAssign) and isinstance(stmt.dest, HLILDeref):
            # *(&x) = v - address-taken local x's own lowered write - folds back to plain
            # x = v, through the same _format_var_assignment ordinary assignment uses, so it
            # gets the same boolean-to-int coercion rather than a second, unreimplemented copy
            unwrapped = unwrap_address_taken_var(stmt.dest)
            if unwrapped is not None:
                lines.append(cls._format_var_assignment(unwrapped, stmt.src, indent_str))

            else:
                # A genuine store through some other pointer - TypeScript has no *ptr syntax,
                # so this is a deref_set() call, matching the addr_of() convention for &var
                ptr_str = cls._format_expr(stmt.dest.operand)
                src_str = cls._format_expr(stmt.src)
                lines.append(f'{indent_str}deref_set({ptr_str}, {src_str});')

        elif isinstance(stmt, HLILAssign):
            lines.append(cls._format_var_assignment(stmt.dest, stmt.src, indent_str))

        elif isinstance(stmt, HLILExprStmt):
            expr_str = cls._format_expr(stmt.expr)
            lines.append(f'{indent_str}{expr_str};')

        elif isinstance(stmt, HLILComment):
            lines.append(f'{indent_str}// {stmt.text}')

        elif isinstance(stmt, HLILBlock):
            # Nested block
            lines.append(f'{indent_str}{{')
            lines.extend(cls._generate_block(stmt, indent + 1))
            lines.append(f'{indent_str}}}')

        else:
            lines.append(f'{indent_str}// {stmt}')

        return lines


def generate_typescript_header() -> str:
    return '''// VM state
const GLOBALS: any[] = [];
const REGS: any[] = new Array(16);

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

'''


def generate_syscall_wrappers(signature_db) -> str:
    '''Generate TypeScript wrapper functions for syscalls'''
    if not signature_db or not signature_db.syscalls:
        return ''

    lines = ['// Syscall wrappers']

    for name, sig in signature_db.syscalls.items():
        # Build parameter list
        params = []
        args = []
        for p in sig.params:
            if p.variadic:
                params.append(f'...{p.name}: ({p.type})[]')
                args.append(f'...{p.name}')

            else:
                params.append(f'{p.name}: {p.type}')
                args.append(p.name)

        params_str = ', '.join(params)
        args_str = ', '.join(args)

        # Determine return type
        if sig.return_hint:
            if sig.return_hint.type == 'void':
                return_type = 'void'
                body = f'syscall({sig.subsystem}, {sig.cmd}, {args_str});' if args_str else f'syscall({sig.subsystem}, {sig.cmd});'

            else:
                return_type = 'number'
                body = f'return syscall({sig.subsystem}, {sig.cmd}, {args_str});' if args_str else f'return syscall({sig.subsystem}, {sig.cmd});'

        else:
            return_type = 'any'
            body = f'return syscall({sig.subsystem}, {sig.cmd}, {args_str});' if args_str else f'return syscall({sig.subsystem}, {sig.cmd});'

        lines.append(f'function {name}({params_str}): {return_type} {{ {body} }}')

    lines.append('')
    return '\n'.join(lines) + '\n'


def generate_typescript(func: HighLevelILFunction) -> str:
    lines = TypeScriptGenerator.generate_function(func)
    return '\n'.join(lines)
