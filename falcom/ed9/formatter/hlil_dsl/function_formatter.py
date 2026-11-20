"""The HLIL DSL's function formatter (docs/dsl/HLIL_DSL.md, Form, Printer): an HLIL function as the lines of its
@scena.HLILCode() definition, or LLILFallback with the reason it stays LLIL. Its forms so far: calls, Set, Let and
Return and the intrinsic statements; If with its .ElseIf / .Else arms, one statement per line in each block; a literal
wrapped where Python would fold, mirror or format the bare one; Python's precedence. The HLIL walk is VM-neutral; what
is ED9's (the constants' spelling, the declaring push and the default return, registers, the ED9-only statements) is
ED9Forms'"""

from enum import IntEnum, auto
import keyword
import re
from typing import Callable, NamedTuple

from dc3 import default_indent, quote_string
from ir.core import is_int_zero
from ir.hlil import (BinaryOp, HighLevelILFunction, HLILAddressOf, HLILAssign, HLILBinaryOp, HLILBlock, HLILCall,
                     HLILComment, HLILConst, HLILDeref, HLILDoWhile, HLILExpression, HLILExprStmt, HLILExternCall,
                     HLILIf, HLILIntrinsic, HLILReturn, HLILStatement, HLILSwitch, HLILSyscall, HLILUnaryOp, HLILVar,
                     HLILVariable, HLILWhile, UnaryOp, VariableKind)
from ir.hlil.hlil import unwrap_address_taken_var
from ...assembler.function import Function
from ...structs.scp_types import RawInt, ScpValue
from ..llil_dsl.function_formatter import Formatter

INDENT = default_indent()
HLIL_DECORATOR = '@scena.HLILCode()'
TEMPORARY = re.compile(r't\d+')
ADDRESS_TAKEN = 'address taken'     # a reason given in several places, counted as one in the logs


class Binding(IntEnum):
    """Python's binding strength, loosest first; a bare negative number binds as a unary minus"""

    COMPARISON  = auto()
    BIT_OR      = auto()
    BIT_AND     = auto()
    SUM         = auto()
    PRODUCT     = auto()
    UNARY       = auto()
    ATOM        = auto()


BINARY_FORMS = {
    BinaryOp.ADD        : ('+', Binding.SUM),
    BinaryOp.SUB        : ('-', Binding.SUM),
    BinaryOp.MUL        : ('*', Binding.PRODUCT),
    BinaryOp.DIV        : ('/', Binding.PRODUCT),
    BinaryOp.MOD        : ('%', Binding.PRODUCT),
    BinaryOp.EQ         : ('==', Binding.COMPARISON),
    BinaryOp.NE         : ('!=', Binding.COMPARISON),
    BinaryOp.LT         : ('<', Binding.COMPARISON),
    BinaryOp.LE         : ('<=', Binding.COMPARISON),
    BinaryOp.GT         : ('>', Binding.COMPARISON),
    BinaryOp.GE         : ('>=', Binding.COMPARISON),
    BinaryOp.BIT_AND    : ('&', Binding.BIT_AND),
    BinaryOp.BIT_OR     : ('|', Binding.BIT_OR),
}
BITWISE = (Binding.BIT_OR, Binding.BIT_AND)
UNARY_SYMBOLS = {UnaryOp.NEG: '-', UnaryOp.BIT_NOT: '~'}
EAGER_LOGIC = {BinaryOp.AND: 'And', BinaryOp.OR: 'Or'}
SHORT_CIRCUIT = (BinaryOp.AND_THEN, BinaryOp.OR_ELSE)
# A string's own operators that run before the DSL sees them: % formats, * repeats (asking the node for a number)
STRING_OPERATORS = (BinaryOp.MOD, BinaryOp.MUL)


class LLILFallback(Exception):
    """The function stays LLIL: the DSL has no form for something in it; the reason is for the logs"""


class ScriptNames(NamedTuple):
    """What one script's functions are printed against"""

    global_name: Callable[[int], str | None]    # a global's name by its index
    functions: frozenset[str]                   # the function table's names
    reserved: frozenset[str]                    # the names the script's DSL import brings


class Printed(NamedTuple):
    """A statement's DSL lines, and how many HLIL statements it stands for (Let(x, value) fuses two)"""

    lines: list[str]
    statements: int


def is_identifier(text: str | None) -> bool:
    return text is not None and text.isidentifier() and not keyword.iskeyword(text)


def is_attribute_name(text: str) -> bool:
    """this.name and script.module.name can spell it: a dunder is Python's own"""
    return is_identifier(text) and not text.startswith('__')


def is_temporary(name: str | None) -> bool:
    """A temporary of the VM-order fold (foldtemps), not a local the DSL declares"""
    return TEMPORARY.fullmatch(name or '') is not None


def is_store_to_local(statement: HLILStatement | None, name: str) -> bool:
    return (isinstance(statement, HLILAssign) and isinstance(statement.dest, HLILVar)
            and statement.dest.var.kind == VariableKind.LOCAL and statement.dest.var.name == name)


def code_statements(block: HLILBlock) -> list[HLILStatement]:
    """block's statements but its comments"""
    return [statement for statement in block.statements if not isinstance(statement, HLILComment)]


def ends_path(statement: HLILStatement) -> bool:
    """No code after statement runs: a return, or an if with an else whose every arm ends its path"""
    match statement:
        case HLILReturn():
            return True

        case HLILIf(false_block=HLILBlock()):
            return block_ends_path(statement.true_block) and block_ends_path(statement.false_block)

    return False


def block_ends_path(block: HLILBlock) -> bool:
    statements = code_statements(block)
    return bool(statements) and ends_path(statements[-1])


def is_zero_test(expr: HLILExpression, op: BinaryOp) -> bool:
    """expr is a comparison (op: == or !=) with a plain 0: an arm's truth test"""
    return (isinstance(expr, HLILBinaryOp) and expr.op == op and isinstance(expr.rhs, HLILConst)
            and is_int_zero(expr.rhs.value))


# Parentheses Python's precedence leaves out but the operation needs. A comparison inside another would chain
# (a < b < c); a bitwise operand of one keeps its parentheses, as C reads it the other way

def left_needs_parentheses(left: Binding, operator: Binding) -> bool:
    return left < operator or (operator == Binding.COMPARISON and (left == Binding.COMPARISON or left in BITWISE))


def right_needs_parentheses(right: Binding, operator: Binding) -> bool:
    """Python groups an operator's equals from the left: one on the right keeps its parentheses"""
    return right <= operator or (operator == Binding.COMPARISON and right in BITWISE)


class ED9Forms:
    """What the function formatter writes that is ED9's"""

    @classmethod
    def constant(cls, value, wrapped: bool) -> str:
        """A constant's text; wrapped: in its constructor, where Python would fold, mirror or format a bare literal"""
        match value:
            case bool():
                raise LLILFallback('bool constant')

            case RawInt():
                return f'Raw({int(value)})'

            case int():
                return f'Int({value})' if wrapped else str(value)

            case float():
                text = ScpValue.float_literal(value)
                return f'Float({text})' if wrapped else text

            case str():
                text = quote_string(value)
                return f'Str({text})' if wrapped else text

        raise LLILFallback(f'{type(value).__name__} constant')

    @classmethod
    def is_plain_literal(cls, expr: HLILExpression) -> bool:
        """A constant Python sees as its own value (Raw(n) is a call, which nothing folds)"""
        return isinstance(expr, HLILConst) and not isinstance(expr.value, RawInt)

    @classmethod
    def is_raw_zero(cls, expr: HLILExpression | None) -> bool:
        """The compiler's declaring push of a local, and its default return value"""
        return isinstance(expr, HLILConst) and isinstance(expr.value, RawInt) and expr.value == 0

    @classmethod
    def register(cls, index: int) -> str:
        return f'REGS[{index}]'

    @classmethod
    def syscall(cls, subsystem: int, cmd: int, args: list[str]) -> str:
        return f'Syscall({', '.join([str(subsystem), str(cmd), *args])})'

    @classmethod
    def intrinsic(cls, name: str, args: list[HLILExpression], text_of: Callable[[HLILExpression], str]) -> str:
        match name:
            case 'POPN':
                return f'PopN({', '.join(text_of(arg) for arg in args)})'

            case 'DEBUG_INT':
                [value] = args
                if not (isinstance(value, HLILConst) and type(value.value) is int):
                    raise LLILFallback('DEBUG_INT operand')

                return f'DebugInt({value.value})'

        raise LLILFallback(f'intrinsic {name}')


def function_lines(func: Function, hlil: HighLevelILFunction, names: ScriptNames,
                   forms: type[ED9Forms] = ED9Forms) -> list[str]:
    """func's @scena.HLILCode() definition from its HLIL, or LLILFallback"""
    return FunctionFormatter(func, names, forms).lines(hlil)


class FunctionFormatter:
    def __init__(self, func: Function, names: ScriptNames, forms: type[ED9Forms]):
        self.func = func
        self.names = names
        self.forms = forms
        self.param_names = {Formatter.param_name(index) for index in range(len(func.params))}
        self.locals: list[str] = []

    def lines(self, hlil: HighLevelILFunction) -> list[str]:
        statements = code_statements(hlil.body)
        body = [line for printed in self.printed_statements(statements) for line in printed]
        if not statements or not ends_path(statements[-1]):
            raise LLILFallback('no final return')

        return [HLIL_DECORATOR, f'def {self.func.name}({Formatter.format_params(self.func.params)}):',
                *(f'{INDENT}{name} = Local({name!r})' for name in self.locals),
                *(f'{INDENT}{line}' for line in body)]

    # Statements

    def printed_statements(self, statements: list[HLILStatement]) -> list[list[str]]:
        """Each DSL statement's lines"""
        printed_lines = []
        position = 0
        while position < len(statements):
            following = statements[position + 1] if position + 1 < len(statements) else None
            printed = self.statement(statements[position], following)
            printed_lines.append(printed.lines)
            position += printed.statements

        return printed_lines

    def statement(self, statement: HLILStatement, following: HLILStatement | None) -> Printed:
        match statement:
            case HLILExprStmt(expr=HLILCall() | HLILSyscall() | HLILExternCall()):
                return Printed([self.call(statement.expr)], 1)

            case HLILExprStmt():
                raise LLILFallback('expression statement')

            case HLILAssign():
                return self.assign(statement, following)

            case HLILReturn(value=None):
                raise LLILFallback('return without value')

            case HLILReturn() if self.forms.is_raw_zero(statement.value):
                return Printed(['Return()'], 1)

            case HLILReturn():
                return Printed([f'Return({self.text(statement.value)})'], 1)

            case HLILIntrinsic():
                return Printed([self.forms.intrinsic(statement.name, statement.args, self.text)], 1)

            case HLILIf():
                return Printed(self.if_lines(statement), 1)

            case HLILWhile() | HLILDoWhile():
                raise LLILFallback('loop')

            case HLILSwitch():
                raise LLILFallback('switch')

        raise LLILFallback(type(statement).__name__)

    def assign(self, statement: HLILAssign, following: HLILStatement | None) -> Printed:
        if not isinstance(statement.dest, HLILVar):
            raise LLILFallback(ADDRESS_TAKEN if isinstance(statement.dest, HLILDeref) else 'assign dest')

        var = statement.dest.var
        if self.is_declared(var):
            return Printed([f'Set({self.variable(var)}, {self.text(statement.src)})'], 1)

        return self.declare_local(var.name, statement.src, following)

    def is_declared(self, var: HLILVariable) -> bool:
        """A global, a register, a parameter or a local declared already: a store to it is a Set"""
        return (var.kind in (VariableKind.GLOBAL, VariableKind.REG) or var.name in self.param_names
                or var.name in self.locals)

    def declare_local(self, name: str, declaring_push: HLILExpression, following: HLILStatement | None) -> Printed:
        """The compiler's declaring push of a local: Let(name), or Let(name, value) when its store follows at once"""
        if is_temporary(name):
            raise LLILFallback('temporary')

        if not is_identifier(name) or name in self.names.reserved or name in self.names.functions:
            raise LLILFallback('local name clash')

        if not self.forms.is_raw_zero(declaring_push):
            raise LLILFallback('declaring push not Raw 0')

        self.locals.append(name)
        if is_store_to_local(following, name):
            return Printed([f'Let({name}, {self.text(following.src)})'], 2)

        return Printed([f'Let({name})'], 1)

    def if_lines(self, statement: HLILIf) -> list[str]:
        """If(test, [...]), then .ElseIf(test, [...]) for an else holding one if and nothing else, then .Else([...]).
        An else-less if whose test is HLIL's E == 0 is the code's if (E) {} else {...}: an empty arm the structuring
        dropped, its test negated (the check refuses one that is a jump if not zero instead)"""
        lines = ['']
        opener = 'If'
        while True:
            then_statements = code_statements(statement.true_block)
            else_statements = code_statements(statement.false_block) if statement.false_block is not None else []
            if not else_statements and is_zero_test(statement.condition, BinaryOp.EQ):
                self.append_arm(lines, f'{opener}({self.text(statement.condition.lhs)}, ', [])
                self.append_arm(lines, '.Else(', then_statements)
                return lines

            self.append_arm(lines, f'{opener}({self.condition(statement.condition)}, ', then_statements)
            if not else_statements:
                return lines

            if len(else_statements) == 1 and isinstance(else_statements[0], HLILIf):
                statement, opener = else_statements[0], '.ElseIf'
                continue

            self.append_arm(lines, '.Else(', else_statements)
            return lines

    def append_arm(self, lines: list[str], head: str, statements: list[HLILStatement]):
        """head, the block's list, one statement per line with a trailing comma, and the closing parenthesis, from
        the end of lines' last line"""
        if not statements:
            lines[-1] += f'{head}[])'
            return

        lines[-1] += f'{head}['
        for printed in self.printed_statements(statements):
            lines.extend(f'{INDENT}{line}' for line in printed[:-1])
            lines.append(f'{INDENT}{printed[-1]},')

        lines.append('])')

    def condition(self, condition: HLILExpression) -> str:
        """The test an arm's jump makes, POP_JMP_ZERO past the arm: HLIL's outermost != 0 against a plain 0 is the
        jump's own, printed bare; an outermost == 0 is the jump's test negated, which no form with an else lowers to"""
        if is_zero_test(condition, BinaryOp.NE):
            return self.text(condition.lhs)

        if is_zero_test(condition, BinaryOp.EQ):
            raise LLILFallback('negated test')

        return self.text(condition)

    # Expressions: (text, its binding strength)

    def text(self, expr: HLILExpression) -> str:
        return self.expr_and_strength(expr)[0]

    def expr_and_strength(self, expr: HLILExpression, wrapped: bool = False) -> tuple[str, Binding]:
        match expr:
            case HLILConst():
                text = self.forms.constant(expr.value, wrapped)
                return text, Binding.UNARY if text.startswith('-') else Binding.ATOM

            case HLILVar():
                return self.variable(expr.var), Binding.ATOM

            case HLILBinaryOp():
                return self.binary(expr)

            case HLILUnaryOp():
                return self.unary(expr)

            case HLILCall() | HLILSyscall() | HLILExternCall():
                return self.call(expr), Binding.ATOM

            case HLILAddressOf():
                raise LLILFallback(ADDRESS_TAKEN)

            case HLILDeref():
                raise LLILFallback(ADDRESS_TAKEN if unwrap_address_taken_var(expr) is not None else 'deref')

        raise LLILFallback(type(expr).__name__)

    def binary(self, expr: HLILBinaryOp) -> tuple[str, Binding]:
        if expr.op in EAGER_LOGIC:
            return self.eager_logic(expr), Binding.ATOM

        if expr.op in SHORT_CIRCUIT:
            raise LLILFallback('short-circuit')

        if expr.op not in BINARY_FORMS:
            raise LLILFallback(f'operator {expr.op.name}')

        symbol, strength = BINARY_FORMS[expr.op]
        left, left_strength = self.expr_and_strength(expr.lhs, wrapped=self.left_literal_wrapped(expr, strength))
        right, right_strength = self.expr_and_strength(expr.rhs)
        if left_needs_parentheses(left_strength, strength):
            left = f'({left})'

        if right_needs_parentheses(right_strength, strength):
            right = f'({right})'

        return f'{left} {symbol} {right}', strength

    def left_literal_wrapped(self, expr: HLILBinaryOp, strength: Binding) -> bool:
        """expr's left literal written in its constructor: Python folds two literals, mirrors a comparison with a
        literal on the left (5 < x is x > 5), and runs a string's own % and *"""
        if not self.forms.is_plain_literal(expr.lhs):
            return False

        return (self.forms.is_plain_literal(expr.rhs) or strength == Binding.COMPARISON
                or (isinstance(expr.lhs.value, str) and expr.op in STRING_OPERATORS))

    def eager_logic(self, expr: HLILBinaryOp) -> str:
        """And(a, b, c) / Or(...), the left spine flat, as And builds it"""
        operands = []
        node = expr
        while isinstance(node, HLILBinaryOp) and node.op == expr.op:
            operands.append(node.rhs)
            node = node.lhs

        operands.append(node)
        return f'{EAGER_LOGIC[expr.op]}({', '.join(self.text(operand) for operand in reversed(operands))})'

    def unary(self, expr: HLILUnaryOp) -> tuple[str, Binding]:
        if expr.op == UnaryOp.NOT:
            return f'Not({self.text(expr.operand)})', Binding.ATOM

        # Python folds an operator on a literal (-5, ~8)
        text, strength = self.expr_and_strength(expr.operand, wrapped=self.forms.is_plain_literal(expr.operand))
        if strength < Binding.UNARY:
            text = f'({text})'

        return f'{UNARY_SYMBOLS[expr.op]}{text}', Binding.UNARY

    def variable(self, var: HLILVariable) -> str:
        match var.kind:
            case VariableKind.GLOBAL:
                name = self.names.global_name(var.index)
                if name is None:
                    raise LLILFallback('unnamed global')

                if not is_attribute_name(name):
                    raise LLILFallback('global name')

                return f'this.{name}'

            case VariableKind.REG:
                return self.forms.register(var.index)

        # A parameter or a local
        if var.name in self.param_names:
            return var.name

        if is_temporary(var.name):
            raise LLILFallback('temporary')

        if var.name not in self.locals:
            raise LLILFallback('local read before its declaration')

        return var.name

    def call(self, expr: HLILCall | HLILSyscall | HLILExternCall) -> str:
        args = [self.text(arg) for arg in expr.args]
        match expr:
            case HLILCall():
                name = expr.func_name
                if not is_identifier(name) or name in self.names.reserved or name in self.param_names:
                    raise LLILFallback('callee name clash')

                return f'{name}({', '.join(args)})'

            case HLILExternCall():
                module, _, name = expr.target.partition(':')
                if not (is_attribute_name(module) and is_attribute_name(name)):
                    raise LLILFallback('script call name')

                return f'script.{module}.{name}({', '.join(args)})'

            case HLILSyscall():
                return self.forms.syscall(expr.subsystem, expr.cmd, args)

        raise LLILFallback(type(expr).__name__)
