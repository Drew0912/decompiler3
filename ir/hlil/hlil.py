'''HLIL - Structured control flow (if/while/do-while) from unstructured MLIL (goto/label)'''

from typing import Callable, Iterator, List, Optional, Sequence, Tuple, Union
from enum import auto
import operator
from common import *
from ir.core import UNASSIGNED_INST_INDEX


class HLILTypeKind(IntEnum2):
    '''HLIL type kinds'''
    UNKNOWN = auto()
    INT     = auto()
    FLOAT   = auto()
    STRING  = auto()
    BOOL    = auto()
    VOID    = auto()
    POINTER = auto()    # Out-parameter: a stack address the callee writes through
    NUMBER  = auto()    # Int or float


class BinaryOp(IntEnum2):
    '''Binary operators'''
    # Arithmetic
    ADD     = auto()
    SUB     = auto()
    MUL     = auto()
    DIV     = auto()
    MOD     = auto()

    # Comparison
    EQ      = auto()
    NE      = auto()
    LT      = auto()
    LE      = auto()
    GT      = auto()
    GE      = auto()

    # Logical
    AND     = auto()
    OR      = auto()

    # Bitwise
    BIT_AND = auto()
    BIT_OR  = auto()
    BIT_XOR = auto()
    SHL     = auto()
    SHR     = auto()


class UnaryOp(IntEnum2):
    '''Unary operators'''
    NEG     = auto()
    NOT     = auto()
    BIT_NOT = auto()


class HLILOperation(IntEnum2):
    '''HLIL operation types'''
    # Control flow statements
    HLIL_IF             = auto()
    HLIL_WHILE          = auto()
    HLIL_DO_WHILE       = auto()
    HLIL_SWITCH         = auto()
    HLIL_BREAK          = auto()
    HLIL_CONTINUE       = auto()
    HLIL_RETURN         = auto()
    HLIL_UNSTRUCTURED   = auto()

    # Other statements
    HLIL_BLOCK          = auto()
    HLIL_ASSIGN         = auto()
    HLIL_EXPR_STMT      = auto()
    HLIL_COMMENT        = auto()

    # Expressions
    HLIL_VAR            = auto()
    HLIL_CONST          = auto()
    HLIL_BINARY_OP      = auto()
    HLIL_UNARY_OP       = auto()
    HLIL_ADDRESS_OF     = auto()
    HLIL_DEREF          = auto()
    HLIL_CALL           = auto()
    HLIL_SYSCALL        = auto()


class HLILInstruction:
    '''Base class for all HLIL instructions'''

    def __init__(self, operation: HLILOperation):
        self.operation = operation
        self.address: int = 0  # Source SCP bytecode offset (inherited from MLIL)
        self.mlil_index: int = UNASSIGNED_INST_INDEX  # Source MLIL instruction index (for debugging/mapping)

    def __str__(self) -> str:
        return f'{self.operation.name}'

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}()'


class HLILStatement(HLILInstruction):
    '''Base class for HLIL statements'''
    pass


class HLILExpression(HLILInstruction):
    '''Base class for HLIL expressions'''
    pass


# ============================================================================
# Variables and Types
# ============================================================================

class VariableKind(IntEnum2):
    '''Variable storage kind'''
    LOCAL   = auto()
    PARAM   = auto()
    GLOBAL  = auto()
    REG     = auto()


class HLILVariable:
    '''HLIL variable with optional type information'''

    def __init__(self, name: Optional[str] = None, type_hint: Optional[HLILTypeKind] = None, default_value: Optional[str] = None,
                 kind: VariableKind = None, index: Optional[int] = None):
        self.name = name
        self.type_hint = type_hint
        self.default_value = default_value
        self.kind = kind if kind is not None else VariableKind.LOCAL
        self.index = index  # For GLOBAL/REG: the slot index

    def __str__(self) -> str:
        if self.kind == VariableKind.GLOBAL:
            return f'GLOBALS[{self.index}]'

        elif self.kind == VariableKind.REG:
            return f'REGS[{self.index}]'

        return self.name

    def __repr__(self) -> str:
        if self.type_hint:
            return f'HLILVariable({self.name}: {self.type_hint})'
        return f'HLILVariable({self.name})'

    def __eq__(self, other) -> bool:
        if not isinstance(other, HLILVariable):
            return False
        return self.name == other.name and self.kind == other.kind and self.index == other.index

    def __hash__(self) -> int:
        return hash(self.name)


# ============================================================================
# Expressions
# ============================================================================

class HLILVar(HLILExpression):
    '''Variable reference'''

    def __init__(self, var: HLILVariable):
        super().__init__(HLILOperation.HLIL_VAR)
        self.var = var

    def __str__(self) -> str:
        return str(self.var)

    def __repr__(self) -> str:
        return f'HLILVar({self.var.name})'


class HLILConst(HLILExpression):
    '''Constant value'''

    def __init__(self, value: Union[int, float, str, bool], is_hex: bool = False):
        super().__init__(HLILOperation.HLIL_CONST)
        self.value = value
        self.is_hex = is_hex

    def __str__(self) -> str:
        if isinstance(self.value, str):
            return f'"{self.value}"'

        elif isinstance(self.value, bool):
            return 'true' if self.value else 'false'

        elif isinstance(self.value, int) and self.is_hex:
            return format_uint32_hex(self.value)

        return str(self.value)

    def __repr__(self) -> str:
        return f'HLILConst({self.value})'


# ============================================================================
# Operator Semantics (language-neutral - shared by every output language)
# ============================================================================

COMPARISON_OPS = frozenset({BinaryOp.EQ, BinaryOp.NE, BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE})

# Binary operators whose result is a boolean
BOOLEAN_BINARY_OPS = COMPARISON_OPS | {BinaryOp.AND, BinaryOp.OR}

# !(a op b) == a NEGATED_COMPARISON_OP[op] b
NEGATED_COMPARISON_OP = {
    BinaryOp.EQ : BinaryOp.NE,
    BinaryOp.NE : BinaryOp.EQ,
    BinaryOp.LT : BinaryOp.GE,
    BinaryOp.LE : BinaryOp.GT,
    BinaryOp.GT : BinaryOp.LE,
    BinaryOp.GE : BinaryOp.LT,
}

# De Morgan's: negating && / || swaps the operator
DE_MORGAN_OP = {
    BinaryOp.AND : BinaryOp.OR,
    BinaryOp.OR  : BinaryOp.AND,
}

# What each comparison computes, for evaluating one between two constants
COMPARISON_FUNCTIONS = {
    BinaryOp.EQ : operator.eq,
    BinaryOp.NE : operator.ne,
    BinaryOp.LT : operator.lt,
    BinaryOp.LE : operator.le,
    BinaryOp.GT : operator.gt,
    BinaryOp.GE : operator.ge,
}


# ============================================================================
# C-Family Syntax (TypeScript codegen and the debug formatter - a non-C output
# needs its own symbols and precedence)
# ============================================================================

BINARY_OP_STR = {
    BinaryOp.ADD        : '+',
    BinaryOp.SUB        : '-',
    BinaryOp.MUL        : '*',
    BinaryOp.DIV        : '/',
    BinaryOp.MOD        : '%',
    BinaryOp.EQ         : '==',
    BinaryOp.NE         : '!=',
    BinaryOp.LT         : '<',
    BinaryOp.LE         : '<=',
    BinaryOp.GT         : '>',
    BinaryOp.GE         : '>=',
    BinaryOp.AND        : '&&',
    BinaryOp.OR         : '||',
    BinaryOp.BIT_AND    : '&',
    BinaryOp.BIT_OR     : '|',
    BinaryOp.BIT_XOR    : '^',
    BinaryOp.SHL        : '<<',
    BinaryOp.SHR        : '>>',
}

UNARY_OP_STR = {
    UnaryOp.NEG         : '-',
    UnaryOp.NOT         : '!',
    UnaryOp.BIT_NOT     : '~',
}

# Higher binds tighter
BINARY_OP_PRECEDENCE = {
    BinaryOp.OR         : 1,
    BinaryOp.AND        : 2,
    BinaryOp.BIT_OR     : 3,
    BinaryOp.BIT_XOR    : 4,
    BinaryOp.BIT_AND    : 5,
    BinaryOp.EQ         : 6,
    BinaryOp.NE         : 6,
    BinaryOp.LT         : 7,
    BinaryOp.LE         : 7,
    BinaryOp.GT         : 7,
    BinaryOp.GE         : 7,
    BinaryOp.SHL        : 8,
    BinaryOp.SHR        : 8,
    BinaryOp.ADD        : 9,
    BinaryOp.SUB        : 9,
    BinaryOp.MUL        : 10,
    BinaryOp.DIV        : 10,
    BinaryOp.MOD        : 10,
}

# a - (b - c) is not (a - b) - c
NON_ASSOCIATIVE_OPS = frozenset({BinaryOp.SUB, BinaryOp.DIV, BinaryOp.MOD})


def needs_parentheses(child_op: BinaryOp, parent_op: BinaryOp, is_left: bool) -> bool:
    '''Whether a binary child printed as parent_op's lhs (is_left) or rhs needs parentheses'''
    child_precedence = BINARY_OP_PRECEDENCE[child_op]
    parent_precedence = BINARY_OP_PRECEDENCE[parent_op]

    if child_precedence != parent_precedence:
        return child_precedence < parent_precedence

    return not is_left and parent_op in NON_ASSOCIATIVE_OPS


class HLILBinaryOp(HLILExpression):
    '''Binary operation: lhs op rhs'''

    def __init__(self, op: BinaryOp, lhs: HLILExpression, rhs: HLILExpression):
        super().__init__(HLILOperation.HLIL_BINARY_OP)
        self.op = op
        self.lhs = lhs
        self.rhs = rhs

    def __str__(self) -> str:
        return f'{self.lhs} {BINARY_OP_STR[self.op]} {self.rhs}'

    def __repr__(self) -> str:
        return f'HLILBinaryOp({self.op.name})'


class HLILUnaryOp(HLILExpression):
    '''Unary operation: op operand'''

    def __init__(self, op: UnaryOp, operand: HLILExpression):
        super().__init__(HLILOperation.HLIL_UNARY_OP)
        self.op = op
        self.operand = operand

    def __str__(self) -> str:
        return f'{UNARY_OP_STR[self.op]}{self.operand}'

    def __repr__(self) -> str:
        return f'HLILUnaryOp({self.op.name})'


class HLILAddressOf(HLILExpression):
    '''Address-of operation: &var'''

    def __init__(self, operand: HLILExpression):
        super().__init__(HLILOperation.HLIL_ADDRESS_OF)
        self.operand = operand

    def __str__(self) -> str:
        return f'&{self.operand}'

    def __repr__(self) -> str:
        return f'HLILAddressOf({self.operand})'


class HLILDeref(HLILExpression):
    '''Pointer dereference: *ptr'''

    def __init__(self, operand: HLILExpression):
        super().__init__(HLILOperation.HLIL_DEREF)
        self.operand = operand

    def __str__(self) -> str:
        # Wrap a compound address so *p + 1 (meaning (*p) + 1) can't be confused with the
        # intended *(p + 1) - only debug text, real codegen builds a deref(...) call instead.
        operand_str = f'({self.operand})' if isinstance(self.operand, HLILBinaryOp) else str(self.operand)
        return f'*{operand_str}'

    def __repr__(self) -> str:
        return f'HLILDeref({self.operand})'


class HLILCall(HLILExpression):
    '''Function call'''

    def __init__(self, func_name: str, args: List[HLILExpression]):
        super().__init__(HLILOperation.HLIL_CALL)
        self.func_name = func_name
        self.args = args

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'{self.func_name}({args_str})'

    def __repr__(self) -> str:
        return f'HLILCall({self.func_name}, {len(self.args)} args)'


class HLILSyscall(HLILExpression):
    '''System call'''

    def __init__(self, subsystem: str, cmd: str, args: List[HLILExpression]):
        super().__init__(HLILOperation.HLIL_SYSCALL)
        self.subsystem = subsystem
        self.cmd = cmd
        self.args = args

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'{self.subsystem}.{self.cmd}({args_str})'

    def __repr__(self) -> str:
        return f'HLILSyscall({self.subsystem}.{self.cmd})'


class HLILExternCall(HLILExpression):
    '''External module call (e.g., script call)'''

    def __init__(self, target: str, args: List[HLILExpression]):
        super().__init__(HLILOperation.HLIL_CALL)
        self.target = target  # Format: "module:func"
        self.args = args

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return f'{self.target}({args_str})'

    def __repr__(self) -> str:
        return f'HLILExternCall({self.target}, {len(self.args)} args)'


# ============================================================================
# Control Flow Statements
# ============================================================================

class HLILBlock(HLILStatement):
    '''Block of statements'''

    def __init__(self, statements: Optional[List[HLILStatement]] = None):
        super().__init__(HLILOperation.HLIL_BLOCK)
        self.statements = statements or []

    def add_statement(self, stmt: HLILStatement):
        '''Add a statement to the block'''
        self.statements.append(stmt)

    def __str__(self) -> str:
        if not self.statements:
            return '{ }'
        return f'{{ {len(self.statements)} statements }}'

    def __repr__(self) -> str:
        return f'HLILBlock({len(self.statements)} stmts)'


class HLILIf(HLILStatement):
    '''Conditional: if (cond) { ... } else { ... }'''

    def __init__(self, condition: HLILExpression, true_block: 'HLILBlock', false_block: Optional['HLILBlock'] = None):
        super().__init__(HLILOperation.HLIL_IF)
        self.condition = condition
        self.true_block = true_block
        self.false_block = false_block

    def __str__(self) -> str:
        if self.false_block:
            return f'if ({self.condition}) {{ ... }} else {{ ... }}'
        return f'if ({self.condition}) {{ ... }}'

    def __repr__(self) -> str:
        return f'HLILIf(cond={self.condition})'


class HLILWhile(HLILStatement):
    '''While loop: while (cond) { ... }, optionally labeled for cross-level break/continue'''

    def __init__(self, condition: HLILExpression, body: 'HLILBlock', label: Optional[str] = None):
        super().__init__(HLILOperation.HLIL_WHILE)
        self.condition = condition
        self.body = body
        self.label = label

    def __str__(self) -> str:
        prefix = f'{self.label}: ' if self.label else ''
        return f'{prefix}while ({self.condition}) {{ ... }}'

    def __repr__(self) -> str:
        return f'HLILWhile(cond={self.condition})'


class HLILDoWhile(HLILStatement):
    '''Do-while loop: do { ... } while (cond);, optionally labeled for cross-level break/continue'''

    def __init__(self, condition: HLILExpression, body: 'HLILBlock', label: Optional[str] = None):
        super().__init__(HLILOperation.HLIL_DO_WHILE)
        self.condition = condition
        self.body = body
        self.label = label

    def __str__(self) -> str:
        prefix = f'{self.label}: ' if self.label else ''
        return f'{prefix}do {{ ... }} while ({self.condition})'

    def __repr__(self) -> str:
        return f'HLILDoWhile(cond={self.condition})'


class HLILSwitchCase:
    '''Switch case: one body, reached by one or more labels

    Several values share a body when the source tested them against one another
    with ||, which is what a fall-through group of case labels means.
    '''

    def __init__(self, values: Optional[List[HLILExpression]], body: 'HLILBlock'):
        self.values = values  # None for default case
        self.body = body

    def is_default(self) -> bool:
        '''Check if this is the default case'''
        return self.values is None

    def _label_str(self) -> str:
        return ', '.join(str(value) for value in self.values)

    def __str__(self) -> str:
        if self.is_default():
            return 'default: { ... }'
        return f'case {self._label_str()}: {{ ... }}'

    def __repr__(self) -> str:
        if self.is_default():
            return 'HLILSwitchCase(default)'
        return f'HLILSwitchCase({self._label_str()})'


class HLILSwitch(HLILStatement):
    '''Switch statement: switch (scrutinee) { case ...: ... }'''

    def __init__(self, scrutinee: HLILExpression, cases: List[HLILSwitchCase]):
        super().__init__(HLILOperation.HLIL_SWITCH)
        self.scrutinee = scrutinee
        self.cases = cases

    def __str__(self) -> str:
        return f'switch ({self.scrutinee}) {{ {len(self.cases)} cases }}'

    def __repr__(self) -> str:
        return f'HLILSwitch({len(self.cases)} cases)'


class HLILBreak(HLILStatement):
    '''Break statement, optionally labeled for breaking an outer loop'''

    def __init__(self, label: Optional[str] = None):
        super().__init__(HLILOperation.HLIL_BREAK)
        self.label = label

    def __str__(self) -> str:
        return f'break {self.label}' if self.label else 'break'

    def __repr__(self) -> str:
        return f'HLILBreak({self.label})' if self.label else 'HLILBreak()'


class HLILContinue(HLILStatement):
    '''Continue statement, optionally labeled for continuing an outer loop'''

    def __init__(self, label: Optional[str] = None):
        super().__init__(HLILOperation.HLIL_CONTINUE)
        self.label = label

    def __str__(self) -> str:
        return f'continue {self.label}' if self.label else 'continue'

    def __repr__(self) -> str:
        return f'HLILContinue({self.label})' if self.label else 'HLILContinue()'


class HLILReturn(HLILStatement):
    '''Return statement'''

    def __init__(self, value: Optional[HLILExpression] = None):
        super().__init__(HLILOperation.HLIL_RETURN)
        self.value = value

    def __str__(self) -> str:
        if self.value is not None:
            return f'return {self.value}'
        return 'return'

    def __repr__(self) -> str:
        return f'HLILReturn({self.value})'


class HLILUnstructured(HLILStatement):
    '''A jump HLIL cannot express (HLIL has no goto): the path ends here, visibly, instead of
    falling through to whatever follows'''

    def __init__(self, target: str, reason: str):
        super().__init__(HLILOperation.HLIL_UNSTRUCTURED)
        self.target = target
        self.reason = reason

    def __str__(self) -> str:
        return f'unstructured jump to {self.target} ({self.reason})'

    def __repr__(self) -> str:
        return f'HLILUnstructured({self.target})'


# Statements that never fall through to the next statement in their block
TERMINAL_STATEMENTS = (HLILReturn, HLILBreak, HLILContinue, HLILUnstructured)


# ============================================================================
# Other Statements
# ============================================================================

class HLILAssign(HLILStatement):
    '''Assignment: dest = src'''

    def __init__(self, dest: HLILExpression, src: HLILExpression):
        super().__init__(HLILOperation.HLIL_ASSIGN)
        self.dest = dest
        self.src = src

    def __str__(self) -> str:
        return f'{self.dest} = {self.src}'

    def __repr__(self) -> str:
        return f'HLILAssign({self.dest} = {self.src})'


class HLILExprStmt(HLILStatement):
    '''Expression statement (for side effects)'''

    def __init__(self, expr: HLILExpression):
        super().__init__(HLILOperation.HLIL_EXPR_STMT)
        self.expr = expr

    def __str__(self) -> str:
        return f'{self.expr}'

    def __repr__(self) -> str:
        return f'HLILExprStmt({self.expr})'


class HLILComment(HLILStatement):
    '''Comment statement (debug/annotations)'''

    def __init__(self, text: str):
        super().__init__(HLILOperation.HLIL_COMMENT)
        self.text = text

    def __str__(self) -> str:
        return f'// {self.text}'

    def __repr__(self) -> str:
        return f'HLILComment({self.text})'


def is_boolean_expr(expr: HLILExpression) -> bool:
    '''Whether expr's value is a boolean: a comparison, && / ||, or !'''
    if isinstance(expr, HLILBinaryOp):
        return expr.op in BOOLEAN_BINARY_OPS

    return isinstance(expr, HLILUnaryOp) and expr.op == UnaryOp.NOT


def negate_condition(cond: HLILExpression) -> HLILExpression:
    '''Negate a condition, distributing through && / || (De Morgan's) rather than wrapping them'''
    # Double negation: !!a -> a
    if isinstance(cond, HLILUnaryOp) and cond.op == UnaryOp.NOT:
        return cond.operand

    # Comparison negation: !(a == b) -> a != b
    if isinstance(cond, HLILBinaryOp) and cond.op in NEGATED_COMPARISON_OP:
        return HLILBinaryOp(NEGATED_COMPARISON_OP[cond.op], cond.lhs, cond.rhs)

    # De Morgan's: !(a && b) -> !a || !b, !(a || b) -> !a && !b
    if isinstance(cond, HLILBinaryOp) and cond.op in DE_MORGAN_OP:
        return HLILBinaryOp(DE_MORGAN_OP[cond.op], negate_condition(cond.lhs), negate_condition(cond.rhs))

    # Default: wrap with NOT
    return HLILUnaryOp(UnaryOp.NOT, cond)


def constant_truth(cond: HLILExpression) -> Optional[bool]:
    '''The value a condition always has - an int constant, a comparison of two int constants, or !, &&
    and || over such conditions - or None otherwise. Float truth and comparisons are unverified in the VM.'''
    if isinstance(cond, HLILConst):
        return bool(cond.value) if isinstance(cond.value, int) else None

    if isinstance(cond, HLILUnaryOp) and cond.op == UnaryOp.NOT:
        inner = constant_truth(cond.operand)
        return None if inner is None else not inner

    if not isinstance(cond, HLILBinaryOp):
        return None

    if cond.op in COMPARISON_FUNCTIONS:
        operands = (cond.lhs, cond.rhs)
        if all(isinstance(o, HLILConst) and isinstance(o.value, int) for o in operands):
            return COMPARISON_FUNCTIONS[cond.op](cond.lhs.value, cond.rhs.value)

        return None

    if cond.op in DE_MORGAN_OP:
        # True decides || on its own, False decides &&
        decisive = cond.op == BinaryOp.OR
        sides = (constant_truth(cond.lhs), constant_truth(cond.rhs))

        if decisive in sides:
            return decisive

        if sides == (not decisive, not decisive):
            return not decisive

    return None


def sole_statement(block: Optional[HLILBlock]) -> Optional[HLILStatement]:
    '''The one non-comment statement in block, or None when it has none or several'''
    if block is None:
        return None

    rest = [stmt for stmt in block.statements if not isinstance(stmt, HLILComment)]
    return rest[0] if len(rest) == 1 else None


def split_else_if_arm(block: HLILBlock) -> Optional[Tuple[List[HLILComment], HLILIf]]:
    '''An else arm's comments and its single inner if, or None if it is not an else-if

    Comments annotate the inner if's test, so they belong before the `} else if` line
    rather than inside the arm. Shared so both renderers agree on the shape.
    '''
    inner_if = sole_statement(block)
    if not isinstance(inner_if, HLILIf):
        return None

    return [stmt for stmt in block.statements if isinstance(stmt, HLILComment)], inner_if


def unwrap_address_taken_var(expr: 'HLILExpression') -> Optional['HLILVar']:
    '''*(&x) - ir/mlil/mlil_ssa.py's memory-form lowering of address-taken local x -
    collapses to plain x. Returns the HLILVar, or None if expr is not that exact shape.
    Shared by every consumer of this shape (the TS codegen, the debug formatter, and CFO's
    modifies-check) so they cannot independently drift on what counts as the canonical form.'''
    if (isinstance(expr, HLILDeref) and isinstance(expr.operand, HLILAddressOf)
            and isinstance(expr.operand.operand, HLILVar)):
        return expr.operand.operand

    return None


def sub_blocks(stmt: 'HLILStatement') -> List['HLILBlock']:
    '''Blocks directly owned by a structured statement - HLILIf's arms, a loop's body, each
    HLILSwitch case's body. Shared so a new statement type needs one edit here, not one per
    walker (CLAUDE.md -0.04).'''
    if isinstance(stmt, HLILIf):
        blocks = [stmt.true_block]
        if stmt.false_block is not None:
            blocks.append(stmt.false_block)
        return blocks

    if isinstance(stmt, (HLILWhile, HLILDoWhile)):
        return [stmt.body]

    if isinstance(stmt, HLILSwitch):
        return [case.body for case in stmt.cases]

    return []


def expr_children(node: HLILInstruction) -> Sequence[HLILExpression]:
    '''Direct sub-expressions of an expression, in evaluation order - none for a leaf'''
    if isinstance(node, HLILBinaryOp):
        return [node.lhs, node.rhs]

    if isinstance(node, (HLILUnaryOp, HLILAddressOf, HLILDeref)):
        return [node.operand]

    if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
        return list(node.args)

    return []


def stmt_children(node: HLILInstruction) -> Sequence[HLILInstruction]:
    '''Every direct child of node - statements, blocks and expressions - in source order. A
    switch contributes each case's labels, then that case's body.'''
    if isinstance(node, HLILAssign):
        return [node.dest, node.src]

    if isinstance(node, HLILExprStmt):
        return [node.expr]

    if isinstance(node, HLILReturn):
        return [node.value] if node.value is not None else []

    if isinstance(node, HLILBlock):
        return list(node.statements)

    if isinstance(node, HLILIf):
        return [node.condition, *sub_blocks(node)]

    if isinstance(node, HLILWhile):
        return [node.condition, node.body]

    if isinstance(node, HLILDoWhile):
        return [node.body, node.condition]

    if isinstance(node, HLILSwitch):
        children = [node.scrutinee]
        for case in node.cases:
            children.extend(case.values or [])
            children.append(case.body)

        return children

    return expr_children(node)


def read_children(node: HLILInstruction) -> Sequence[HLILInstruction]:
    '''stmt_children without a plain assignment target: writing x does not read it, while a
    store through a pointer (*p = v) still reads p'''
    if isinstance(node, HLILAssign) and not isinstance(node.dest, HLILDeref):
        return [node.src]

    return stmt_children(node)


def iter_tree(node: Optional[HLILInstruction],
              children: Callable[[HLILInstruction], Sequence[HLILInstruction]] = stmt_children,
              exclude: Tuple[int, ...] = ()) -> Iterator[HLILInstruction]:
    '''node and everything below it, pre-order in children's order, without recursion. A node
    whose id() is in exclude is skipped together with everything below it.'''
    pending = [node]
    while pending:
        current = pending.pop()
        if current is None or id(current) in exclude:
            continue

        yield current
        pending.extend(reversed(children(current)))


def contains_escaping_exit(block: Optional[HLILBlock], exit_type: type, include_labeled: bool = False) -> bool:
    '''Whether block holds an exit_type statement (HLILBreak or HLILContinue) that leaves it: a
    bare one that no construct inside block owns - a loop owns both kinds, a switch only a
    break - or, with include_labeled, a labeled one anywhere, since its label may name a loop
    outside block.'''
    return _contains_escaping_exit(block, exit_type, include_labeled, owned = False)


def _contains_escaping_exit(block: Optional[HLILBlock], exit_type: type, include_labeled: bool, owned: bool) -> bool:
    if block is None:
        return False

    for stmt in block.statements:
        if isinstance(stmt, exit_type) and (include_labeled if stmt.label is not None else not owned):
            return True

        owner = isinstance(stmt, (HLILWhile, HLILDoWhile)) or (exit_type is HLILBreak and isinstance(stmt, HLILSwitch))

        # Only a labeled exit can get out of an owner, and none is being looked for
        if owner and not include_labeled:
            continue

        if any(_contains_escaping_exit(child, exit_type, include_labeled, owned or owner) for child in sub_blocks(stmt)):
            return True

    return False


def contains_bare_break(block: Optional[HLILBlock]) -> bool:
    '''Whether block contains a bare break not owned by a nested loop or switch.'''
    return contains_escaping_exit(block, HLILBreak)


def reachable_statements(block: HLILBlock) -> List[HLILStatement]:
    '''Every statement control can reach from the start of block, nested ones included, in source
    order. Only constant conditions prune (constant_truth: the arm of if (0), the code after a
    while (1) no break leaves), so a statement left out can never run.'''
    reached: List[HLILStatement] = []
    _reach_block(block, reached, [])
    return reached


class _ExitTarget:
    '''A loop or switch that a break inside it (for a loop, also a continue) can leave'''

    def __init__(self, stmt: HLILStatement):
        self.label = getattr(stmt, 'label', None)
        self.is_switch = isinstance(stmt, HLILSwitch)
        self.broken = False
        self.continued = False


def resolve_exit_target(targets: Sequence, label: Optional[str], loop_only: bool):
    '''The innermost of targets - records of the enclosing loops and switches, outermost first,
    each with a label and an is_switch - that a break (loop_only False) or a continue (True)
    carrying label leaves'''
    for target in reversed(targets):
        if label is not None:
            if target.label == label and not target.is_switch:
                return target

        elif not (loop_only and target.is_switch):
            return target

    return None


def _reach_block(block: Optional[HLILBlock], reached: List[HLILStatement], targets: List[_ExitTarget]) -> bool:
    '''Record block's reachable statements; whether control can fall out of its end'''
    if block is None:
        return True

    for stmt in block.statements:
        reached.append(stmt)
        if not _reach_statement(stmt, reached, targets):
            return False

    return True


def _reach_statement(stmt: HLILStatement, reached: List[HLILStatement], targets: List[_ExitTarget]) -> bool:
    '''Record the reachable statements nested in stmt; whether control can fall through past it'''
    if isinstance(stmt, (HLILBreak, HLILContinue)):
        target = resolve_exit_target(targets, stmt.label, loop_only = isinstance(stmt, HLILContinue))
        if target is not None and isinstance(stmt, HLILBreak):
            target.broken = True

        elif target is not None:
            target.continued = True

        return False

    if isinstance(stmt, TERMINAL_STATEMENTS):
        return False

    if isinstance(stmt, HLILIf):
        truth = constant_truth(stmt.condition)
        falls_through = False

        if truth is not False:
            falls_through |= _reach_block(stmt.true_block, reached, targets)

        if truth is not True:
            falls_through |= _reach_block(stmt.false_block, reached, targets)

        return falls_through

    if isinstance(stmt, HLILWhile):
        truth = constant_truth(stmt.condition)
        loop = _ExitTarget(stmt)

        if truth is not False:
            _reach_block(stmt.body, reached, targets + [loop])

        return truth is not True or loop.broken

    if isinstance(stmt, HLILDoWhile):
        loop = _ExitTarget(stmt)
        condition_reached = _reach_block(stmt.body, reached, targets + [loop]) or loop.continued
        return loop.broken or (condition_reached and constant_truth(stmt.condition) is not True)

    if isinstance(stmt, HLILSwitch):
        switch = _ExitTarget(stmt)
        falls_through = not any(case.is_default() for case in stmt.cases)

        for case in stmt.cases:
            falls_through |= _reach_block(case.body, reached, targets + [switch])

        return falls_through or switch.broken

    if isinstance(stmt, HLILBlock):
        return _reach_block(stmt, reached, targets)

    return True


# ============================================================================
# Function Container
# ============================================================================

class HighLevelILFunction:
    '''HLIL function container'''

    def __init__(self, name: str, start_addr: int = 0, *, is_common_func: bool = False):
        self.name = name
        self.start_addr = start_addr
        self.body = HLILBlock()
        self.variables: List[HLILVariable] = []  # Local variables
        self.parameters: List[HLILVariable] = []  # Parameters
        self.is_common_func = is_common_func

    def add_statement(self, stmt: HLILStatement):
        '''Add a statement to the function body'''
        self.body.add_statement(stmt)

    def __str__(self) -> str:
        return f'HighLevelILFunction({self.name}, {len(self.body.statements)} stmts)'

    def __repr__(self) -> str:
        return f'HighLevelILFunction({self.name})'
