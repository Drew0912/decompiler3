'''HLIL - Structured control flow (if/while/do-while) from unstructured MLIL (goto/label)'''

from typing import List, Optional, Tuple, Union
from enum import auto
from common import *


class HLILTypeKind(IntEnum2):
    '''HLIL type kinds'''
    UNKNOWN = auto()
    INT     = auto()
    FLOAT   = auto()
    STRING  = auto()
    BOOL    = auto()
    VOID    = auto()


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
        self.mlil_index: int = -1  # Source MLIL instruction index (for debugging/mapping)

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

    def __init__(self, name: Optional[str] = None, type_hint: Optional[str] = None, default_value: Optional[str] = None,
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
            # Display as unsigned 32-bit hex
            unsigned = self.value & 0xFFFFFFFF
            return f'0x{unsigned:08X}'

        return str(self.value)

    def __repr__(self) -> str:
        return f'HLILConst({self.value})'


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


def split_else_if_arm(block: HLILBlock) -> Optional[Tuple[List[HLILComment], HLILIf]]:
    '''An else arm's comments and its single inner if, or None if it is not an else-if

    Comments annotate the inner if's test, so they belong before the `} else if` line
    rather than inside the arm. Shared so both renderers agree on the shape.
    '''
    if not block or not block.statements:
        return None

    comments = [stmt for stmt in block.statements if isinstance(stmt, HLILComment)]
    rest = [stmt for stmt in block.statements if not isinstance(stmt, HLILComment)]

    if len(rest) != 1 or not isinstance(rest[0], HLILIf):
        return None

    return comments, rest[0]


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
