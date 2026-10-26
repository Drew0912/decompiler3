"""MLIL - Stack-free IR (variables instead of stack operations)"""

from typing import Any, Callable, Iterator, TYPE_CHECKING

from dc3 import format_uint32_hex, IntEnum2, quote_string
from ir.core import *


UNASSIGNED_SLOT_INDEX = -1

if TYPE_CHECKING:
    from ir.llil import LowLevelILFunction


# === Naming Utilities ===

def mlil_stack_var_name(slot_index: int) -> str:
    """Generate stack variable name (var_s0, var_s1, ...)"""
    return f'var_s{slot_index}'


def mlil_arg_var_name(arg_index: int) -> str:
    """Generate argument variable name (arg0, arg1, ...)"""
    return f'arg{arg_index}'


def mlil_reg_var_name(reg_index: int) -> str:
    """Generate register variable name (reg0, reg1, ...)"""
    return f'reg{reg_index}'


def mlil_global_var_name(global_index: int) -> str:
    """Generate global variable name (global0, global1, ...)"""
    return f'global{global_index}'


class MediumLevelILOperation(IntEnum2):
    """MLIL operations - stack-free version of LLIL"""

    # Constants
    MLIL_CONST              = 0     # Constant value (int/float/str)

    # Variables
    MLIL_VAR                = 10    # Load variable
    MLIL_SET_VAR            = 11    # Store to variable

    # Arithmetic operations
    MLIL_ADD                = 20
    MLIL_SUB                = 21
    MLIL_MUL                = 22
    MLIL_DIV                = 23
    MLIL_MOD                = 24

    # Bitwise operations
    MLIL_AND                = 30
    MLIL_OR                 = 31
    MLIL_XOR                = 32
    MLIL_SHL                = 33
    MLIL_SHR                = 34

    # Logical operations
    MLIL_LOGICAL_AND        = 40
    MLIL_LOGICAL_OR         = 41
    MLIL_LOGICAL_NOT        = 42

    # Comparison operations
    MLIL_EQ                 = 50
    MLIL_NE                 = 51
    MLIL_LT                 = 52
    MLIL_LE                 = 53
    MLIL_GT                 = 54
    MLIL_GE                 = 55

    # Unary operations
    MLIL_NEG                = 60
    MLIL_TEST_ZERO          = 61
    MLIL_ADDRESS_OF         = 62    # Address of variable (&var)
    MLIL_BITWISE_NOT        = 63    # Bitwise NOT (~x)

    # Control flow
    MLIL_GOTO               = 70    # Unconditional jump
    MLIL_IF                 = 71    # Conditional branch
    MLIL_RET                = 72    # Return (with optional value)

    # Function calls
    MLIL_CALL               = 80    # Function call
    MLIL_SYSCALL            = 81    # System call

    # Globals
    MLIL_LOAD_GLOBAL        = 90
    MLIL_STORE_GLOBAL       = 91

    # Registers
    MLIL_LOAD_REG           = 100
    MLIL_STORE_REG          = 101

    # Debug
    MLIL_NOP                = 110
    MLIL_DEBUG              = 111

    # Generic pointer dereference (address computed at runtime, unlike LOAD_GLOBAL/REG which
    # target a statically-known slot)
    MLIL_DEREF              = 120
    MLIL_STORE_DEREF        = 121

    # Falcom VM specific
    MLIL_CALL_SCRIPT        = 1000

    # SSA
    MLIL_PHI                = 2000
    MLIL_VAR_SSA            = 2001
    MLIL_SET_VAR_SSA        = 2002
    MLIL_UNDEF              = 2003


class MediumLevelILInstruction(ILInstruction):
    """Base class for MLIL instructions"""

    def __init__(self, operation: MediumLevelILOperation, *, address: int = 0):
        super().__init__()
        self.operation = operation
        self.address = address
        self.inst_index = UNASSIGNED_INST_INDEX  # Statement number, final once the MLIL pipeline ends
        self.llil_index = UNASSIGNED_INST_INDEX  # Source LLIL instruction index

    @property
    def operation_name(self) -> str:
        return self.operation.name.replace('MLIL_', '')

    def __str__(self) -> str:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.operation_name}>'

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        """Direct expression operands in evaluation order - none for a leaf. Every node holding
        an expression overrides this and rebuild(); walk(), map_operands() and the use collectors
        are built on them."""
        return ()

    def copy_metadata_from(self, source: MediumLevelILInstruction) -> MediumLevelILInstruction:
        """Copy address and index metadata from another MLIL instruction"""
        self.address = source.address
        self.inst_index = source.inst_index
        self.llil_index = source.llil_index
        return self


# === Instruction Categories ===

class MediumLevelILExpr(MediumLevelILInstruction):
    """Base class for value expressions"""


class MediumLevelILStatement(MediumLevelILInstruction):
    """Base class for statements"""


# === Variables ===

class MLILVariable:
    """MLIL variable (non-SSA)"""

    def __init__(self, name: str, slot_index: int = UNASSIGNED_SLOT_INDEX):
        self.name = name
        self.slot_index = slot_index  # Original stack slot (for debugging)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        if self.slot_index != UNASSIGNED_SLOT_INDEX:
            return f'MLILVariable({self.name}, slot={self.slot_index})'
        return f'MLILVariable({self.name})'

    def __eq__(self, other) -> bool:
        return isinstance(other, MLILVariable) and self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)


# === Constants ===

class MLILConst(MediumLevelILExpr, Constant):
    """Constant value (int, float, or string)"""

    def __init__(self, value: Any, is_hex: bool = False, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_CONST, **kwargs)
        self.value = value
        self.is_hex = is_hex

    def __str__(self) -> str:
        if isinstance(self.value, int) and self.is_hex:
            return format_uint32_hex(self.value)

        if isinstance(self.value, str):
            return quote_string(self.value)

        return str(self.value)


class MLILUndef(MediumLevelILExpr):
    """Undefined value (result of call via AddressOf, etc.)"""

    def __init__(self, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_UNDEF, **kwargs)

    def __str__(self) -> str:
        return '<undef>'


# === Variable Operations ===

class MLILVar(MediumLevelILExpr):
    """Load variable value"""

    def __init__(self, var: MLILVariable, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_VAR, **kwargs)
        self.var = var

    def __str__(self) -> str:
        return str(self.var)


class MLILSetVar(MediumLevelILStatement):
    """Store value to variable"""

    def __init__(self, var: MLILVariable, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SET_VAR, **kwargs)
        self.var = var
        self.value = value

    def rebuild(self, value: MediumLevelILInstruction) -> MLILSetVar:
        return MLILSetVar(self.var, value).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'{self.var} = {self.value}'


# === Binary Operations ===

# Each binary operation's operator as the listing prints it
BINARY_OP_SYMBOLS = {
    MediumLevelILOperation.MLIL_ADD         : '+',
    MediumLevelILOperation.MLIL_SUB         : '-',
    MediumLevelILOperation.MLIL_MUL         : '*',
    MediumLevelILOperation.MLIL_DIV         : '/',
    MediumLevelILOperation.MLIL_MOD         : '%',
    MediumLevelILOperation.MLIL_AND         : '&',
    MediumLevelILOperation.MLIL_OR          : '|',
    MediumLevelILOperation.MLIL_XOR         : '^',
    MediumLevelILOperation.MLIL_SHL         : '<<',
    MediumLevelILOperation.MLIL_SHR         : '>>',
    MediumLevelILOperation.MLIL_LOGICAL_AND : '&&',
    MediumLevelILOperation.MLIL_LOGICAL_OR  : '||',
    MediumLevelILOperation.MLIL_EQ          : '==',
    MediumLevelILOperation.MLIL_NE          : '!=',
    MediumLevelILOperation.MLIL_LT          : '<',
    MediumLevelILOperation.MLIL_LE          : '<=',
    MediumLevelILOperation.MLIL_GT          : '>',
    MediumLevelILOperation.MLIL_GE          : '>=',
}


class MLILBinaryOp(MediumLevelILExpr):
    """Base class for binary operations: each subclass sets only its OPERATION"""

    OPERATION: MediumLevelILOperation

    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(self.OPERATION, **kwargs)
        self.lhs = lhs
        self.rhs = rhs

    def rebuild(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILBinaryOp:
        """Copy of this operation with new operands, keeping metadata"""
        return type(self)(lhs, rhs).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.lhs, self.rhs)

    def __str__(self) -> str:
        op_str = BINARY_OP_SYMBOLS.get(self.operation, self.operation_name)
        return f'({self.lhs} {op_str} {self.rhs})'


class MLILAdd(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_ADD


class MLILSub(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_SUB


class MLILMul(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_MUL


class MLILDiv(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_DIV


class MLILMod(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_MOD


class MLILAnd(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_AND


class MLILOr(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_OR


class MLILXor(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_XOR


class MLILShl(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_SHL


class MLILShr(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_SHR


class MLILLogicalAnd(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_LOGICAL_AND


class MLILLogicalOr(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_LOGICAL_OR


# De Morgan: the logical operator each one becomes when a negation is pushed into its operands
DE_MORGAN = {MLILLogicalAnd: MLILLogicalOr, MLILLogicalOr: MLILLogicalAnd}


# === Comparison Operations ===

class MLILEq(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_EQ


class MLILNe(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_NE


class MLILLt(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_LT


class MLILLe(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_LE


class MLILGt(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_GT


class MLILGe(MLILBinaryOp):
    OPERATION = MediumLevelILOperation.MLIL_GE


# Each comparison and the comparison with the opposite outcome
NEGATED_COMPARISON = {
    MLILEq  : MLILNe,
    MLILNe  : MLILEq,
    MLILLt  : MLILGe,
    MLILLe  : MLILGt,
    MLILGt  : MLILLe,
    MLILGe  : MLILLt,
}
COMPARISON_TYPES = tuple(NEGATED_COMPARISON)


def negate_comparison(expr: MediumLevelILInstruction) -> MediumLevelILInstruction | None:
    """The comparison with the opposite outcome over the same operands, or None if expr is not a comparison"""
    negated_type = NEGATED_COMPARISON.get(type(expr))
    return negated_type(expr.lhs, expr.rhs) if negated_type is not None else None


# === Unary Operations ===

# Each unary operation's operator as the listing prints it (TestZero, AddressOf and Deref print their own form)
UNARY_OP_SYMBOLS = {
    MediumLevelILOperation.MLIL_NEG         : '-',
    MediumLevelILOperation.MLIL_LOGICAL_NOT : '!',
    MediumLevelILOperation.MLIL_BITWISE_NOT : '~',
}


class MLILUnaryOp(MediumLevelILExpr):
    """Base class for unary operations: each subclass sets only its OPERATION"""

    OPERATION: MediumLevelILOperation

    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(self.OPERATION, **kwargs)
        self.operand = operand

    def rebuild(self, operand: MediumLevelILInstruction) -> MLILUnaryOp:
        """Copy of this operation with a new operand, keeping metadata"""
        return type(self)(operand).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.operand,)

    def __str__(self) -> str:
        op_str = UNARY_OP_SYMBOLS.get(self.operation, self.operation_name)
        return f'{op_str}{self.operand}'


class MLILNeg(MLILUnaryOp):
    OPERATION = MediumLevelILOperation.MLIL_NEG


class MLILLogicalNot(MLILUnaryOp):
    OPERATION = MediumLevelILOperation.MLIL_LOGICAL_NOT


class MLILTestZero(MLILUnaryOp):
    OPERATION = MediumLevelILOperation.MLIL_TEST_ZERO

    def __str__(self) -> str:
        return f'({self.operand} == 0)'


class MLILBitwiseNot(MLILUnaryOp):
    """Bitwise NOT (~x)"""

    OPERATION = MediumLevelILOperation.MLIL_BITWISE_NOT


class MLILAddressOf(MLILUnaryOp):
    """Address-of operation (&var)"""

    OPERATION = MediumLevelILOperation.MLIL_ADDRESS_OF

    def __str__(self) -> str:
        return f'&{self.operand}'


# === Control Flow ===

class MLILGoto(MediumLevelILStatement, Terminal):
    """Unconditional jump"""

    def __init__(self, target: MediumLevelILBasicBlock, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_GOTO, **kwargs)
        self.target = target

    def __str__(self) -> str:
        return f'goto {self.target.label}'


class MLILIf(MediumLevelILStatement, Terminal):
    """Conditional branch"""

    def __init__(self, condition: MediumLevelILInstruction, true_target: MediumLevelILBasicBlock,
                 false_target: MediumLevelILBasicBlock, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_IF, **kwargs)
        self.condition = condition
        self.true_target = true_target
        self.false_target = false_target

    def rebuild(self, condition: MediumLevelILInstruction) -> MLILIf:
        return MLILIf(condition, self.true_target, self.false_target).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.condition,)

    def __str__(self) -> str:
        return f'if ({self.condition}) goto {self.true_target.label} else {self.false_target.label}'


class MLILRet(MediumLevelILStatement, Terminal):
    """Return from function"""

    def __init__(self, value: MediumLevelILInstruction | None = None, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_RET, **kwargs)
        self.value = value

    def rebuild(self, value: MediumLevelILInstruction) -> MLILRet:
        return MLILRet(value).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.value,) if self.value is not None else ()

    def __str__(self) -> str:
        if self.value is not None:
            return f'return {self.value}'

        return 'return'


# === Function Calls ===

class MediumLevelILCall(MediumLevelILStatement):
    """Base class for calls: statements that also define an output variable

    output is the variable receiving the call result (the VM result register),
    or None when the result is unused. It holds an MLILVariable, or an
    MLILVariableSSA while the function is in SSA form.

    clobbers_registers is True for an ordinary call, whose callee may change any VM
    register/global other than its own output - SSA construction gives every one of
    them a fresh, unknown-valued pseudo-definition here. False marks a call proven to
    have no VM register/global side effects at all (e.g. a pure debug print), so
    nothing but its own output (if any) is treated as redefined.
    """

    def __init__(self, operation: MediumLevelILOperation, args: list[MediumLevelILInstruction],
                 output: Any | None = None, *, clobbers_registers: bool = True, **kwargs):
        super().__init__(operation, **kwargs)
        self.args = args
        self.output = output
        self.clobbers_registers = clobbers_registers

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return tuple(self.args)

    def format_with_output(self, call_str: str) -> str:
        """Prefix the call text with its output assignment"""
        if self.output is None:
            return call_str

        return f'{self.output} = {call_str}'

    def rebuild(self, *args: MediumLevelILInstruction) -> MediumLevelILCall:
        """Copy of this call with new arguments, keeping target, output, clobbers_registers and metadata"""
        raise NotImplementedError


class MLILCall(MediumLevelILCall):
    """Function call"""

    def __init__(self, target: str, args: list[MediumLevelILInstruction], output: Any | None = None,
                 *, clobbers_registers: bool = True, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_CALL, args, output, clobbers_registers=clobbers_registers,
                         **kwargs)
        self.target = target

    def rebuild(self, *args: MediumLevelILInstruction) -> MLILCall:
        return MLILCall(self.target, list(args), self.output,
                        clobbers_registers=self.clobbers_registers).copy_metadata_from(self)

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return self.format_with_output(f'{self.target}({args_str})')


class MLILSyscall(MediumLevelILCall):
    """System call"""

    def __init__(self, subsystem: int, cmd: int, args: list[MediumLevelILInstruction], output: Any | None = None,
                 **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SYSCALL, args, output, **kwargs)
        self.subsystem = subsystem
        self.cmd = cmd

    def rebuild(self, *args: MediumLevelILInstruction) -> MLILSyscall:
        return MLILSyscall(self.subsystem, self.cmd, list(args), self.output,
                           clobbers_registers=self.clobbers_registers).copy_metadata_from(self)

    def __str__(self) -> str:
        args_str = ', '.join([f'{self.subsystem}', f'{self.cmd}', *(str(arg) for arg in self.args)])
        return self.format_with_output(f'syscall({args_str})')


class MLILCallScript(MediumLevelILCall):
    """Falcom script call"""

    def __init__(self, module: str, func: str, args: list[MediumLevelILInstruction], output: Any | None = None,
                 **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_CALL_SCRIPT, args, output, **kwargs)
        self.module = module
        self.func = func

    def rebuild(self, *args: MediumLevelILInstruction) -> MLILCallScript:
        return MLILCallScript(self.module, self.func, list(args), self.output,
                              clobbers_registers=self.clobbers_registers).copy_metadata_from(self)

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return self.format_with_output(f'{self.module}.{self.func}({args_str})')


# === Global Variables ===

class MLILLoadGlobal(MediumLevelILExpr):
    """Load global variable"""

    def __init__(self, index: int, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOAD_GLOBAL, **kwargs)
        self.index = index

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}]'


class MLILStoreGlobal(MediumLevelILStatement):
    """Store to global variable"""

    def __init__(self, index: int, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_STORE_GLOBAL, **kwargs)
        self.index = index
        self.value = value

    def rebuild(self, value: MediumLevelILInstruction) -> MLILStoreGlobal:
        return MLILStoreGlobal(self.index, value).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}] = {self.value}'


# === Registers ===

class MLILLoadReg(MediumLevelILExpr):
    """Load register"""

    def __init__(self, index: int, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOAD_REG, **kwargs)
        self.index = index

    def __str__(self) -> str:
        return f'REG[{self.index}]'


class MLILStoreReg(MediumLevelILStatement):
    """Store to register"""

    def __init__(self, index: int, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_STORE_REG, **kwargs)
        self.index = index
        self.value = value

    def rebuild(self, value: MediumLevelILInstruction) -> MLILStoreReg:
        return MLILStoreReg(self.index, value).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.value,)

    def __str__(self) -> str:
        return f'REG[{self.index}] = {self.value}'


# === Debug ===

class MLILNop(MediumLevelILStatement):
    """No operation"""

    def __init__(self, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_NOP, **kwargs)

    def __str__(self) -> str:
        return 'nop'


class MLILDebug(MediumLevelILStatement):
    """Debug information"""

    def __init__(self, debug_type: str, value: Any, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_DEBUG, **kwargs)
        self.debug_type = debug_type
        self.value = value

    def __str__(self) -> str:
        return f'debug.{self.debug_type}({self.value})'


def is_nop_instr(instr: MediumLevelILInstruction) -> bool:
    return isinstance(instr, (MLILDebug, MLILNop))


# === Pointer Dereference ===

def _parenthesize_deref_operand(operand: MediumLevelILInstruction) -> str:
    """Wrap a compound address in parens so *p + 1 (meaning (*p) + 1) can't be confused with
    the intended *(p + 1) - only debug/dump text, real codegen builds deref(...) calls instead"""
    if isinstance(operand, MLILBinaryOp):
        return f'({operand})'

    return str(operand)


class MLILDeref(MLILUnaryOp):
    """Load *ptr - dereference a pointer expression. Impure: unlike a variable read, the target
    memory is not tracked by SSA, so this can never be assumed constant across a store through
    any pointer (see the inliner's _impure_read_storages and RegGlobalValuePropagator's
    _is_closed_form, which never caches a deref read under a REG/GLOBAL slot at all).
    """

    OPERATION = MediumLevelILOperation.MLIL_DEREF

    def __str__(self) -> str:
        return f'*{_parenthesize_deref_operand(self.operand)}'


class MLILStoreDeref(MediumLevelILStatement):
    """*dest = value - store through a pointer expression. Always an observable side effect:
    never removed by DCE and never reordered, since the target is not a tracked SSA variable.
    """

    def __init__(self, dest: MediumLevelILInstruction, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_STORE_DEREF, **kwargs)
        self.dest = dest
        self.value = value

    def rebuild(self, dest: MediumLevelILInstruction, value: MediumLevelILInstruction) -> MLILStoreDeref:
        """Copy of this store with a new dest/value, keeping metadata"""
        return MLILStoreDeref(dest, value).copy_metadata_from(self)

    def operands(self) -> tuple[MediumLevelILInstruction, ...]:
        return (self.dest, self.value)

    def __str__(self) -> str:
        return f'*{_parenthesize_deref_operand(self.dest)} = {self.value}'


# === Traversal ===

def walk(node: MediumLevelILInstruction, skip: tuple[type, ...] = ()) -> Iterator[MediumLevelILInstruction]:
    """node and every expression below it, pre-order in evaluation order. A node that is an
    instance of a type in skip (subclasses included) is yielded but not descended into."""
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        if skip and isinstance(current, skip):
            continue
        operands = current.operands()
        if len(operands) == 1:
            pending.append(operands[0])
        elif operands:
            pending.extend(reversed(operands))


def map_operands(node: MediumLevelILInstruction,
                 transform: Callable[[MediumLevelILInstruction], MediumLevelILInstruction]) -> MediumLevelILInstruction:
    """node rebuilt over transform(operand) for each direct operand, in evaluation order - node
    itself when every operand comes back unchanged, so `is` tells a pass whether anything changed"""
    operands = node.operands()
    if not operands:
        return node

    if len(operands) == 1:
        operand = operands[0]
        new_operand = transform(operand)
        return node if new_operand is operand else node.rebuild(new_operand)

    new_operands = [transform(operand) for operand in operands]
    for new, old in zip(new_operands, operands):
        if new is not old:
            return node.rebuild(*new_operands)

    return node


# === Basic Block ===

class MediumLevelILBasicBlock(ILBasicBlock):
    """MLIL basic block"""

    def __init__(self, index: int, start: int = 0, label: str = None):
        super().__init__(index, start, label or f'mlil_{index}')

    @property
    def block_name(self) -> str:
        return f'mlil_block_{self.index}'

    def __str__(self) -> str:
        body = '\n'.join(f'  {inst}' for inst in self.instructions)
        return f'{self.label}:\n{body}'

    def __repr__(self) -> str:
        return f'<MediumLevelILBasicBlock {self.index} "{self.label}">'


# === Function ===

class MediumLevelILFunction:
    """MLIL function container"""

    def __init__(self, name: str, start_addr: int = 0, params: list[IRParameter] = None):
        self.name = name
        self.start_addr = start_addr
        self.source_params: list[IRParameter] = params or []  # Original params from source
        self.basic_blocks: list[MediumLevelILBasicBlock] = []
        self.parameters: list[MLILVariable] = []  # Ordered parameter list (populated during translation)
        self.locals: dict[str, MLILVariable] = {}  # Local variables
        self.register_vars: dict[int, MLILVariable] = {}  # VM register index -> variable
        self.global_vars: dict[int, MLILVariable] = {}  # Global var table index -> variable
        self.llil_function: 'LowLevelILFunction | None' = None
        self.var_types: dict[str, MLILType] = {}  # Variable name -> inferred type

    def add_basic_block(self, block: MediumLevelILBasicBlock):
        self.basic_blocks.append(block)

    def renumber_blocks(self):
        """Renumber basic blocks to match list positions after a structural change"""
        for i, block in enumerate(self.basic_blocks):
            block.index = i

    def renumber_instructions(self):
        """Give every statement a unique inst_index, 0..N-1 in block order"""
        for i, inst in enumerate(self.iter_instructions()):
            inst.inst_index = i

    def create_block(self, start: int = 0, label: str = None) -> MediumLevelILBasicBlock:
        block = MediumLevelILBasicBlock(len(self.basic_blocks), start, label)
        self.add_basic_block(block)
        return block

    def get_or_create_parameter(self, param_index: int, name: str) -> MLILVariable:
        """Get existing parameter or create new one (1-based index)"""
        # Extend list if needed
        while len(self.parameters) < param_index:
            self.parameters.append(None)

        if self.parameters[param_index - 1] is None:
            self.parameters[param_index - 1] = MLILVariable(name)

        return self.parameters[param_index - 1]

    def get_or_create_local(self, name: str, slot_index: int = UNASSIGNED_SLOT_INDEX) -> MLILVariable:
        """Get existing local variable or create new one"""
        if name not in self.locals:
            self.locals[name] = MLILVariable(name, slot_index)
        return self.locals[name]

    def get_or_create_register_var(self, reg_index: int) -> MLILVariable:
        """Get existing register variable or create new one

        VM registers are modelled as variables so the SSA passes track them like
        any other value. Calls define the result register and clobber the others.
        """
        if reg_index not in self.register_vars:
            self.register_vars[reg_index] = self.get_or_create_local(mlil_reg_var_name(reg_index))

        return self.register_vars[reg_index]

    def is_register_var(self, var: MLILVariable) -> bool:
        return var in self.register_vars.values()

    def get_or_create_global_var(self, global_index: int) -> MLILVariable:
        """Get existing global variable or create new one

        Unlike registers/locals, global variables are kept out of self.locals - they are
        script-wide storage, not something that belongs in a locals-derived variable listing
        """
        if global_index not in self.global_vars:
            self.global_vars[global_index] = MLILVariable(mlil_global_var_name(global_index))

        return self.global_vars[global_index]

    def is_global_var(self, var: MLILVariable) -> bool:
        return var in self.global_vars.values()

    def call_may_clobber(self, call: MediumLevelILCall, var: MLILVariable) -> bool:
        """Whether `call` may clobber the register/global storage represented by `var`"""
        return call.clobbers_registers and (self.is_register_var(var) or self.is_global_var(var))

    def global_index_of(self, var: MLILVariable) -> int | None:
        """Global var table index of a variable, or None if it does not model a global"""
        for index, global_var in self.global_vars.items():
            if global_var == var:
                return index

        return None

    def iter_instructions(self) -> Iterator[MediumLevelILInstruction]:
        for block in self.basic_blocks:
            yield from block.instructions

    def __str__(self) -> str:
        result = [f'; ===== MLIL Function {self.name} =====']
        for block in self.basic_blocks:
            result.append('')
            result.append(str(block))
        return '\n'.join(result)
