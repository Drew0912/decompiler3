'''MLIL - Stack-free IR (variables instead of stack operations)'''

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional, Union, TYPE_CHECKING

from common import *
from ir.core import *


FLOAT_ROUND_REL_TOL = 1e-6
FLOAT_ROUND_ABS_TOL = 1e-9

UNASSIGNED_INST_INDEX = -1
UNASSIGNED_SLOT_INDEX = -1

if TYPE_CHECKING:
    from ir.llil import LowLevelILBasicBlock, LowLevelILFunction


# === Naming Utilities ===

def mlil_stack_var_name(slot_index: int) -> str:
    '''Generate stack variable name (var_s0, var_s1, ...)'''
    if slot_index < 0:
        raise ValueError(f'Negative slot_index: {slot_index}')
    return f'var_s{slot_index}'


def mlil_arg_var_name(arg_index: int) -> str:
    '''Generate argument variable name (arg0, arg1, ...)'''
    return f'arg{arg_index}'


def mlil_reg_var_name(reg_index: int) -> str:
    '''Generate register variable name (reg0, reg1, ...)'''
    if reg_index < 0:
        raise ValueError(f'Negative reg_index: {reg_index}')
    return f'reg{reg_index}'


def mlil_global_var_name(global_index: int) -> str:
    '''Generate global variable name (global0, global1, ...)'''
    if global_index < 0:
        raise ValueError(f'Negative global_index: {global_index}')
    return f'global{global_index}'


class MediumLevelILOperation(IntEnum2):
    '''MLIL operations - stack-free version of LLIL'''

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

    # SSA (future)
    MLIL_PHI                = 2000
    MLIL_VAR_SSA            = 2001
    MLIL_SET_VAR_SSA        = 2002
    MLIL_UNDEF              = 2003


class MediumLevelILInstruction(ILInstruction):
    '''Base class for MLIL instructions'''

    def __init__(self, operation: MediumLevelILOperation, *, address: int = 0):
        super().__init__()
        self.operation = operation
        self.address = address
        self.inst_index = UNASSIGNED_INST_INDEX  # Inherited from LLIL instruction index
        self.llil_index = UNASSIGNED_INST_INDEX  # Source LLIL instruction index (for debugging/mapping)
        self.options = ILOptions()

    @property
    def operation_name(self) -> str:
        return self.operation.name.replace('MLIL_', '')

    @abstractmethod
    def __str__(self) -> str:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.operation_name}>'

    def copy_metadata_from(self, source: 'MediumLevelILInstruction') -> 'MediumLevelILInstruction':
        '''Copy source tracking metadata from another MLIL instruction.'''
        self.address = source.address
        self.inst_index = source.inst_index
        self.llil_index = source.llil_index
        return self


# === Instruction Categories ===

class MediumLevelILExpr(MediumLevelILInstruction):
    '''Base class for value expressions'''
    pass


class MediumLevelILStatement(MediumLevelILInstruction):
    '''Base class for statements'''
    pass


# === Variables ===

class MLILVariable:
    '''MLIL variable (non-SSA)'''

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
    '''Constant value (int, float, or string)'''

    def __init__(self, value: Any, is_hex: bool = False, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_CONST, **kwargs)
        self.value = value
        self.is_hex = is_hex

    def __str__(self) -> str:
        if isinstance(self.value, int):
            if self.is_hex:
                # Display as unsigned 32-bit hex
                unsigned = self.value & 0xFFFFFFFF
                return f'0x{unsigned:08X}'

            return str(self.value)

        elif isinstance(self.value, float):
            return format_float(self.value)

        elif isinstance(self.value, str):

            return quote_string(self.value)
        return str(self.value)


class MLILUndef(MediumLevelILExpr):
    '''Undefined value (result of call via AddressOf, etc.)'''

    def __init__(self, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_UNDEF, **kwargs)

    def __str__(self) -> str:
        return '<undef>'


# === Variable Operations ===

class MLILVar(MediumLevelILExpr):
    '''Load variable value'''

    def __init__(self, var: MLILVariable, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_VAR, **kwargs)
        self.var = var

    def __str__(self) -> str:
        return str(self.var)


class MLILSetVar(MediumLevelILStatement):
    '''Store value to variable'''

    def __init__(self, var: MLILVariable, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SET_VAR, **kwargs)
        self.var = var
        self.value = value

    def __str__(self) -> str:
        return f'{self.var} = {self.value}'


# === Binary Operations ===

class MLILBinaryOp(MediumLevelILExpr, BinaryOperation):
    '''Base class for binary operations'''

    def __init__(self, operation: MediumLevelILOperation, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(operation, **kwargs)
        self.lhs = lhs
        self.rhs = rhs

    def __str__(self) -> str:
        op_map = {
            MediumLevelILOperation.MLIL_ADD: '+',
            MediumLevelILOperation.MLIL_SUB: '-',
            MediumLevelILOperation.MLIL_MUL: '*',
            MediumLevelILOperation.MLIL_DIV: '/',
            MediumLevelILOperation.MLIL_MOD: '%',
            MediumLevelILOperation.MLIL_AND: '&',
            MediumLevelILOperation.MLIL_OR: '|',
            MediumLevelILOperation.MLIL_XOR: '^',
            MediumLevelILOperation.MLIL_SHL: '<<',
            MediumLevelILOperation.MLIL_SHR: '>>',
            MediumLevelILOperation.MLIL_LOGICAL_AND: '&&',
            MediumLevelILOperation.MLIL_LOGICAL_OR: '||',
            MediumLevelILOperation.MLIL_EQ: '==',
            MediumLevelILOperation.MLIL_NE: '!=',
            MediumLevelILOperation.MLIL_LT: '<',
            MediumLevelILOperation.MLIL_LE: '<=',
            MediumLevelILOperation.MLIL_GT: '>',
            MediumLevelILOperation.MLIL_GE: '>=',
        }
        op_str = op_map.get(self.operation, self.operation_name)
        return f'({self.lhs} {op_str} {self.rhs})'


class MLILAdd(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_ADD, lhs, rhs, **kwargs)


class MLILSub(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SUB, lhs, rhs, **kwargs)


class MLILMul(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_MUL, lhs, rhs, **kwargs)


class MLILDiv(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_DIV, lhs, rhs, **kwargs)


class MLILMod(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_MOD, lhs, rhs, **kwargs)


class MLILAnd(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_AND, lhs, rhs, **kwargs)


class MLILOr(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_OR, lhs, rhs, **kwargs)


class MLILXor(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_XOR, lhs, rhs, **kwargs)


class MLILShl(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SHL, lhs, rhs, **kwargs)


class MLILShr(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SHR, lhs, rhs, **kwargs)


class MLILLogicalAnd(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOGICAL_AND, lhs, rhs, **kwargs)


class MLILLogicalOr(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOGICAL_OR, lhs, rhs, **kwargs)


# === Comparison Operations ===

class MLILEq(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_EQ, lhs, rhs, **kwargs)


class MLILNe(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_NE, lhs, rhs, **kwargs)


class MLILLt(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LT, lhs, rhs, **kwargs)


class MLILLe(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LE, lhs, rhs, **kwargs)


class MLILGt(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_GT, lhs, rhs, **kwargs)


class MLILGe(MLILBinaryOp):
    def __init__(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_GE, lhs, rhs, **kwargs)


# === Unary Operations ===

class MLILUnaryOp(MediumLevelILExpr, UnaryOperation):
    '''Base class for unary operations'''

    def __init__(self, operation: MediumLevelILOperation, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(operation, **kwargs)
        self.operand = operand

    def __str__(self) -> str:
        op_map = {
            MediumLevelILOperation.MLIL_NEG: '-',
            MediumLevelILOperation.MLIL_LOGICAL_NOT: '!',
            MediumLevelILOperation.MLIL_BITWISE_NOT: '~',
        }
        op_str = op_map.get(self.operation, self.operation_name)
        return f'{op_str}{self.operand}'


class MLILNeg(MLILUnaryOp):
    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_NEG, operand, **kwargs)


class MLILLogicalNot(MLILUnaryOp):
    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOGICAL_NOT, operand, **kwargs)


class MLILTestZero(MLILUnaryOp):
    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_TEST_ZERO, operand, **kwargs)

    def __str__(self) -> str:
        return f'({self.operand} == 0)'


class MLILBitwiseNot(MLILUnaryOp):
    '''Bitwise NOT (~x)'''
    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_BITWISE_NOT, operand, **kwargs)


class MLILAddressOf(MLILUnaryOp):
    '''Address-of operation (&var)'''

    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_ADDRESS_OF, operand, **kwargs)

    def __str__(self) -> str:
        return f'&{self.operand}'


# === Control Flow ===

class MLILGoto(MediumLevelILStatement, Terminal):
    '''Unconditional jump'''

    def __init__(self, target: 'MediumLevelILBasicBlock', **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_GOTO, **kwargs)
        self.target = target

    def __str__(self) -> str:
        return f'goto {self.target.label}'


class MLILIf(MediumLevelILStatement, Terminal):
    '''Conditional branch'''

    def __init__(self, condition: MediumLevelILInstruction, true_target: 'MediumLevelILBasicBlock', false_target: 'MediumLevelILBasicBlock', **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_IF, **kwargs)
        self.condition = condition
        self.true_target = true_target
        self.false_target = false_target

    def __str__(self) -> str:
        return f'if ({self.condition}) goto {self.true_target.label} else {self.false_target.label}'


class MLILRet(MediumLevelILStatement, Terminal):
    '''Return from function'''

    def __init__(self, value: Optional[MediumLevelILInstruction] = None, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_RET, **kwargs)
        self.value = value

    def __str__(self) -> str:
        if self.value is not None:
            return f'return {self.value}'
        else:
            return 'return'


# === Function Calls ===

class MediumLevelILCall(MediumLevelILStatement):
    '''Base class for calls: statements that also define an output variable

    output is the variable receiving the call result (the VM result register),
    or None when the result is unused. It holds an MLILVariable, or an
    MLILVariableSSA while the function is in SSA form.

    clobbers_registers is True for an ordinary call, whose callee may change any VM
    register/global other than its own output - SSA construction gives every one of
    them a fresh, unknown-valued pseudo-definition here. False marks a call proven to
    have no VM register/global side effects at all (e.g. a pure debug print), so
    nothing but its own output (if any) is treated as redefined.
    '''

    def __init__(self, operation: MediumLevelILOperation, args: List[MediumLevelILInstruction],
                 output: Optional[Any] = None, *, clobbers_registers: bool = True, **kwargs):
        super().__init__(operation, **kwargs)
        self.args = args
        self.output = output
        self.clobbers_registers = clobbers_registers

    def format_with_output(self, call_str: str) -> str:
        '''Prefix the call text with its output assignment'''
        if self.output is None:
            return call_str

        return f'{self.output} = {call_str}'

    @abstractmethod
    def rebuild(self, args: List[MediumLevelILInstruction]) -> 'MediumLevelILCall':
        '''Copy of this call with new arguments, keeping target, output and metadata'''
        raise NotImplementedError


class MLILCall(MediumLevelILCall):
    '''Function call'''

    def __init__(self, target: str, args: List[MediumLevelILInstruction], output: Optional[Any] = None,
                 *, clobbers_registers: bool = True, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_CALL, args, output, clobbers_registers = clobbers_registers, **kwargs)
        self.target = target

    def rebuild(self, args: List[MediumLevelILInstruction]) -> 'MLILCall':
        return MLILCall(self.target, args, self.output, clobbers_registers = self.clobbers_registers,
                        address = self.address).copy_metadata_from(self)

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return self.format_with_output(f'{self.target}({args_str})')


class MLILSyscall(MediumLevelILCall):
    '''System call'''

    def __init__(self, subsystem: int, cmd: int, args: List[MediumLevelILInstruction], output: Optional[Any] = None, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SYSCALL, args, output, **kwargs)
        self.subsystem = subsystem
        self.cmd = cmd

    def rebuild(self, args: List[MediumLevelILInstruction]) -> 'MLILSyscall':
        return MLILSyscall(self.subsystem, self.cmd, args, self.output, address = self.address).copy_metadata_from(self)

    def __str__(self) -> str:
            args = [
                f'{self.subsystem}',
                f'{self.cmd}',
                *[str(arg) for arg in self.args],
            ]

            return self.format_with_output(f'syscall({', '.join(args)})')


class MLILCallScript(MediumLevelILCall):
    '''Falcom script call'''

    def __init__(self, module: str, func: str, args: List[MediumLevelILInstruction], output: Optional[Any] = None, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_CALL_SCRIPT, args, output, **kwargs)
        self.module = module
        self.func = func

    def rebuild(self, args: List[MediumLevelILInstruction]) -> 'MLILCallScript':
        return MLILCallScript(self.module, self.func, args, self.output, address = self.address).copy_metadata_from(self)

    def __str__(self) -> str:
        args_str = ', '.join(str(arg) for arg in self.args)
        return self.format_with_output(f'{self.module}.{self.func}({args_str})')


# === Global Variables ===

class MLILLoadGlobal(MediumLevelILExpr):
    '''Load global variable'''

    def __init__(self, index: int, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOAD_GLOBAL, **kwargs)
        self.index = index

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}]'


class MLILStoreGlobal(MediumLevelILStatement):
    '''Store to global variable'''

    def __init__(self, index: int, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_STORE_GLOBAL, **kwargs)
        self.index = index
        self.value = value

    def __str__(self) -> str:
        return f'GLOBAL[{self.index}] = {self.value}'


# === Registers ===

class MLILLoadReg(MediumLevelILExpr):
    '''Load register'''

    def __init__(self, index: int, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_LOAD_REG, **kwargs)
        self.index = index

    def __str__(self) -> str:
        return f'REG[{self.index}]'


class MLILStoreReg(MediumLevelILStatement):
    '''Store to register'''

    def __init__(self, index: int, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_STORE_REG, **kwargs)
        self.index = index
        self.value = value

    def __str__(self) -> str:
        return f'REG[{self.index}] = {self.value}'


# === Debug ===

class MLILNop(MediumLevelILStatement):
    '''No operation'''

    def __init__(self, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_NOP, **kwargs)

    def __str__(self) -> str:
        return 'nop'


class MLILDebug(MediumLevelILStatement):
    '''Debug information'''

    def __init__(self, debug_type: str, value: Any, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_DEBUG, **kwargs)
        self.debug_type = debug_type
        self.value = value

    def __str__(self) -> str:
        return f'debug.{self.debug_type}({self.value})'


def is_nop_instr(instr: MediumLevelILInstruction) -> bool:
    '''Check if instruction has no effect (debug/nop)'''
    return isinstance(instr, (MLILDebug, MLILNop))


# === Pointer Dereference ===

def _parenthesize_deref_operand(operand: MediumLevelILInstruction) -> str:
    '''Wrap a compound address in parens so *p + 1 (meaning (*p) + 1) can't be confused with
    the intended *(p + 1) - only debug/dump text, real codegen builds deref(...) calls instead.'''
    if isinstance(operand, MLILBinaryOp):
        return f'({operand})'

    return str(operand)


class MLILDeref(MLILUnaryOp):
    '''Load *ptr - dereference a pointer expression. Impure: unlike a variable read, the target
    memory is not tracked by SSA, so this can never be assumed constant across a store through
    any pointer (see the inliner's _is_impure_read and RegGlobalValuePropagator's
    _is_closed_form, which never caches a deref read under a REG/GLOBAL slot at all).
    '''

    def __init__(self, operand: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_DEREF, operand, **kwargs)

    def __str__(self) -> str:
        return f'*{_parenthesize_deref_operand(self.operand)}'


class MLILStoreDeref(MediumLevelILStatement):
    '''*dest = value - store through a pointer expression. Always an observable side effect:
    never removed by DCE and never reordered, since the target is not a tracked SSA variable.
    '''

    def __init__(self, dest: MediumLevelILInstruction, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_STORE_DEREF, **kwargs)
        self.dest = dest
        self.value = value

    def rebuild(self, dest: MediumLevelILInstruction, value: MediumLevelILInstruction) -> 'MLILStoreDeref':
        '''Copy of this store with a new dest/value, keeping metadata'''
        return MLILStoreDeref(dest, value, address = self.address).copy_metadata_from(self)

    def __str__(self) -> str:
        return f'*{_parenthesize_deref_operand(self.dest)} = {self.value}'


# === Basic Block ===

class MediumLevelILBasicBlock:
    '''MLIL basic block'''

    def __init__(self, index: int, start: int = 0, label: str = None):
        self.index = index
        self.start = start
        self.label = label or f'mlil_{index}'
        self.instructions: List[MediumLevelILInstruction] = []
        self.incoming_edges: List['MediumLevelILBasicBlock'] = []
        self.outgoing_edges: List['MediumLevelILBasicBlock'] = []
        self.llil_block: Optional[LowLevelILBasicBlock] = None  # Source LLIL block

    def add_instruction(self, inst: MediumLevelILInstruction):
        self.instructions.append(inst)

    def add_outgoing_edge(self, block: 'MediumLevelILBasicBlock'):
        if block not in self.outgoing_edges:
            self.outgoing_edges.append(block)
        if self not in block.incoming_edges:
            block.incoming_edges.append(self)

    @property
    def block_name(self) -> str:
        return f'mlil_block_{self.index}'

    @property
    def has_terminal(self) -> bool:
        return (self.instructions and
                isinstance(self.instructions[-1], Terminal))

    def __str__(self) -> str:
        body = '\n'.join(f'  {inst}' for inst in self.instructions)
        return f'{self.label}:\n{body}'

    def __repr__(self) -> str:
        return f'<MediumLevelILBasicBlock {self.index} "{self.label}">'


# === Function ===

class MediumLevelILFunction:
    '''MLIL function container'''

    def __init__(self, name: str, start_addr: int = 0, params: List['IRParameter'] = None, *, is_common_func: bool = False):
        self.name = name
        self.start_addr = start_addr
        self.source_params: List['IRParameter'] = params or []  # Original params from source
        self.basic_blocks: List[MediumLevelILBasicBlock] = []
        self.parameters: List[MLILVariable] = []  # Ordered parameter list (populated during translation)
        self.locals: Dict[str, MLILVariable] = {}  # Local variables
        self.register_vars: Dict[int, MLILVariable] = {}  # VM register index -> variable
        self.global_vars: Dict[int, MLILVariable] = {}  # Global var table index -> variable
        self.llil_function: Optional[LowLevelILFunction] = None
        self._inst_block_map: Dict[int, MediumLevelILBasicBlock] = {}
        self.var_types: Dict[str, 'MLILType'] = {}  # Variable name -> inferred type
        self.is_common_func = is_common_func

    @property
    def num_params(self) -> int:
        '''Number of parameters (for backward compatibility)'''
        return len(self.source_params)

    def add_basic_block(self, block: MediumLevelILBasicBlock):
        self.basic_blocks.append(block)

    def renumber_blocks(self):
        '''Renumber basic blocks to match list positions after a structural change, and rebuild
        the inst_index -> block map, which goes stale for the same reason (a removed block would
        otherwise stay reachable through it)'''
        self._inst_block_map = {}

        for i, block in enumerate(self.basic_blocks):
            block.index = i

            for inst in block.instructions:
                if inst.inst_index != UNASSIGNED_INST_INDEX:
                    self._inst_block_map[inst.inst_index] = block

    def create_block(self, start: int = 0, label: str = None) -> MediumLevelILBasicBlock:
        block = MediumLevelILBasicBlock(len(self.basic_blocks), start, label)
        self.add_basic_block(block)
        return block

    def get_or_create_parameter(self, param_index: int, name: str) -> MLILVariable:
        '''Get existing parameter or create new one (1-based index)'''
        # Extend list if needed
        while len(self.parameters) < param_index:
            self.parameters.append(None)

        if self.parameters[param_index - 1] is None:
            self.parameters[param_index - 1] = MLILVariable(name)

        return self.parameters[param_index - 1]

    def get_or_create_local(self, name: str, slot_index: int = UNASSIGNED_SLOT_INDEX) -> MLILVariable:
        '''Get existing local variable or create new one'''
        if name not in self.locals:
            self.locals[name] = MLILVariable(name, slot_index)
        return self.locals[name]

    def get_or_create_register_var(self, reg_index: int) -> MLILVariable:
        '''Get existing register variable or create new one

        VM registers are modelled as variables so the SSA passes track them like
        any other value. Calls define the result register and clobber the others.
        '''
        if reg_index not in self.register_vars:
            self.register_vars[reg_index] = self.get_or_create_local(mlil_reg_var_name(reg_index))

        return self.register_vars[reg_index]

    def is_register_var(self, var: MLILVariable) -> bool:
        '''Check whether a variable models a VM register'''
        return var in self.register_vars.values()

    def get_or_create_global_var(self, global_index: int) -> MLILVariable:
        '''Get existing global variable or create new one

        Unlike registers/locals, global variables are kept out of self.locals - they are
        script-wide storage, not something that belongs in a locals-derived variable listing.
        '''
        if global_index not in self.global_vars:
            self.global_vars[global_index] = MLILVariable(mlil_global_var_name(global_index))

        return self.global_vars[global_index]

    def is_global_var(self, var: MLILVariable) -> bool:
        '''Check whether a variable models a VM global'''
        return var in self.global_vars.values()

    def call_may_clobber(self, call: 'MediumLevelILCall', var: MLILVariable) -> bool:
        '''Whether `call` may clobber the register/global storage represented by `var`'''
        return call.clobbers_registers and (self.is_register_var(var) or self.is_global_var(var))

    def global_index_of(self, var: MLILVariable) -> int | None:
        '''Global var table index of a variable, or None if it does not model a global'''
        for index, global_var in self.global_vars.items():
            if global_var == var:
                return index

        return None

    def register_instruction(self, block: MediumLevelILBasicBlock, inst: MediumLevelILInstruction):
        if inst.inst_index == UNASSIGNED_INST_INDEX:
            raise RuntimeError('MLIL instruction must have inst_index set')
        self._inst_block_map[inst.inst_index] = block

    def get_block_for_instruction(self, inst_index: int) -> Optional[MediumLevelILBasicBlock]:
        return self._inst_block_map.get(inst_index)

    def iter_blocks(self) -> Iterator[MediumLevelILBasicBlock]:
        return iter(self.basic_blocks)

    def iter_instructions(self) -> Iterator[MediumLevelILInstruction]:
        for block in self.basic_blocks:
            yield from block.instructions

    def __str__(self) -> str:
        result = [f'; ===== MLIL Function {self.name} =====']
        for block in self.basic_blocks:
            result.append('')
            result.append(str(block))
        return '\n'.join(result)
