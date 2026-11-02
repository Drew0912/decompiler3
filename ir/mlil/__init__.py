"""Medium Level IL - Stack-free intermediate representation (the SSA path, kept and never called by the decompile
path, is ir/mlil_ssa/)"""

from .mlil_builder import *
from .llil_ops import *
from .stack_translator import *
from .mlil_formatter import *
from .mlil_types import *
from .passes import *
from .mlil import *

__all__ = [
    # Naming utilities
    'mlil_stack_var_name',
    'mlil_arg_var_name',
    'mlil_reg_var_name',
    'mlil_global_var_name',

    # Builder, Translator, Formatter
    'MLILBuilder',
    'BINARY_OP_TYPES',
    'UNARY_OP_TYPES',
    'StackTranslator',
    'UnsupportedStackShape',
    'MLILFormatter',

    # Passes
    'StackTranslatorPass',
    'BlockMergePass',
    'CallResultPass',
    'ReturnValuePass',
    'BitwiseHexPass',

    # Type System
    'MLILType',
    'MLILTypeKind',
    'MLILVariantType',
    'unify_types',

    # Core
    'MediumLevelILOperation',
    'MediumLevelILInstruction',
    'MediumLevelILExpr',
    'MediumLevelILStatement',
    'MediumLevelILFunction',
    'MediumLevelILBasicBlock',

    # Variables
    'UNASSIGNED_SLOT_INDEX',
    'MLILVariable',

    # Constants
    'MLILConst',
    'MLILUndef',

    # Variable operations
    'MLILVar',
    'MLILSetVar',

    # Binary operations
    'BINARY_OP_SYMBOLS',
    'MLILBinaryOp',
    'MLILAdd',
    'MLILSub',
    'MLILMul',
    'MLILDiv',
    'MLILMod',
    'MLILAnd',
    'MLILOr',
    'MLILXor',
    'MLILShl',
    'MLILShr',
    'MLILLogicalAnd',
    'MLILLogicalOr',
    'DE_MORGAN',

    # Comparison operations
    'MLILEq',
    'MLILNe',
    'MLILLt',
    'MLILLe',
    'MLILGt',
    'MLILGe',
    'NEGATED_COMPARISON',
    'COMPARISON_TYPES',
    'negate_comparison',

    # Unary operations
    'UNARY_OP_SYMBOLS',
    'MLILUnaryOp',
    'MLILNeg',
    'MLILLogicalNot',
    'MLILBitwiseNot',
    'MLILTestZero',
    'MLILAddressOf',

    # Control flow
    'MLILGoto',
    'MLILIf',
    'MLILRet',

    # Function calls
    'MediumLevelILCall',
    'MLILCall',
    'MLILSyscall',
    'MLILCallScript',

    # Globals
    'MLILLoadGlobal',
    'MLILStoreGlobal',

    # Registers
    'MLILLoadReg',
    'MLILStoreReg',

    # Pointer dereference
    'MLILDeref',
    'MLILStoreDeref',

    # Debug
    'MLILNop',
    'MLILDebug',
    'is_nop_instr',

    # Traversal
    'walk',
    'map_operands',
]
