'''Medium Level IL - Stack-free intermediate representation'''

from .mlil_builder import *
from .llil_to_mlil import *
from .mlil_formatter import *
from .mlil_optimizer import *
from .mlil_ssa_optimizer import *
from .mlil_ssa import *
from .mlil_types import *
from .mlil_passes import *
from .mlil import *

__all__ = [
    # Naming utilities
    'mlil_stack_var_name',
    'mlil_arg_var_name',
    'mlil_reg_var_name',
    'mlil_global_var_name',

    # Builder, Translator, Formatter, and Optimizers
    'MLILBuilder',
    'LLILToMLILTranslator',
    'translate_llil_to_mlil',
    'MLILFormatter',
    'format_mlil_function',
    'SSAOptimizer',
    'mlil_optimization_passes',
    'optimize_mlil',

    # Passes
    'LLILToMLILPass',
    'SSAConversionPass',
    'SSAOptimizationPass',
    'SSATypeInferencePass',
    'SSADeconstructionPass',

    # SSA
    'MLILVariableSSA',
    'MLILVarSSA',
    'MLILSetVarSSA',
    'MLILPhi',
    'DominanceAnalysis',
    'SSAConstructor',
    'SSADeconstructor',
    'convert_to_ssa',
    'convert_from_ssa',

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
    'MLILVariable',

    # Constants
    'MLILConst',

    # Variable operations
    'MLILVar',
    'MLILSetVar',

    # Binary operations
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

    # Comparison operations
    'MLILEq',
    'MLILNe',
    'MLILLt',
    'MLILLe',
    'MLILGt',
    'MLILGe',

    # Unary operations
    'MLILUnaryOp',
    'MLILNeg',
    'MLILLogicalNot',
    'MLILBitwiseNot',
    'MLILTestZero',

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
]
