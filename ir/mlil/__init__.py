"""Medium Level IL - Stack-free intermediate representation"""

from .mlil_builder import *
from .llil_to_mlil import *
from .mlil_formatter import *
from .mlil_optimizer import *
from .mlil_ssa_optimizer import *
from .mlil_ssa import *
from .mlil_types import *
from .passes import *
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
    'BINARY_OP_TYPES',
    'UNARY_OP_TYPES',
    'MLILFormatter',
    'SSAOptimizer',
    'SSA_OPTIMIZER_MAX_ITERATIONS',
    'mlil_optimization_passes',
    'optimize_mlil',

    # Passes
    'LLILToMLILPass',
    'SSAConversionPass',
    'SSAOptimizationPass',
    'SSADeconstructionPass',
    'NNFPass',
    'SCCP',
    'LatticeValue',
    'ConstantPropagationPass',
    'CopyPropagationPass',
    'ExpressionSimplificationPass',
    'ConditionSimplificationPass',
    'ExpressionInliningPass',
    'SSADeadCodeEliminationPass',
    'DeadPhiSourceEliminationPass',
    'SSATypeInferencePass',
    'BlockMergePass',
    'RegGlobalState',
    'RegGlobalValuePropagator',
    'RegGlobalValuePropagationPass',
    'BitwiseHexPass',

    # SSA
    'MLILVariableSSA',
    'MLILVarSSA',
    'MLILSetVarSSA',
    'MLILPhi',
    'iter_ssa_reads',
    'iter_ssa_defs',
    'exit_register_versions',
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
