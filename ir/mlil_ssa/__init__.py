"""The SSA path's MLIL - the variable-model LLIL -> MLIL translator, SSA form and its optimizer; kept beside the
decompile path (the stack translator, ir/mlil/) and never called by it. It imports from ir.mlil, never the other way"""

from .mlil_ssa_function import *
from .mlil_types import *
from .mlil_ssa_formatter import *
from .llil_to_mlil import *
from .mlil_optimizer import *
from .mlil_ssa_optimizer import *
from .mlil_ssa import *
from .passes import *

__all__ = [
    # Function, builder, listing and naming utilities
    'MediumLevelILFunctionSSA',
    'MLILBuilderSSA',
    'MLILFormatterSSA',
    'mlil_reg_var_name',
    'mlil_global_var_name',

    # Type System
    'MLILType',
    'MLILTypeKind',
    'MLILVariantType',
    'unify_types',

    # Translator and optimizers
    'LLILToMLILTranslator',
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
    'RegGlobalState',
    'RegGlobalValuePropagator',
    'RegGlobalValuePropagationPass',

    # SSA
    'MediumLevelILOperationSSA',
    'MLILVariableSSA',
    'MLILVarSSA',
    'MLILUndef',
    'MLILSetVarSSA',
    'MLILPhi',
    'iter_ssa_reads',
    'iter_ssa_defs',
    'registers_left_by_returns',
    'DominanceAnalysis',
    'SSAConstructor',
    'SSADeconstructor',
    'convert_to_ssa',
    'convert_from_ssa',
]
