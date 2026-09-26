'''MLIL Optimization Passes'''

# Lifting
from .pass_llil_to_mlil import LLILToMLILPass

# SSA conversion/deconstruction
from .pass_ssa import SSAConversionPass, SSAOptimizationPass, SSADeconstructionPass

# SSA optimization passes
from .pass_ssa_nnf import NNFPass
from .pass_ssa_sccp import SCCP, LatticeValue
from .pass_ssa_constant_propagation import ConstantPropagationPass
from .pass_ssa_copy_propagation import CopyPropagationPass
from .pass_ssa_expression_simplification import ExpressionSimplificationPass
from .pass_ssa_condition_simplification import ConditionSimplificationPass
from .pass_ssa_expression_inlining import ExpressionInliningPass
from .pass_ssa_dead_code import DeadCodeEliminationPass as SSADeadCodeEliminationPass
from .pass_ssa_dead_phi import DeadPhiSourceEliminationPass
from .pass_ssa_type_inference import SSATypeInferencePass

# Non-SSA passes
from .pass_block_merge import BlockMergePass
from .pass_reg_global_propagation import (
    StorageKind,
    StorageKey,
    RegGlobalState,
    RegGlobalValuePropagator,
    RegGlobalValuePropagationPass,
)

__all__ = [
    # Lifting
    'LLILToMLILPass',
    # SSA conversion
    'SSAConversionPass',
    'SSAOptimizationPass',
    'SSADeconstructionPass',
    # SSA optimization
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
    # Non-SSA
    'BlockMergePass',
    'StorageKind',
    'StorageKey',
    'RegGlobalState',
    'RegGlobalValuePropagator',
    'RegGlobalValuePropagationPass',
]
