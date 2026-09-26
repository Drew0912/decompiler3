'''HLIL Optimization Passes'''

from .pass_mlil_to_hlil import MLILToHLILPass
from .pass_control_flow_optimization import ControlFlowOptimizationPass
from .pass_loop_recovery import LoopRecoveryPass
from .pass_common_return_extraction import CommonReturnExtractionPass
from .pass_dead_code_elimination import DeadCodeEliminationPass
from .pass_branch_order_normalization import BranchOrderNormalizationPass

__all__ = [
    'MLILToHLILPass',
    'ControlFlowOptimizationPass',
    'LoopRecoveryPass',
    'CommonReturnExtractionPass',
    'DeadCodeEliminationPass',
    'BranchOrderNormalizationPass',
]
