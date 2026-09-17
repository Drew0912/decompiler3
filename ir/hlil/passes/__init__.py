'''HLIL Optimization Passes'''

from .pass_mlil_to_hlil import MLILToHLILPass
from .pass_control_flow_optimization import ControlFlowOptimizationPass
from .pass_loop_recovery import LoopRecoveryPass
from .pass_common_return_extraction import CommonReturnExtractionPass
from .pass_copy_propagation import CopyPropagationPass
from .pass_dead_code_elimination import DeadCodeEliminationPass

__all__ = [
    'MLILToHLILPass',
    'ControlFlowOptimizationPass',
    'LoopRecoveryPass',
    'CommonReturnExtractionPass',
    'CopyPropagationPass',
    'DeadCodeEliminationPass',
]
