"""SSA-related passes"""

from ir.pipeline import Pass
from ir.mlil.mlil import MediumLevelILFunction
from ..mlil_ssa import convert_to_ssa, convert_from_ssa


class SSAConversionPass(Pass):
    """Convert MLIL to SSA form"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        convert_to_ssa(func)
        return func


class SSAOptimizationPass(Pass):
    """Run SSA-based optimizations"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        # Delayed import to avoid circular dependency
        from ..mlil_ssa_optimizer import SSAOptimizer
        optimizer = SSAOptimizer(func)
        return optimizer.optimize()


class SSADeconstructionPass(Pass):
    """Convert SSA back to non-SSA form"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        convert_from_ssa(func)
        return func
