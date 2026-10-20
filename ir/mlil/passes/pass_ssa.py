"""SSA-related passes"""

from ir.pipeline import Pass
from ..mlil import MediumLevelILFunction
from ..mlil_ssa import convert_to_ssa, convert_from_ssa


class SSAConversionPass(Pass):
    """Convert MLIL to SSA form"""

    def run(self, mlil_func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Convert to SSA form (in-place)"""
        convert_to_ssa(mlil_func)
        return mlil_func


class SSAOptimizationPass(Pass):
    """Run SSA-based optimizations"""

    def run(self, mlil_func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Optimize SSA form"""
        # Delayed import to avoid circular dependency
        from ..mlil_ssa_optimizer import SSAOptimizer
        optimizer = SSAOptimizer(mlil_func)
        return optimizer.optimize()


class SSADeconstructionPass(Pass):
    """Convert SSA back to non-SSA form"""

    def run(self, mlil_func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Deconstruct SSA form (in-place)"""
        convert_from_ssa(mlil_func)
        return mlil_func
