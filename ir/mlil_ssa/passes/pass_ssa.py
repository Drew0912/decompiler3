"""SSA-related passes"""

from ir.pipeline import Pass
from ..mlil_ssa import convert_to_ssa, convert_from_ssa
from ..mlil_ssa_function import MediumLevelILFunctionSSA


class SSAConversionPass(Pass):
    """Convert MLIL to SSA form"""

    def run(self, func: MediumLevelILFunctionSSA) -> MediumLevelILFunctionSSA:
        convert_to_ssa(func)
        return func


class SSAOptimizationPass(Pass):
    """Run SSA-based optimizations"""

    def run(self, func: MediumLevelILFunctionSSA) -> MediumLevelILFunctionSSA:
        # Delayed import to avoid circular dependency
        from ..mlil_ssa_optimizer import SSAOptimizer
        optimizer = SSAOptimizer(func)
        return optimizer.optimize()


class SSADeconstructionPass(Pass):
    """Convert SSA back to non-SSA form"""

    def run(self, func: MediumLevelILFunctionSSA) -> MediumLevelILFunctionSSA:
        convert_from_ssa(func)
        return func
