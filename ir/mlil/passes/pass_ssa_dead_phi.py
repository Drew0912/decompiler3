"""Dead Phi Source Elimination Pass

Eliminate dead Phi nodes and their source definitions.
A Phi node is "dead" if its result is never used except by other dead Phi nodes.
"""

from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
)
from ..mlil_ssa import (
    exit_register_versions,
    iter_ssa_reads,
    MLILVariableSSA,
    MLILSetVarSSA,
    MLILPhi,
)
from .pass_ssa_dead_code import string_debug_comment


class DeadPhiSourceEliminationPass(Pass):
    """Eliminate dead Phi nodes and definitions feeding them"""

    def __init__(self, replaced_vars: set[MLILVariableSSA] | None = None):
        self.ssa_uses: dict[MLILVariableSSA, list[MediumLevelILInstruction]] = {}
        self.exit_versions: set[MLILVariableSSA] = set()    # read by the caller after a return: a real use
        # Kept even while empty: the optimizer hands in constant propagation's set, which fills up later
        self.replaced_vars = set() if replaced_vars is None else replaced_vars

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Run dead phi elimination"""
        self._build_info(func)
        self._eliminate_dead_phis(func)
        return func

    def _build_info(self, func: MediumLevelILFunction):
        """Build SSA use chains, and the register versions the returns leave for the caller"""
        self.ssa_uses = {}

        for inst in func.iter_instructions():
            for var, _ in iter_ssa_reads(inst):
                self.ssa_uses.setdefault(var, []).append(inst)

        self.exit_versions = exit_register_versions(func)

    def _eliminate_dead_phis(self, func: MediumLevelILFunction):
        """Eliminate dead Phi nodes and definitions feeding them"""
        # Find all Phi nodes with no real use
        dead_phis: set[MLILPhi] = set()
        for inst in func.iter_instructions():
            if isinstance(inst, MLILPhi):
                if not self._has_real_use(inst.dest):
                    dead_phis.add(inst)

        if not dead_phis:
            return

        # Find definitions that only feed dead Phis
        dead_defs: set[MLILVariableSSA] = set()
        for var, uses in self.ssa_uses.items():
            if not uses or var in self.exit_versions:
                continue

            # Check if all uses are dead Phi nodes
            if all(isinstance(u, MLILPhi) and u in dead_phis for u in uses):
                # This variable only feeds dead Phis, so it's dead too
                dead_defs.add(var)

        # Remove dead Phi nodes and dead definitions
        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                # Skip dead Phi nodes
                if isinstance(inst, MLILPhi) and inst in dead_phis:
                    continue

                # Skip definitions that only feed dead Phis - except a global write, which is an
                # observable cross-function side effect regardless of whether the phi is read
                if isinstance(inst, MLILSetVarSSA) and inst.var in dead_defs \
                        and not func.is_global_var(inst.var.base_var):
                    new_instructions.extend(string_debug_comment(inst, self.replaced_vars))
                    continue

                new_instructions.append(inst)

            block.instructions = new_instructions

    def _has_real_use(self, start_var: MLILVariableSSA) -> bool:
        """Check if variable has any real (non-Phi) use through Phi chains: a read, or a return leaving it"""
        visited = set()
        queue = [start_var]

        while queue:
            var = queue.pop(0)
            if var in visited:
                continue

            visited.add(var)
            if var in self.exit_versions:
                return True

            for use in self.ssa_uses.get(var, []):
                if isinstance(use, MLILPhi):
                    # Follow Phi chain
                    queue.append(use.dest)
                else:
                    # Found a real use
                    return True

        return False
