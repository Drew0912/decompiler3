"""Dead Code Elimination Pass

Remove SSA variable assignments that are never used.
"""

from typing import Dict, List, Set
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILCall,
    MLILConst,
    MLILDebug,
)
from ..mlil_ssa import (
    iter_ssa_reads,
    MLILVariableSSA,
    MLILSetVarSSA,
    MLILPhi,
)


def string_debug_comment(inst: MLILSetVarSSA, sccp_replaced_vars: Set[MLILVariableSSA]) -> List[MLILDebug]:
    """A removed assignment of a string constant, kept as a debug comment - unless SCCP replaced the variable,
    so the string already sits in its uses (a call's arguments)"""
    if isinstance(inst.value, MLILConst) and isinstance(inst.value.value, str) and inst.var not in sccp_replaced_vars:
        return [MLILDebug('string', inst.value.value).copy_metadata_from(inst)]

    return []


class SSADeadCodeEliminationPass(Pass):
    """Remove unused SSA variable assignments"""

    def __init__(self, sccp_replaced_vars: Set[MLILVariableSSA] = None):
        self.ssa_uses: Dict[MLILVariableSSA, List[MediumLevelILInstruction]] = {}
        self.sccp_replaced_vars = sccp_replaced_vars or set()

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Eliminate dead code

        Removing an assignment or phi can leave the definitions it read unread too, so one sweep
        only removes the unread end of a dead chain - sweep until a sweep removes none.
        """
        while self._sweep(func):
            pass

        return func

    def _sweep(self, func: MediumLevelILFunction) -> bool:
        """Remove every assignment and phi nothing reads now; whether any was removed

        Clearing an unread call output does not count: it drops no read, so it cannot make
        anything else dead.
        """
        self._build_use_chains(func)
        removed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    # A global write is an observable cross-function side effect - keep it even
                    # with zero in-function reads, unlike an ordinary dead local assignment
                    if self.ssa_uses.get(inst.var) or func.is_global_var(inst.var.base_var):
                        new_instructions.append(inst)
                    else:
                        removed = True
                        new_instructions.extend(string_debug_comment(inst, self.sccp_replaced_vars))
                elif isinstance(inst, MLILPhi):
                    if self.ssa_uses.get(inst.dest):
                        new_instructions.append(inst)
                    else:
                        removed = True
                else:
                    # An unread call result is dropped, the call itself stays
                    if isinstance(inst, MediumLevelILCall) and inst.output is not None:
                        if not self.ssa_uses.get(inst.output):
                            inst.output = None

                    new_instructions.append(inst)

            block.instructions = new_instructions

        return removed

    def _build_use_chains(self, func: MediumLevelILFunction):
        """Build SSA use chains"""
        self.ssa_uses = {}

        for inst in func.iter_instructions():
            for var, reader in iter_ssa_reads(inst):
                self.ssa_uses.setdefault(var, []).append(reader)
