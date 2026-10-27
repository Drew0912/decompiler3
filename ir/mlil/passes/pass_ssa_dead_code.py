"""Dead Code Elimination Pass

Remove SSA variable assignments that are never used
"""

from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
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


def string_debug_comment(inst: MLILSetVarSSA, replaced_vars: set[MLILVariableSSA]) -> list[MLILDebug]:
    """A removed assignment of a string constant, kept as a debug comment - unless constant propagation replaced
    the variable, so the string already sits in its uses (a call's arguments)"""
    if isinstance(inst.value, MLILConst) and isinstance(inst.value.value, str) and inst.var not in replaced_vars:
        return [MLILDebug('string', inst.value.value).copy_metadata_from(inst)]

    return []


class SSADeadCodeEliminationPass(Pass):
    """Remove unused SSA variable assignments"""

    def __init__(self, replaced_vars: set[MLILVariableSSA] | None = None):
        self.read_vars: set[MLILVariableSSA] = set()
        # Kept even while empty: the optimizer hands in constant propagation's set, which fills up later
        self.replaced_vars = set() if replaced_vars is None else replaced_vars

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Eliminate dead code

        Removing an assignment or phi can leave the definitions it read unread too, so one sweep
        only removes the unread end of a dead chain - sweep until a sweep removes none
        """
        while self._sweep(func):
            pass

        return func

    def _sweep(self, func: MediumLevelILFunction) -> bool:
        """Remove every assignment and phi nothing reads now; whether any was removed

        Clearing an unread call output does not count: it drops no read, so it cannot make
        anything else dead
        """
        self._collect_read_vars(func)
        removed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    # A global write is an observable cross-function side effect - keep it even
                    # with zero in-function reads, unlike an ordinary dead local assignment
                    if inst.var in self.read_vars or func.is_global_var(inst.var.base_var):
                        new_instructions.append(inst)
                    else:
                        removed = True
                        new_instructions.extend(string_debug_comment(inst, self.replaced_vars))
                elif isinstance(inst, MLILPhi):
                    if inst.dest in self.read_vars:
                        new_instructions.append(inst)
                    else:
                        removed = True
                else:
                    # An unread call result is dropped, the call itself stays
                    if isinstance(inst, MediumLevelILCall) and inst.output is not None:
                        if inst.output not in self.read_vars:
                            inst.output = None

                    new_instructions.append(inst)

            block.instructions = new_instructions

        return removed

    def _collect_read_vars(self, func: MediumLevelILFunction):
        """The SSA variables func reads anywhere: a sweep only asks whether a variable is read"""
        self.read_vars = {var for inst in func.iter_instructions() for var, _ in iter_ssa_reads(inst)}
