'''Dead Code Elimination Pass

Remove SSA variable assignments that are never used.
'''

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


class DeadCodeEliminationPass(Pass):
    '''Remove unused SSA variable assignments'''

    def __init__(self, sccp_replaced_vars: Set[MLILVariableSSA] = None):
        self.ssa_uses: Dict[MLILVariableSSA, List[MediumLevelILInstruction]] = {}
        self.sccp_replaced_vars = sccp_replaced_vars or set()

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Eliminate dead code'''
        self._build_use_chains(func)

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                if not isinstance(inst, (MLILSetVarSSA, MLILPhi)):
                    # An unread call result is dropped, the call itself stays
                    if isinstance(inst, MediumLevelILCall) and inst.output is not None:
                        if not self.ssa_uses.get(inst.output):
                            # Never discard an observable global write
                            if func.is_global_var(inst.output.base_var):
                                raise ValueError(f'call output is a global: {inst}')

                            inst.output = None

                    new_instructions.append(inst)
                    continue

                if isinstance(inst, MLILSetVarSSA):
                    uses = self.ssa_uses.get(inst.var, [])

                    # A global write is an observable cross-function side effect - keep it even
                    # with zero in-function reads, unlike an ordinary dead local assignment
                    if len(uses) > 0 or func.is_global_var(inst.var.base_var):
                        new_instructions.append(inst)

                    else:
                        # Preserve string constants as debug comments
                        # Skip if variable was replaced by SCCP (string is now in function args)
                        if isinstance(inst.value, MLILConst) and isinstance(inst.value.value, str):
                            if inst.var not in self.sccp_replaced_vars:
                                debug_comment = MLILDebug('string', inst.value.value)
                                new_instructions.append(debug_comment)

                elif isinstance(inst, MLILPhi):
                    if len(self.ssa_uses.get(inst.dest, [])) > 0:
                        new_instructions.append(inst)

            block.instructions = new_instructions

        return func

    def _build_use_chains(self, func: MediumLevelILFunction):
        '''Build SSA use chains'''
        self.ssa_uses = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                for var, reader in iter_ssa_reads(inst):
                    self.ssa_uses.setdefault(var, []).append(reader)
