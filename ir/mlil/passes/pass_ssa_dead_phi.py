'''Dead Phi Source Elimination Pass

Eliminate dead Phi nodes and their source definitions.
A Phi node is "dead" if its result is never used except by other dead Phi nodes.
'''

from typing import Dict, List, Set
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILBasicBlock,
    MLILConst,
    MLILDebug,
    MLILBinaryOp,
    MLILUnaryOp,
    MLILRet,
    MLILCall,
    MLILSyscall,
    MLILCallScript,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILStoreDeref,
)
from ..mlil_ssa import (
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILIf,
)


class DeadPhiSourceEliminationPass(Pass):
    '''Eliminate dead Phi nodes and definitions feeding them'''

    def __init__(self, sccp_replaced_vars: Set[MLILVariableSSA] = None):
        self.ssa_defs: Dict[MLILVariableSSA, MediumLevelILInstruction] = {}
        self.ssa_uses: Dict[MLILVariableSSA, List[MediumLevelILInstruction]] = {}
        self.inst_block: Dict[MediumLevelILInstruction, MediumLevelILBasicBlock] = {}
        self.sccp_replaced_vars = sccp_replaced_vars or set()

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Run dead phi elimination'''
        self._build_info(func)
        self._eliminate_dead_phis(func)
        return func

    def _build_info(self, func: MediumLevelILFunction):
        '''Build def-use chains and mappings'''
        self.ssa_defs = {}
        self.ssa_uses = {}
        self.inst_block = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                self.inst_block[inst] = block

                if isinstance(inst, MLILSetVarSSA):
                    self.ssa_defs[inst.var] = inst
                    self._collect_uses(inst.value, inst)

                elif isinstance(inst, MLILPhi):
                    self.ssa_defs[inst.dest] = inst
                    for src_var, _ in inst.sources:
                        if src_var not in self.ssa_uses:
                            self.ssa_uses[src_var] = []
                        self.ssa_uses[src_var].append(inst)

                else:
                    self._collect_uses_in_stmt(inst, inst)

    def _collect_uses(self, expr, user):
        '''Collect variable uses in expression'''
        if isinstance(expr, MLILVarSSA):
            if expr.var not in self.ssa_uses:
                self.ssa_uses[expr.var] = []
            self.ssa_uses[expr.var].append(user)

        elif isinstance(expr, MLILBinaryOp):
            self._collect_uses(expr.lhs, user)
            self._collect_uses(expr.rhs, user)

        elif isinstance(expr, MLILUnaryOp):
            self._collect_uses(expr.operand, user)

    def _collect_uses_in_stmt(self, stmt, user):
        '''Collect variable uses in statement'''
        if isinstance(stmt, MLILIf):
            self._collect_uses(stmt.condition, user)

        elif isinstance(stmt, MLILRet):
            if stmt.value:
                self._collect_uses(stmt.value, user)

        elif isinstance(stmt, (MLILCall, MLILSyscall, MLILCallScript)):
            for arg in stmt.args:
                self._collect_uses(arg, user)

        elif isinstance(stmt, (MLILStoreGlobal, MLILStoreReg)):
            self._collect_uses(stmt.value, user)

        elif isinstance(stmt, MLILStoreDeref):
            self._collect_uses(stmt.dest, user)
            self._collect_uses(stmt.value, user)

    def _eliminate_dead_phis(self, func: MediumLevelILFunction):
        '''Eliminate dead Phi nodes and definitions feeding them'''
        # Find all Phi nodes with no real use
        dead_phis: Set[MLILPhi] = set()
        for block in func.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILPhi):
                    if not self._has_real_use(inst.dest):
                        dead_phis.add(inst)

        if not dead_phis:
            return

        # Find definitions that only feed dead Phis
        dead_defs: Set[MLILVariableSSA] = set()
        for var, uses in self.ssa_uses.items():
            if not uses:
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
                    # Preserve string constants as debug comments
                    # Skip if variable was replaced by SCCP (string is now in function args)
                    if isinstance(inst.value, MLILConst) and isinstance(inst.value.value, str):
                        if inst.var not in self.sccp_replaced_vars:
                            debug_comment = MLILDebug('string', inst.value.value)
                            new_instructions.append(debug_comment)

                    continue

                new_instructions.append(inst)

            block.instructions = new_instructions

    def _has_real_use(self, start_var: MLILVariableSSA) -> bool:
        '''Check if variable has any real (non-Phi) use through Phi chains'''
        visited = set()
        queue = [start_var]

        while queue:
            var = queue.pop(0)
            if var in visited:
                continue

            visited.add(var)

            for use in self.ssa_uses.get(var, []):
                if isinstance(use, MLILPhi):
                    # Follow Phi chain
                    queue.append(use.dest)

                else:
                    # Found a real use
                    return True

        return False
