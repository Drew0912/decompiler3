'''Copy Propagation Pass

Replace SSA variable copies (x#1 = x#0 -> use x#0).
'''

from typing import Dict, List, Optional, Set, Tuple
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
    MLILBinaryOp,
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILTestZero,
    MLILRet,
    MediumLevelILCall,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILAddressOf,
    MLILDeref,
    MLILStoreDeref,
)
from ..mlil_ssa import (
    iter_ssa_reads,
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILIf,
)


def reaches_without_redefinition(func: MediumLevelILFunction, base_var, def_block: MediumLevelILBasicBlock,
                                 def_idx: int, use_block: MediumLevelILBasicBlock, use_idx: int) -> bool:
    '''True if nothing between (def_block, def_idx) and (use_block, use_idx) redefines base_var:
    an explicit definition, a call's own output, or a call that may clobber it
    (func.call_may_clobber). The call itself counts, not its `<undef>` pseudo-defs, which
    dead-code elimination can drop while the clobber remains.

    Across blocks, use_block's prefix is scanned first, then the walk follows single-predecessor
    edges back to def_block. Only in-degree matters: a def block that branches still forwards
    into a successor whose sole predecessor it is, while a merge point or a cycle that never
    reaches def_block returns False. Shared by CopyPropagationPass and ExpressionInliningPass.
    '''
    def redefines(inst) -> bool:
        if isinstance(inst, MLILSetVarSSA):
            return inst.var.base_var == base_var

        if isinstance(inst, MediumLevelILCall):
            return (inst.output is not None and inst.output.base_var == base_var) or func.call_may_clobber(inst, base_var)

        return False

    if def_block is use_block:
        if def_idx <= use_idx:
            return not any(redefines(inst) for inst in def_block.instructions[def_idx + 1:use_idx])

        return False  # use precedes def in program order - not a valid def->use edge

    if any(redefines(inst) for inst in use_block.instructions[:use_idx]):
        return False

    current = use_block
    visited = {use_block}
    while current is not def_block:
        if len(current.incoming_edges) != 1:
            return False  # a merge point - ambiguous which predecessor actually ran

        pred = current.incoming_edges[0]
        if pred in visited:
            return False  # a single-predecessor cycle that never reaches def_block

        visited.add(pred)
        start = def_idx + 1 if pred is def_block else 0
        if any(redefines(inst) for inst in pred.instructions[start:]):
            return False

        current = pred

    return True


class CopyPropagationPass(Pass):
    '''Replace SSA variable copies with original variables'''

    def __init__(self):
        self.ssa_defs: Dict[MLILVariableSSA, MLILSetVarSSA] = {}
        self.def_positions: Dict[MLILVariableSSA, Tuple[MediumLevelILBasicBlock, int]] = {}
        self.use_counts: Dict[MLILVariableSSA, int] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Propagate copies through the function'''
        changed = True

        while changed:
            self._build_def_chains(func)
            self._count_uses(func)
            changed = self._propagate_once(func)

        return func

    def _build_def_chains(self, func: MediumLevelILFunction):
        '''Build SSA definition chains and their (block, index) positions'''
        self.ssa_defs = {}
        self.def_positions = {}

        for block in func.basic_blocks:
            for idx, inst in enumerate(block.instructions):
                if isinstance(inst, MLILSetVarSSA):
                    self.ssa_defs[inst.var] = inst
                    self.def_positions[inst.var] = (block, idx)

                elif isinstance(inst, MLILPhi):
                    self.ssa_defs[inst.dest] = inst
                    self.def_positions[inst.dest] = (block, idx)

    def _count_uses(self, func: MediumLevelILFunction):
        '''Count reads of every SSA variable'''
        self.use_counts = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                for var in self._collect_uses(inst):
                    self.use_counts[var] = self.use_counts.get(var, 0) + 1

    @classmethod
    def _collect_uses(cls, node: MediumLevelILInstruction) -> List[MLILVariableSSA]:
        '''SSA variables node reads. A read under & is not counted: this pass never rewrites the
        operand of &.'''
        return [var for var, _ in iter_ssa_reads(node, skip = (MLILAddressOf,))]

    def _propagate_once(self, func: MediumLevelILFunction) -> bool:
        '''Single copy propagation pass - resolves each read to its effective root'''
        changed = False

        for block in func.basic_blocks:
            new_instructions = []

            for idx, inst in enumerate(block.instructions):
                new_inst = self._replace_in_inst(inst, func, block, idx)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _resolve_effective_root(self, var: MLILVariableSSA, func: MediumLevelILFunction,
                                use_block: MediumLevelILBasicBlock, use_idx: int,
                                visiting: Optional[Set[MLILVariableSSA]] = None) -> MLILVariableSSA:
        '''Follow a chain of pure copies (x#n = y#m) back to its furthest safe ancestor.

        Stops at the first link that is not itself a plain copy, that is a register/global
        read from a source used more than once (keeps the local's own name rather than
        spreading the register's/global's identity over it), or whose source is not safely
        reachable - without an intervening redefinition of the same storage - from var's OWN
        definition (not source_var's) through to (use_block, use_idx). Using var's definition
        rather than source_var's is deliberate, not just simpler: SSA construction guarantees
        nothing redefines source_var's base variable between source_var's own definition and
        var's definition anyway (otherwise var would have been assigned a later version), so
        that earlier stretch never needed checking - and var's definition always has a
        recorded position (it is exactly how `defn` above was found), while source_var's does
        not when source_var is a version seeded at function entry (a parameter, or a
        register/global read before any assignment in this function). Cycle-guarded via
        `visiting`, since a chain can only be walked once per call regardless.

        The multi-use check applies at every hop, not just one whose immediate source is a
        register/global: t#1 = reg0#1; a#1 = t#1; z1#1 = a#1; z2#1 = a#1 must stop at a#1
        (used twice), not resolve through it to reg0#1, even though t#1 itself (a#1's direct
        source) is used only once. The recursive call below resolves the rest of the chain
        first, so the register/global-ness of the final root is known before this hop decides
        whether it is safe to disappear into it.
        '''
        if visiting is None:
            visiting = set()

        if var in visiting:
            return var

        defn = self.ssa_defs.get(var)
        if not isinstance(defn, MLILSetVarSSA) or not isinstance(defn.value, MLILVarSSA):
            return var

        source_var = defn.value.var
        is_reg_or_global = func.is_register_var(source_var.base_var) or func.is_global_var(source_var.base_var)

        if is_reg_or_global:
            # A local read more than once keeps its own name rather than the
            # register's/global's, so reg0/global0 does not spread over values that have a
            # real variable. With a single read there is nothing to spread.
            if self.use_counts.get(var, 0) > 1:
                return var

            def_block, def_idx = self.def_positions[var]
            if not reaches_without_redefinition(func, source_var.base_var, def_block, def_idx, use_block, use_idx):
                return var

        visiting.add(var)
        root = self._resolve_effective_root(source_var, func, use_block, use_idx, visiting)

        # var's own source (source_var) may be a plain local - is_reg_or_global False above,
        # so the multi-use guard never ran for var - but resolving further back may still
        # land on a register/global through that local. The same "don't spread reg/global
        # identity over a multiply-used value" rule applies here too.
        root_is_reg_or_global = func.is_register_var(root.base_var) or func.is_global_var(root.base_var)
        if root_is_reg_or_global and self.use_counts.get(var, 0) > 1:
            return var

        return root

    def _replace_in_inst(self, inst: MediumLevelILInstruction, func: MediumLevelILFunction,
                         block: MediumLevelILBasicBlock, idx: int) -> MediumLevelILInstruction:
        '''Replace copy variables in instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._replace_in_expr(inst.value, func, block, idx)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_condition = self._replace_in_expr(inst.condition, func, block, idx)
            if new_condition is not inst.condition:
                return MLILIf(new_condition, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._replace_in_expr(inst.value, func, block, idx)
                if new_value is not inst.value:
                    return MLILRet(new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MediumLevelILCall):
            new_args = [self._replace_in_expr(arg, func, block, idx) for arg in inst.args]
            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                return inst.rebuild(new_args)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._replace_in_expr(inst.value, func, block, idx)
            if new_value is not inst.value:
                if isinstance(inst, MLILStoreGlobal):
                    return MLILStoreGlobal(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

                return MLILStoreReg(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._replace_in_expr(inst.dest, func, block, idx)
            new_value = self._replace_in_expr(inst.value, func, block, idx)
            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _replace_in_expr(self, expr: MediumLevelILInstruction, func: MediumLevelILFunction,
                         block: MediumLevelILBasicBlock, idx: int) -> MediumLevelILInstruction:
        '''Replace copy variables in expression'''
        if isinstance(expr, MLILVarSSA):
            root = self._resolve_effective_root(expr.var, func, block, idx)
            if root is not expr.var:
                return MLILVarSSA(root)

        elif isinstance(expr, MLILBinaryOp):
            lhs = self._replace_in_expr(expr.lhs, func, block, idx)
            rhs = self._replace_in_expr(expr.rhs, func, block, idx)
            if lhs is not expr.lhs or rhs is not expr.rhs:
                return expr.rebuild(lhs, rhs)

        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILTestZero, MLILDeref)):
            # MLILDeref belongs here: unlike MLILAddressOf (whose operand is a location, never
            # substitutable), a pointer's VALUE is an ordinary operand - propagating a value-equal
            # copy into it is safe and desirable.
            operand = self._replace_in_expr(expr.operand, func, block, idx)
            if operand is not expr.operand:
                return expr.rebuild(operand)

        return expr
