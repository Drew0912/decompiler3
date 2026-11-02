"""Expression Inlining Pass

Inline expressions that are only used once.
Pattern: x#n = expr; ... use(x#n) -> ... use(expr)
"""

from ir.pipeline import Pass
from ir.mlil.mlil import (
    map_operands,
    walk,
    MediumLevelILFunction,
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
    MLILConst,
    MLILLoadGlobal,
    MLILLoadReg,
    MLILAddressOf,
    MLILDeref,
)
from ..mlil_ssa import (
    iter_ssa_defs,
    iter_ssa_reads,
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILUndef,
)
from .pass_ssa_copy_propagation import reaches_without_redefinition


class ExpressionInliningPass(Pass):
    """Inline single-use expressions"""

    def __init__(self):
        self.ssa_defs: dict[MLILVariableSSA, MLILSetVarSSA] = {}
        self.def_positions: dict[MLILVariableSSA, tuple[MediumLevelILBasicBlock, int]] = {}
        self.ssa_uses: dict[MLILVariableSSA, list[MediumLevelILInstruction]] = {}
        self.use_positions: dict[MLILVariableSSA, list[tuple[MediumLevelILBasicBlock, int]]] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Inline single-use expressions"""
        changed = True

        while changed:
            self._build_def_use_chains(func)
            changed = self._inline_once(func)

        return func

    def _build_def_use_chains(self, func: MediumLevelILFunction):
        """Build SSA def-use chains, tracking each def's and use's (block, index) position"""
        self.ssa_defs = {}
        self.def_positions = {}
        self.ssa_uses = {}
        self.use_positions = {}

        for var, definition, block, index in iter_ssa_defs(func):
            self.ssa_defs[var] = definition
            self.def_positions[var] = (block, index)

        for block in func.basic_blocks:
            for idx, inst in enumerate(block.instructions):
                for var, reader in iter_ssa_reads(inst):
                    self._record_use(var, reader, block, idx)

    def _record_use(self, var: MLILVariableSSA, use: MediumLevelILInstruction,
                    block: MediumLevelILBasicBlock, idx: int):
        self.ssa_uses.setdefault(var, []).append(use)
        self.use_positions.setdefault(var, []).append((block, idx))

    def _inline_once(self, func: MediumLevelILFunction) -> bool:
        """Single inlining pass"""
        inlinable: dict[MLILVariableSSA, MediumLevelILInstruction] = {}

        for ssa_var, defn in self.ssa_defs.items():
            if not isinstance(defn, MLILSetVarSSA):
                continue

            # Skip var-to-var copies (handled by CopyPropagation)
            if isinstance(defn.value, MLILVarSSA):
                continue

            # Skip constants (handled by ConstantPropagation)
            if isinstance(defn.value, MLILConst):
                continue

            # Undefined values mark a variable a call may have written; inlining one
            # would turn a real read into <undef>
            if isinstance(defn.value, MLILUndef):
                continue

            uses = self.ssa_uses.get(ssa_var, [])
            if len(uses) != 1:
                continue

            use = uses[0]

            # Skip if used in Phi (may require duplication across branches)
            if isinstance(use, MLILPhi):
                continue

            def_pos = self.def_positions.get(ssa_var)
            use_pos = self.use_positions.get(ssa_var, [None])[0]

            storages = self._impure_read_storages(defn.value, func)

            if storages is None or storages:
                if def_pos is None or use_pos is None:
                    continue

                if storages is None:
                    # No trackable storage to check reachability against - require the use to
                    # be the immediately next instruction instead of refusing to inline at all
                    if not self._is_immediate_use(def_pos, use_pos, use):
                        continue
                else:
                    def_block, def_idx = def_pos
                    use_block, use_idx = use_pos
                    if not all(
                        reaches_without_redefinition(func, storage, def_block, def_idx, use_block, use_idx)
                        for storage in storages
                    ):
                        continue

            inlinable[ssa_var] = defn.value

        if not inlinable:
            return False

        changed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = map_operands(inst, lambda expr: self._inline_in_expr(expr, inlinable))
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _impure_read_storages(self, expr: MediumLevelILInstruction, func: MediumLevelILFunction) -> list | None:
        """The register/global base variables expr reads, one entry per read in evaluation order;
        [] if it reads no mutable storage. `reg0 + global3` gives two: a hazard on either one alone
        makes forwarding the expression unsafe, so each needs its own reachability check.

        None if expr contains an MLILDeref, MLILLoadReg or MLILLoadGlobal anywhere: none of these
        has an SSA version reaches_without_redefinition can track, so one poisons the whole
        expression. (An MLILLoadGlobal survives into SSA form for a global this function only
        reads - mlil_ssa.py's _raise_globals never raises it into a variable.)
        """
        storages = []
        for node in walk(expr):
            if isinstance(node, (MLILLoadReg, MLILLoadGlobal, MLILDeref)):
                return None

            if isinstance(node, MLILVarSSA):
                base = node.var.base_var
                if func.is_register_var(base) or func.is_global_var(base):
                    storages.append(base)

        return storages

    def _is_immediate_use(self, def_pos: tuple[MediumLevelILBasicBlock, int],
                          use_pos: tuple[MediumLevelILBasicBlock, int],
                          use: MediumLevelILInstruction) -> bool:
        """Check if use immediately follows definition in the same block"""
        def_block, def_idx = def_pos
        use_block, use_idx = use_pos

        if def_block is not use_block or use_idx != def_idx + 1:
            return False

        return any(node is use for node in walk(def_block.instructions[def_idx + 1]))

    def _inline_in_expr(self, expr: MediumLevelILInstruction,
                        inlinable: dict[MLILVariableSSA, MediumLevelILInstruction]) -> MediumLevelILInstruction:
        """Inline single-use expressions"""
        if isinstance(expr, MLILVarSSA):
            return inlinable.get(expr.var, expr)
        elif isinstance(expr, MLILAddressOf):
            # &x's operand is a location: an expression computing x's value is no substitute
            return expr
        else:
            return map_operands(expr, lambda operand: self._inline_in_expr(operand, inlinable))
