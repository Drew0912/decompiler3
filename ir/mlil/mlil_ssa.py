'''MLIL SSA - SSA form with dominance analysis and Phi placement'''

from __future__ import annotations
from typing import Dict, List, Set, Optional, Tuple, Deque
from collections import deque, defaultdict
from .mlil import *


# ============================================================================
# SSA Types
# ============================================================================

class MLILVariableSSA:
    '''SSA-versioned variable (e.g., var_s0#1, var_s0#2)'''

    def __init__(self, base_var: MLILVariable, version: int):
        self.base_var = base_var
        self.version = version

    @property
    def name(self) -> str:
        return f'{self.base_var.name}#{self.version}'

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f'SSA({self.base_var.name}#{self.version})'

    def __eq__(self, other) -> bool:
        return (isinstance(other, MLILVariableSSA) and
                self.base_var == other.base_var and
                self.version == other.version)

    def __hash__(self) -> int:
        return hash((self.base_var, self.version))


class MLILVarSSA(MediumLevelILExpr):
    '''Load SSA variable value'''

    def __init__(self, var: MLILVariableSSA, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_VAR_SSA, **kwargs)
        self.var = var

    def __str__(self) -> str:
        return str(self.var)


class MLILSetVarSSA(MediumLevelILStatement):
    '''Assign to SSA variable'''

    def __init__(self, var: MLILVariableSSA, value: MediumLevelILInstruction, **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_SET_VAR_SSA, **kwargs)
        self.var = var
        self.value = value

    def __str__(self) -> str:
        return f'{self.var} = {self.value}'


class MLILPhi(MediumLevelILStatement):
    '''Phi node: merge values from predecessors'''

    def __init__(self, dest: MLILVariableSSA, sources: List[Tuple[MLILVariableSSA, MediumLevelILBasicBlock]], **kwargs):
        super().__init__(MediumLevelILOperation.MLIL_PHI, **kwargs)
        self.dest = dest
        self.sources = sources  # [(ssa_var, predecessor_block), ...]

    def __str__(self) -> str:
        if not self.sources:
            return f'{self.dest} = φ()'

        src_strs = ', '.join(f'{var} from {block.label}' for var, block in self.sources)
        return f'{self.dest} = φ({src_strs})'


# ============================================================================
# Dominance Analysis (Iterative)
# ============================================================================

class DominanceAnalysis:
    '''Compute dominance tree and dominance frontiers (iterative)'''

    def __init__(self, function: MediumLevelILFunction):
        self.function = function
        self.blocks = self._compute_rpo(function.basic_blocks)

        # Results
        self.idom: Dict[MediumLevelILBasicBlock, Optional[MediumLevelILBasicBlock]] = {}
        self.dom_tree: Dict[MediumLevelILBasicBlock, List[MediumLevelILBasicBlock]] = defaultdict(list)
        self.dom_frontier: Dict[MediumLevelILBasicBlock, Set[MediumLevelILBasicBlock]] = defaultdict(set)

    def _compute_rpo(self, blocks: List[MediumLevelILBasicBlock]) -> List[MediumLevelILBasicBlock]:
        '''Compute Reverse Postorder via DFS (only reachable blocks)'''
        if not blocks:
            return []

        visited = set()
        postorder = []
        stack = [(blocks[0], False)]

        while stack:
            block, processed = stack.pop()

            if processed:
                postorder.append(block)
                continue

            if block in visited:
                continue

            visited.add(block)
            stack.append((block, True))

            for succ in reversed(block.outgoing_edges):
                if succ not in visited:
                    stack.append((succ, False))

        return list(reversed(postorder))

    def analyze(self):
        '''Run dominance analysis'''
        self._compute_dominators()
        self._build_dom_tree()
        self._compute_dom_frontiers()

    def _compute_dominators(self):
        '''Compute immediate dominators (iterative dataflow)'''
        if not self.blocks:
            return

        entry = self.blocks[0]

        # Initialize: entry dominates itself, others dominated by all
        self.idom[entry] = entry
        for block in self.blocks[1:]:
            self.idom[block] = None

        # Build predecessor map
        preds: Dict[MediumLevelILBasicBlock, List[MediumLevelILBasicBlock]] = defaultdict(list)
        for block in self.blocks:
            for succ in block.outgoing_edges:
                preds[succ].append(block)

        # Iterate until convergence
        changed = True
        while changed:
            changed = False

            for block in self.blocks[1:]:  # Skip entry
                if not preds[block]:
                    continue

                # New idom = intersect of all processed predecessors
                new_idom = None
                for pred in preds[block]:
                    if self.idom[pred] is not None:
                        if new_idom is None:
                            new_idom = pred

                        else:
                            new_idom = self._intersect(pred, new_idom)

                if new_idom != self.idom[block]:
                    self.idom[block] = new_idom
                    changed = True

    def _intersect(self, b1: MediumLevelILBasicBlock, b2: MediumLevelILBasicBlock) -> MediumLevelILBasicBlock:
        '''Find common dominator of b1 and b2'''
        finger1 = b1
        finger2 = b2

        # Build index cache for O(1) lookup
        if not hasattr(self, '_block_index'):
            self._block_index = {b: i for i, b in enumerate(self.blocks)}

        max_iterations = len(self.blocks) * 2
        iterations = 0

        while finger1 != finger2:
            iterations += 1
            if iterations > max_iterations:
                raise RuntimeError(f'_intersect: infinite loop detected between {b1} and {b2}')

            while self._block_index[finger1] > self._block_index[finger2]:
                finger1 = self.idom[finger1]

            while self._block_index[finger2] > self._block_index[finger1]:
                finger2 = self.idom[finger2]

        return finger1

    def _build_dom_tree(self):
        '''Build dominator tree from immediate dominators'''
        for block, dominator in self.idom.items():
            if dominator is not None and dominator != block:
                self.dom_tree[dominator].append(block)

    def _compute_dom_frontiers(self):
        '''Compute dominance frontiers (iterative)'''
        # Build predecessor map
        preds: Dict[MediumLevelILBasicBlock, List[MediumLevelILBasicBlock]] = defaultdict(list)
        for block in self.blocks:
            for succ in block.outgoing_edges:
                preds[succ].append(block)

        max_iterations = len(self.blocks)

        for block in self.blocks:
            if len(preds[block]) < 2:
                continue

            for pred in preds[block]:
                runner = pred
                iterations = 0

                while runner != self.idom.get(block):
                    iterations += 1
                    if iterations > max_iterations:
                        raise RuntimeError(f'_compute_dom_frontiers: infinite loop at block {block}')

                    self.dom_frontier[runner].add(block)
                    runner = self.idom.get(runner)

                    if runner is None:
                        break


def _names_in_use(function: MediumLevelILFunction) -> Set[str]:
    '''Every name a fresh local must not collide with: locals (registers included - a
    register's MLILVariable is created via get_or_create_local, so it lives in .locals too),
    parameters, and globals. Shared by every minted-name site in this file
    (SSAConstructor._mint_local, SSADeconstructor._allocate_variables) so they cannot
    independently drift on which namespaces count.'''
    return (set(function.locals)
            | {p.name for p in function.parameters if p is not None}
            | {g.name for g in function.global_vars.values()})


# ============================================================================
# SSA Construction (Iterative)
# ============================================================================

class SSAConstructor:
    '''Convert MLIL to SSA form (iterative algorithms)'''

    def __init__(self, function: MediumLevelILFunction, remove_unreachable: bool = False):
        self.function = function
        self.remove_unreachable = remove_unreachable
        self.dom_analysis = DominanceAnalysis(function)

        # Variable tracking
        self.var_defs: Dict[MLILVariable, Set[MediumLevelILBasicBlock]] = defaultdict(set)
        self.var_versions: Dict[MLILVariable, int] = {}
        self.var_stack: Dict[MLILVariable, List[int]] = defaultdict(list)

        # Every local whose address is taken anywhere in the function - populated by
        # construct() before def-collection, since a deref store's conservative clobber
        # (see _collect_defs/_rename_inst) needs it
        self.address_taken_vars: Set[MLILVariable] = set()

    def construct(self) -> MediumLevelILFunction:
        '''Convert function to SSA form (modifies in-place)'''
        # Step 0: Raise stored globals into variables, so the rest of SSA construction
        # tracks them exactly like registers (versions, phis, call clobbers)
        self._raise_globals()

        # Step 1: Dominance analysis
        self.dom_analysis.analyze()

        # Optionally remove unreachable blocks
        if self.remove_unreachable:
            reachable_set = set(self.dom_analysis.blocks)
            self.function.basic_blocks = [b for b in self.function.basic_blocks if b in reachable_set]
            self.function.renumber_blocks()

        # Step 2: Collect address-taken locals/parameters - a stable storage identity, not
        # a scalar SSA value, so they are lowered to explicit *(&x) memory form below rather
        # than versioned directly (see _lower_address_taken_vars)
        self.address_taken_vars = self._collect_address_taken_vars()

        # Step 3: A call's own output is a def path independent of MLILSetVar - redirect any
        # that would alias an address-taken local through a fresh temp before the general
        # lowering runs, so that lowering never has to special-case call outputs
        self._decompose_address_taken_call_outputs()

        # Step 4: Lower every address-taken local's reads/writes to explicit *(&x) deref/
        # store form, so each one renames to a single stable address identity below instead
        # of being versioned like an ordinary scalar
        self._lower_address_taken_vars()

        # Step 5: Collect variable definitions
        self._collect_defs()

        # Step 6: Insert Phi nodes
        self._insert_phi_nodes()

        # Step 7: Rename variables (iterative)
        self._rename_variables_iterative()

        return self.function

    def _collect_address_taken_vars(self) -> Set[MLILVariable]:
        '''Every local or parameter whose address is taken anywhere in the function.

        Deliberately function-wide rather than scoped to one AddressOf site, since a lowered
        read/write (see _lower_address_taken_vars) must be consistent everywhere the variable
        appears, not just near the nearest '&'.

        Raises if a register or raised global is ever address-taken - no opcode produces one
        today, and admitting one here would need the same memory-form lowering this class
        gives locals/parameters, which registers/globals do not go through. Checked by
        identity (is_register_var/is_global_var), not by '.locals' membership - a register's
        MLILVariable is created via get_or_create_local, so it lives in '.locals' too.
        '''
        address_taken: Set[MLILVariable] = set()

        for block in self.function.basic_blocks:
            for inst in block.instructions:
                self._collect_address_taken_in(inst, address_taken)

        for var in address_taken:
            if self.function.is_register_var(var) or self.function.is_global_var(var):
                raise NotImplementedError(
                    f'Address taken of register/global variable {var.name!r} - no opcode '
                    f'produces this today, and it is not covered by address-taken lowering')

        return address_taken

    def _collect_address_taken_in(self, node: MediumLevelILInstruction, address_taken: Set[MLILVariable]):
        '''Recursively find every AddressOf(var) in an instruction/expression tree'''
        if node is None:
            return

        if isinstance(node, MLILAddressOf):
            if isinstance(node.operand, MLILVar):
                address_taken.add(node.operand.var)
            return

        if isinstance(node, MLILBinaryOp):
            self._collect_address_taken_in(node.lhs, address_taken)
            self._collect_address_taken_in(node.rhs, address_taken)

        elif isinstance(node, MLILUnaryOp):
            self._collect_address_taken_in(node.operand, address_taken)

        elif isinstance(node, MediumLevelILCall):
            for arg in node.args:
                self._collect_address_taken_in(arg, address_taken)

        elif isinstance(node, MLILSetVar):
            self._collect_address_taken_in(node.value, address_taken)

        elif isinstance(node, (MLILStoreReg, MLILStoreGlobal)):
            self._collect_address_taken_in(node.value, address_taken)

        elif isinstance(node, MLILStoreDeref):
            self._collect_address_taken_in(node.dest, address_taken)
            self._collect_address_taken_in(node.value, address_taken)

        elif isinstance(node, MLILIf):
            self._collect_address_taken_in(node.condition, address_taken)

        elif isinstance(node, MLILRet):
            self._collect_address_taken_in(node.value, address_taken)

    def _decompose_address_taken_call_outputs(self):
        '''A call's own output is a def path independent of MLILSetVar - if it would alias an
        address-taken local, redirect it through a temp + MLILSetVar so the one general
        address-taken rewrite (_lower_address_taken_vars) handles it below, instead of leaving
        a second, unrewritten path back to the SSA-identity/storage-identity conflation this
        class's memory-form lowering exists to close.'''
        for block in self.function.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_instructions.append(inst)

                if isinstance(inst, MediumLevelILCall) and inst.output in self.address_taken_vars:
                    original_output = inst.output
                    temp = self._mint_local(f'{original_output.name}__result')
                    inst.output = temp

                    set_var = MLILSetVar(original_output, MLILVar(temp), address = inst.address).copy_metadata_from(inst)
                    new_instructions.append(set_var)

            block.instructions = new_instructions

    def _mint_local(self, candidate: str) -> MLILVariable:
        '''A fresh local guaranteed not to collide with any existing local/parameter/global
        name, and actually registered on the function - not just proven collision-free.'''
        names_in_use = _names_in_use(self.function)

        name = candidate
        suffix = 0
        while name in names_in_use:
            name = f'{candidate}_{suffix}'
            suffix += 1

        return self.function.get_or_create_local(name)

    def _lower_address_taken_vars(self):
        '''Rewrite every read/write of an address-taken local/parameter to explicit *(&x)
        memory form, so it renames to one stable address identity in
        _rename_variables_iterative instead of being versioned like an ordinary scalar value -
        see _collect_address_taken_vars's docstring for why.'''
        if not self.address_taken_vars:
            return

        for block in self.function.basic_blocks:
            block.instructions = [self._lower_inst(inst) for inst in block.instructions]

    def _lower_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Lower one instruction (mirrors _raise_inst's per-kind dispatch)'''
        if isinstance(inst, MLILSetVar):
            new_value = self._lower_expr(inst.value)

            if inst.var in self.address_taken_vars:
                dest = MLILAddressOf(MLILVar(inst.var))
                return MLILStoreDeref(dest, new_value, address = inst.address).copy_metadata_from(inst)

            if new_value is not inst.value:
                return MLILSetVar(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

            return inst

        else:
            return self._lower_stmt(inst)

    def _lower_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Recursively lower address-taken reads in an expression tree (mirrors _raise_expr's walk)'''
        if isinstance(expr, MLILAddressOf):
            # The variable whose address is being taken is the stable address identity
            # itself - leave &x as &x, never rewrite it to &*(&x)
            return expr

        elif isinstance(expr, MLILVar) and expr.var in self.address_taken_vars:
            return MLILDeref(MLILAddressOf(MLILVar(expr.var))).copy_metadata_from(expr)

        elif isinstance(expr, MLILBinaryOp):
            new_lhs = self._lower_expr(expr.lhs)
            new_rhs = self._lower_expr(expr.rhs)

            if new_lhs is expr.lhs and new_rhs is expr.rhs:
                return expr

            return self._rebuild_binary_op(expr, new_lhs, new_rhs)

        elif isinstance(expr, MLILUnaryOp):
            new_operand = self._lower_expr(expr.operand)

            if new_operand is expr.operand:
                return expr

            return self._rebuild_unary_op(expr, new_operand)

        else:
            return expr

    def _lower_stmt(self, stmt: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Lower address-taken reads inside a statement's expressions (mirrors _raise_stmt's walk)'''
        if isinstance(stmt, MLILIf):
            new_cond = self._lower_expr(stmt.condition)

            if new_cond is not stmt.condition:
                return MLILIf(new_cond, stmt.true_target, stmt.false_target, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILRet):
            if stmt.value is not None:
                new_value = self._lower_expr(stmt.value)

                if new_value is not stmt.value:
                    return MLILRet(new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MediumLevelILCall):
            new_args = [self._lower_expr(arg) for arg in stmt.args]

            if any(new_args[i] is not stmt.args[i] for i in range(len(stmt.args))):
                return stmt.rebuild(new_args)

        elif isinstance(stmt, MLILStoreReg):
            new_value = self._lower_expr(stmt.value)

            if new_value is not stmt.value:
                return MLILStoreReg(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILStoreGlobal):
            new_value = self._lower_expr(stmt.value)

            if new_value is not stmt.value:
                return MLILStoreGlobal(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILStoreDeref):
            new_dest = self._lower_expr(stmt.dest)
            new_value = self._lower_expr(stmt.value)

            if new_dest is not stmt.dest or new_value is not stmt.value:
                return stmt.rebuild(new_dest, new_value)

        return stmt

    def _raise_globals(self):
        '''Raise MLILStoreGlobal/MLILLoadGlobal into MLILSetVar/MLILVar over per-index MLILVariables,
        for every global stored somewhere in this function.

        An unraised MLILLoadGlobal (a global that is only ever read in this function) is left alone -
        it falls through _rename_expr's catch-all unchanged, which is correct: a read-only global
        gains nothing from SSA versioning.
        '''
        self.raised_global_indices = {
            inst.index
            for block in self.function.basic_blocks
            for inst in block.instructions
            if isinstance(inst, MLILStoreGlobal)
        }

        if not self.raised_global_indices:
            return

        for block in self.function.basic_blocks:
            block.instructions = [self._raise_inst(inst) for inst in block.instructions]

    def _raise_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Raise one instruction (mirrors _rename_inst's per-kind dispatch, without SSA versioning)'''
        if isinstance(inst, MLILStoreGlobal):
            # Every MLILStoreGlobal's index is in raised_global_indices by construction (see _raise_globals)
            new_value = self._raise_expr(inst.value)
            global_var = self.function.get_or_create_global_var(inst.index)
            return MLILSetVar(global_var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILSetVar):
            new_value = self._raise_expr(inst.value)

            if new_value is not inst.value:
                return MLILSetVar(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

            return inst

        else:
            return self._raise_stmt(inst)

    def _raise_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Recursively raise MLILLoadGlobal in an expression tree (mirrors _rename_expr's walk)'''
        if isinstance(expr, MLILLoadGlobal) and expr.index in self.raised_global_indices:
            global_var = self.function.get_or_create_global_var(expr.index)
            return MLILVar(global_var).copy_metadata_from(expr)

        elif isinstance(expr, MLILBinaryOp):
            new_lhs = self._raise_expr(expr.lhs)
            new_rhs = self._raise_expr(expr.rhs)

            if new_lhs is expr.lhs and new_rhs is expr.rhs:
                return expr

            return self._rebuild_binary_op(expr, new_lhs, new_rhs)

        elif isinstance(expr, MLILUnaryOp):
            new_operand = self._raise_expr(expr.operand)

            if new_operand is expr.operand:
                return expr

            return self._rebuild_unary_op(expr, new_operand)

        else:
            return expr

    def _raise_stmt(self, stmt: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Raise MLILLoadGlobal inside a statement's expressions (mirrors _rename_stmt's walk)'''
        if isinstance(stmt, MLILIf):
            new_cond = self._raise_expr(stmt.condition)

            if new_cond is not stmt.condition:
                return MLILIf(new_cond, stmt.true_target, stmt.false_target, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILRet):
            if stmt.value is not None:
                new_value = self._raise_expr(stmt.value)

                if new_value is not stmt.value:
                    return MLILRet(new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MediumLevelILCall):
            new_args = [self._raise_expr(arg) for arg in stmt.args]

            if any(new_args[i] is not stmt.args[i] for i in range(len(stmt.args))):
                return stmt.rebuild(new_args)

        elif isinstance(stmt, MLILStoreReg):
            new_value = self._raise_expr(stmt.value)

            if new_value is not stmt.value:
                return MLILStoreReg(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILStoreDeref):
            new_dest = self._raise_expr(stmt.dest)
            new_value = self._raise_expr(stmt.value)

            if new_dest is not stmt.dest or new_value is not stmt.value:
                return stmt.rebuild(new_dest, new_value)

        return stmt

    def _collect_defs(self):
        '''Collect blocks where each variable is defined'''
        for block in self.function.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVar):
                    self.var_defs[inst.var].add(block)

                elif isinstance(inst, MediumLevelILCall):
                    for var in self._call_defined_vars(inst):
                        self.var_defs[var].add(block)

    def _call_defined_vars(self, inst: MediumLevelILCall) -> List[MLILVariable]:
        '''Variables a call writes: its output, plus the registers/globals it clobbers.

        A callee may change any register or global, so every one of them other than the
        variable receiving the result becomes undefined across the call. Address-taken
        locals need no entry here - they are lowered to explicit *(&x) memory form before
        this runs (see _lower_address_taken_vars), so a call passing &x has no scalar def to
        record; _decompose_address_taken_call_outputs guarantees inst.output is never one of
        them either.
        '''
        defined = []

        if inst.output is not None:
            defined.append(inst.output)

        for var in list(self.function.register_vars.values()) + list(self.function.global_vars.values()):
            if var != inst.output:
                defined.append(var)

        return defined

    def _insert_phi_nodes(self):
        '''Insert Phi nodes at dominance frontiers (worklist algorithm)'''
        for var, def_blocks in self.var_defs.items():
            worklist: Deque[MediumLevelILBasicBlock] = deque(def_blocks)
            phi_placed: Set[MediumLevelILBasicBlock] = set()

            while worklist:
                block = worklist.popleft()

                for df_block in self.dom_analysis.dom_frontier[block]:
                    if df_block in phi_placed:
                        continue

                    # Insert Phi at beginning
                    phi = MLILPhi(
                        dest = MLILVariableSSA(var, 0),  # Placeholder, updated in renaming
                        sources = []
                    )
                    df_block.instructions.insert(0, phi)
                    phi_placed.add(df_block)

                    # If df_block wasn't in def_blocks, add to worklist
                    if df_block not in def_blocks:
                        worklist.append(df_block)

    def _rename_variables_iterative(self):
        '''Rename variables to SSA form (iterative DFS)'''
        if not self.function.basic_blocks:
            return

        # Initialize all function variables (especially parameters) to version 0.
        # Parameters and globals are "defined" at function entry.
        #
        # var_versions[var] is seeded to 1, not 0: it is the NEXT version _new_version() will
        # allocate, and 0 is already taken by this entry seed (pushed below via var_stack). Seeding
        # it to 0 would make the first real definition (e.g. a Phi) ALSO get version 0, colliding
        # with the entry seed's identity - two unrelated definitions sharing one MLILVariableSSA,
        # so SSA-based passes (e.g. SCCP) can propagate the later definition's value backward into
        # reads of the entry seed. var_stack[var] is unaffected: 0 remains the correct version for a
        # read before any real definition.
        for var in self.function.parameters:
            if var is not None:
                self.var_versions[var] = 1
                self.var_stack[var].append(0)

        for var in self.function.locals.values():
            self.var_versions[var] = 1
            self.var_stack[var].append(0)

        # Globals live outside function.locals (see get_or_create_global_var) so they need their own seeding
        for var in self.function.global_vars.values():
            self.var_versions[var] = 1
            self.var_stack[var].append(0)

        entry = self.function.basic_blocks[0]

        # Stack: (block, phase)
        # phase 0: process block
        # phase 1: process successors' phis
        # phase 2: recurse to children
        # phase 3: pop versions
        stack: List[Tuple[MediumLevelILBasicBlock, int, List[MLILVariable]]] = [(entry, 0, [])]
        visited: Set[MediumLevelILBasicBlock] = set()

        while stack:
            block, phase, pushed_vars = stack.pop()

            if phase == 0:
                # Process block instructions
                if block in visited:
                    continue

                visited.add(block)
                pushed = []

                new_insts = []
                for inst in block.instructions:
                    result = self._rename_inst(inst, pushed)
                    if isinstance(result, list):
                        new_insts.extend(result)
                    else:
                        new_insts.append(result)

                block.instructions = new_insts

                # Schedule remaining phases
                stack.append((block, 3, pushed))  # Phase 3: pop versions
                stack.append((block, 2, []))       # Phase 2: recurse children
                stack.append((block, 1, []))       # Phase 1: update successor phis

            elif phase == 1:
                # Update Phi nodes in successors
                for succ in block.outgoing_edges:
                    for inst in succ.instructions:
                        if isinstance(inst, MLILPhi):
                            var = inst.dest.base_var

                            if var in self.var_stack and self.var_stack[var]:
                                current_ver = self.var_stack[var][-1]
                                ssa_var = MLILVariableSSA(var, current_ver)
                                inst.sources.append((ssa_var, block))

            elif phase == 2:
                # Recurse to dominated children
                for child in self.dom_analysis.dom_tree[block]:
                    stack.append((child, 0, []))

            elif phase == 3:
                # Pop versions
                for var in pushed_vars:
                    if self.var_stack[var]:
                        self.var_stack[var].pop()

    def _rename_inst(self, inst: MediumLevelILInstruction, pushed: List[MLILVariable]) -> MediumLevelILInstruction:
        '''Rename variables in single instruction'''
        if isinstance(inst, MLILPhi):
            # Allocate new version for Phi dest
            new_ver = self._new_version(inst.dest.base_var)
            pushed.append(inst.dest.base_var)
            inst.dest = MLILVariableSSA(inst.dest.base_var, new_ver)
            return inst

        elif isinstance(inst, MLILSetVar):
            # Rename uses in RHS
            new_value = self._rename_expr(inst.value)

            # Allocate new version for LHS
            new_ver = self._new_version(inst.var)
            pushed.append(inst.var)

            return MLILSetVarSSA(MLILVariableSSA(inst.var, new_ver), new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MediumLevelILCall):
            # Rename the call (uses current SSA versions)
            renamed = self._rename_stmt(inst)

            # The call result defines a new version of the output variable
            output_var = renamed.output
            if output_var is not None:
                new_ver = self._new_version(output_var)
                pushed.append(output_var)
                renamed.output = MLILVariableSSA(output_var, new_ver)

            # Registers and globals the call clobbers get pseudo-definitions so later reads
            # do not see the older value. Address-taken locals need no such treatment here -
            # they are lowered to explicit *(&x) memory form before renaming (see
            # _lower_address_taken_vars), so a call passing &x has no scalar def to create,
            # and _decompose_address_taken_call_outputs guarantees output_var is never one
            clobbered_vars = list(self.function.register_vars.values()) + list(self.function.global_vars.values())
            clobbered = [var for var in clobbered_vars if var != output_var]

            if not clobbered:
                return renamed

            result = [renamed]
            for var in clobbered:
                new_ver = self._new_version(var)
                pushed.append(var)

                # Pseudo-definition: var#new = <undef> (call modified the variable)
                new_ssa_var = MLILVariableSSA(var, new_ver)
                pseudo_def = MLILSetVarSSA(new_ssa_var, MLILUndef(), address = inst.address).copy_metadata_from(inst)
                result.append(pseudo_def)

            return result

        else:
            # Other statements: rename expressions
            return self._rename_stmt(inst)

    def _rename_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Recursively rename variables in expression'''
        if isinstance(expr, MLILVar):
            # Replace with SSA version
            var = expr.var

            if var not in self.var_stack or not self.var_stack[var]:
                raise ValueError(f'Use of undefined variable: {var.name}')

            current_ver = self.var_stack[var][-1]
            return MLILVarSSA(MLILVariableSSA(var, current_ver))

        elif isinstance(expr, MLILVarSSA):
            # Already SSA, keep it
            return expr

        elif isinstance(expr, MLILConst):
            return expr

        elif isinstance(expr, MLILBinaryOp):
            new_lhs = self._rename_expr(expr.lhs)
            new_rhs = self._rename_expr(expr.rhs)

            if new_lhs is expr.lhs and new_rhs is expr.rhs:
                return expr

            # Explicit reconstruction (no type() hack)
            return self._rebuild_binary_op(expr, new_lhs, new_rhs)

        elif isinstance(expr, MLILUnaryOp):
            new_operand = self._rename_expr(expr.operand)

            if new_operand is expr.operand:
                return expr

            return self._rebuild_unary_op(expr, new_operand)

        else:
            # Other expressions (LoadGlobal, LoadReg, etc.)
            return expr

    def _rename_stmt(self, stmt: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Rename variables in statement'''
        if isinstance(stmt, MLILIf):
            new_cond = self._rename_expr(stmt.condition)

            if new_cond is not stmt.condition:
                return MLILIf(new_cond, stmt.true_target, stmt.false_target, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILRet):
            if stmt.value is not None:
                new_value = self._rename_expr(stmt.value)

                if new_value is not stmt.value:
                    return MLILRet(new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MediumLevelILCall):
            new_args = [self._rename_expr(arg) for arg in stmt.args]

            if any(new_args[i] is not stmt.args[i] for i in range(len(stmt.args))):
                return stmt.rebuild(new_args)

        elif isinstance(stmt, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._rename_expr(stmt.value)

            if new_value is not stmt.value:
                if isinstance(stmt, MLILStoreGlobal):
                    return MLILStoreGlobal(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

                else:
                    return MLILStoreReg(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILStoreDeref):
            new_dest = self._rename_expr(stmt.dest)
            new_value = self._rename_expr(stmt.value)

            if new_dest is not stmt.dest or new_value is not stmt.value:
                return stmt.rebuild(new_dest, new_value)

        return stmt

    def _rebuild_binary_op(self, expr: MLILBinaryOp, lhs, rhs) -> MediumLevelILInstruction:
        '''Rebuild binary operation (explicit, not type())'''
        if isinstance(expr, MLILAdd):
            rebuilt = MLILAdd(lhs, rhs)

        elif isinstance(expr, MLILSub):
            rebuilt = MLILSub(lhs, rhs)

        elif isinstance(expr, MLILMul):
            rebuilt = MLILMul(lhs, rhs)

        elif isinstance(expr, MLILDiv):
            rebuilt = MLILDiv(lhs, rhs)

        elif isinstance(expr, MLILMod):
            rebuilt = MLILMod(lhs, rhs)

        elif isinstance(expr, MLILAnd):
            rebuilt = MLILAnd(lhs, rhs)

        elif isinstance(expr, MLILOr):
            rebuilt = MLILOr(lhs, rhs)

        elif isinstance(expr, MLILXor):
            rebuilt = MLILXor(lhs, rhs)

        elif isinstance(expr, MLILShl):
            rebuilt = MLILShl(lhs, rhs)

        elif isinstance(expr, MLILShr):
            rebuilt = MLILShr(lhs, rhs)

        elif isinstance(expr, MLILLogicalAnd):
            rebuilt = MLILLogicalAnd(lhs, rhs)

        elif isinstance(expr, MLILLogicalOr):
            rebuilt = MLILLogicalOr(lhs, rhs)

        elif isinstance(expr, MLILEq):
            rebuilt = MLILEq(lhs, rhs)

        elif isinstance(expr, MLILNe):
            rebuilt = MLILNe(lhs, rhs)

        elif isinstance(expr, MLILLt):
            rebuilt = MLILLt(lhs, rhs)

        elif isinstance(expr, MLILLe):
            rebuilt = MLILLe(lhs, rhs)

        elif isinstance(expr, MLILGt):
            rebuilt = MLILGt(lhs, rhs)

        elif isinstance(expr, MLILGe):
            rebuilt = MLILGe(lhs, rhs)

        else:
            raise NotImplementedError(f'Unknown binary op: {type(expr).__name__}')

        return rebuilt.copy_metadata_from(expr)

    def _rebuild_unary_op(self, expr: MLILUnaryOp, operand) -> MediumLevelILInstruction:
        '''Rebuild unary operation (explicit, not type())'''
        if isinstance(expr, MLILNeg):
            rebuilt = MLILNeg(operand)

        elif isinstance(expr, MLILLogicalNot):
            rebuilt = MLILLogicalNot(operand)

        elif isinstance(expr, MLILBitwiseNot):
            rebuilt = MLILBitwiseNot(operand)

        elif isinstance(expr, MLILTestZero):
            rebuilt = MLILTestZero(operand)

        elif isinstance(expr, MLILAddressOf):
            rebuilt = MLILAddressOf(operand)

        elif isinstance(expr, MLILDeref):
            rebuilt = MLILDeref(operand)

        else:
            raise NotImplementedError(f'Unknown unary op: {type(expr).__name__}')

        return rebuilt.copy_metadata_from(expr)

    def _new_version(self, var: MLILVariable) -> int:
        '''Allocate new SSA version for variable'''
        if var not in self.var_versions:
            self.var_versions[var] = 0

        version = self.var_versions[var]
        self.var_versions[var] += 1
        self.var_stack[var].append(version)
        return version


# ============================================================================
# SSA Deconstruction
# ============================================================================

class SSADeconstructor:
    '''Convert SSA back to non-SSA form with interference-based variable allocation'''

    def __init__(self, function: MediumLevelILFunction):
        self.function = function
        self.all_ssa_vars: Set[MLILVariableSSA] = set()
        self.var_defs: Dict[MLILVariableSSA, Tuple[MediumLevelILBasicBlock, int]] = {}
        self.var_uses: Dict[MLILVariableSSA, List[Tuple[MediumLevelILBasicBlock, int]]] = defaultdict(list)
        self.live_in: Dict[MediumLevelILBasicBlock, Set[MLILVariableSSA]] = {}
        self.live_out: Dict[MediumLevelILBasicBlock, Set[MLILVariableSSA]] = {}
        self.interference: Dict[MLILVariableSSA, Set[MLILVariableSSA]] = defaultdict(set)
        self.var_mapping: Dict[MLILVariableSSA, MLILVariable] = {}
        self.reg_index_by_var: Dict[MLILVariable, int] = {}
        self.undefined_reg_versions: Set[MLILVariableSSA] = set()

        # Defs whose value is a call-clobber MLILUndef placeholder (never emitted - see
        # _apply_mapping_to_inst) - excluded from _allocate_variables so they never consume a class
        self.undef_defs: Set[MLILVariableSSA] = set()

        # dest <-> src edges from copy-shaped defs (MLILSetVarSSA(dest, MLILVarSSA(src))) - always
        # same-base-variable for phi-elimination copies, since phi sources are versions of the phi's
        # own variable. One dest can have several source partners (one copy per predecessor edge),
        # so this is many-to-many, not a single preferred partner.
        self.copy_affinity: Dict[MLILVariableSSA, Set[MLILVariableSSA]] = defaultdict(set)

        # Blocks added to carry a phi copy on a critical edge, dropped again if
        # the copy coalesces away
        self.split_blocks: List[MediumLevelILBasicBlock] = []

    def deconstruct(self) -> MediumLevelILFunction:
        '''Convert from SSA to non-SSA (modifies in-place)'''
        # Step 1: Eliminate Phi nodes (insert copies in predecessors)
        self._eliminate_phi_nodes()

        # Step 2: Collect all SSA variables and their def/use sites
        self._collect_ssa_vars()
        self._collect_undefined_register_versions()

        # Step 3: Compute liveness (which variables are live at each point)
        self._compute_liveness()

        # Step 4: Build interference graph (variables that can't share a name)
        self._build_interference_graph()

        # Step 5: Allocate final variable names (coalescing)
        self._allocate_variables()

        # Step 6: Replace SSA variables with allocated variables
        self._apply_mapping()

        # Step 7: Drop the split blocks whose copy coalesced away
        self._remove_redundant_splits()

        return self.function

    def _collect_ssa_vars(self):
        '''Collect all SSA variables and their definition/use sites'''
        for block in self.function.basic_blocks:
            for inst_idx, inst in enumerate(block.instructions):
                if isinstance(inst, MLILSetVarSSA):
                    self.all_ssa_vars.add(inst.var)
                    self.var_defs[inst.var] = (block, inst_idx)

                    if isinstance(inst.value, MLILUndef):
                        self.undef_defs.add(inst.var)

                    elif isinstance(inst.value, MLILVarSSA):
                        self.copy_affinity[inst.var].add(inst.value.var)
                        self.copy_affinity[inst.value.var].add(inst.var)

                    self._collect_uses_in_expr(inst.value, block, inst_idx)

                else:
                    if isinstance(inst, MediumLevelILCall) and inst.output is not None:
                        self.all_ssa_vars.add(inst.output)
                        self.var_defs[inst.output] = (block, inst_idx)

                    self._collect_uses_in_stmt(inst, block, inst_idx)

    def _collect_undefined_register_versions(self):
        '''Register versions that hold no value known inside this function

        A register read whose value comes from the caller, or from a callee that
        clobbered it, degrades to the literal REGS[n] form rather than becoming a
        local variable that is used before it is assigned.
        '''
        self.reg_index_by_var = {var: index for index, var in self.function.register_vars.items()}

        if not self.reg_index_by_var:
            return

        defined: Set[MLILVariableSSA] = set()

        for block in self.function.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    if not isinstance(inst.value, MLILUndef):
                        defined.add(inst.var)

                elif isinstance(inst, MediumLevelILCall) and inst.output is not None:
                    defined.add(inst.output)

        for ssa_var in self.all_ssa_vars:
            if ssa_var.base_var in self.reg_index_by_var and ssa_var not in defined:
                self.undefined_reg_versions.add(ssa_var)

    def _collect_uses_in_expr(self, expr, block: MediumLevelILBasicBlock, inst_idx: int):
        '''Recursively collect variable uses in an expression'''
        if isinstance(expr, MLILVarSSA):
            self.all_ssa_vars.add(expr.var)
            self.var_uses[expr.var].append((block, inst_idx))

        elif isinstance(expr, MLILBinaryOp):
            self._collect_uses_in_expr(expr.lhs, block, inst_idx)
            self._collect_uses_in_expr(expr.rhs, block, inst_idx)

        elif isinstance(expr, MLILAddressOf):
            # AddressOf uses the variable (its address is passed to function)
            self._collect_uses_in_expr(expr.operand, block, inst_idx)

        elif isinstance(expr, MLILUnaryOp):
            self._collect_uses_in_expr(expr.operand, block, inst_idx)

    def _collect_uses_in_stmt(self, stmt, block: MediumLevelILBasicBlock, inst_idx: int):
        '''Collect variable uses in a statement'''
        if isinstance(stmt, MLILIf):
            self._collect_uses_in_expr(stmt.condition, block, inst_idx)

        elif isinstance(stmt, MLILRet):
            if stmt.value:
                self._collect_uses_in_expr(stmt.value, block, inst_idx)

        elif isinstance(stmt, (MLILCall, MLILSyscall, MLILCallScript)):
            for arg in stmt.args:
                self._collect_uses_in_expr(arg, block, inst_idx)

        elif isinstance(stmt, (MLILStoreGlobal, MLILStoreReg)):
            self._collect_uses_in_expr(stmt.value, block, inst_idx)

        elif isinstance(stmt, MLILStoreDeref):
            self._collect_uses_in_expr(stmt.dest, block, inst_idx)
            self._collect_uses_in_expr(stmt.value, block, inst_idx)

    def _compute_liveness(self):
        '''Compute live-in and live-out sets for each block using dataflow analysis'''
        # Initialize
        for block in self.function.basic_blocks:
            self.live_in[block] = set()
            self.live_out[block] = set()

        # Iterate until fixed point
        changed = True
        while changed:
            changed = False
            # Process blocks in reverse order
            for block in reversed(self.function.basic_blocks):
                # live_out = union of live_in of all successors
                new_live_out = set()
                for succ in block.outgoing_edges:
                    # Skip successors that were removed by optimization
                    if succ in self.live_in:
                        new_live_out |= self.live_in[succ]

                # live_in = use + (live_out - def)
                use_set = set()
                def_set = set()
                for inst in block.instructions:
                    if isinstance(inst, MLILSetVarSSA):
                        def_set.add(inst.var)
                        for var in self._get_vars_in_expr(inst.value):
                            if var not in def_set:
                                use_set.add(var)

                    else:
                        for var in self._get_vars_in_stmt(inst):
                            if var not in def_set:
                                use_set.add(var)

                        # Arguments are read before the result is written
                        if isinstance(inst, MediumLevelILCall) and inst.output is not None:
                            def_set.add(inst.output)

                new_live_in = use_set | (new_live_out - def_set)

                if new_live_in != self.live_in[block] or new_live_out != self.live_out[block]:
                    changed = True
                    self.live_in[block] = new_live_in
                    self.live_out[block] = new_live_out

    def _get_vars_in_expr(self, expr) -> Set[MLILVariableSSA]:
        '''Get all SSA variables used in an expression'''
        result = set()
        if isinstance(expr, MLILVarSSA):
            result.add(expr.var)

        elif isinstance(expr, MLILBinaryOp):
            result |= self._get_vars_in_expr(expr.lhs)
            result |= self._get_vars_in_expr(expr.rhs)

        elif isinstance(expr, (MLILAddressOf, MLILUnaryOp)):
            result |= self._get_vars_in_expr(expr.operand)

        return result

    def _get_vars_in_stmt(self, stmt) -> Set[MLILVariableSSA]:
        '''Get all SSA variables used in a statement'''
        result = set()
        if isinstance(stmt, MLILIf):
            result |= self._get_vars_in_expr(stmt.condition)

        elif isinstance(stmt, MLILRet):
            if stmt.value:
                result |= self._get_vars_in_expr(stmt.value)

        elif isinstance(stmt, (MLILCall, MLILSyscall, MLILCallScript)):
            for arg in stmt.args:
                result |= self._get_vars_in_expr(arg)

        elif isinstance(stmt, (MLILStoreGlobal, MLILStoreReg)):
            result |= self._get_vars_in_expr(stmt.value)

        elif isinstance(stmt, MLILStoreDeref):
            result |= self._get_vars_in_expr(stmt.dest)
            result |= self._get_vars_in_expr(stmt.value)

        return result

    def _build_interference_graph(self):
        '''Build interference graph: two variables interfere if live at same point'''
        for block in self.function.basic_blocks:
            live = set(self.live_out[block])

            # Walk instructions backwards
            for inst in reversed(block.instructions):
                if isinstance(inst, MLILSetVarSSA):
                    defined_var = inst.var
                    # All currently live variables interfere with defined_var
                    self._add_interference(defined_var, live)
                    live.discard(defined_var)
                    live |= self._get_vars_in_expr(inst.value)

                elif isinstance(inst, MediumLevelILCall) and inst.output is not None:
                    self._add_interference(inst.output, live)
                    live.discard(inst.output)
                    live |= self._get_vars_in_stmt(inst)

                else:
                    live |= self._get_vars_in_stmt(inst)

    def _add_interference(self, defined_var: MLILVariableSSA, live: Set[MLILVariableSSA]):
        '''Record interference between a defined variable and everything live at that point'''
        for live_var in live:
            if live_var != defined_var:
                self.interference[defined_var].add(live_var)
                self.interference[live_var].add(defined_var)

    def _allocate_variables(self):
        '''Allocate final variable names using graph coloring / coalescing

        Defined-but-unused versions are allocated here too, not just live ones - excluding them
        would leave _apply_mapping_to_inst falling back to the raw, interference-unaware base
        variable for their def, which can silently clobber whatever coalesced version is live under
        that name at that point. Only undef_defs (call-clobber MLILUndef placeholders, which
        _apply_mapping_to_inst drops unconditionally regardless of allocation) are excluded. Globals
        are excluded entirely - they always lower back to GLOBALS[n] by index
        (_apply_mapping_to_inst/_expr), so coalescing them would only mint unused global0_v0-style
        names into function.locals.
        '''
        # Not just live vars - a defined-but-unused version still needs an interference-checked
        # name here (see docstring above), so this only drops undef placeholders and globals.
        allocatable_vars = {
            v for v in self.all_ssa_vars
            if v not in self.undef_defs and not self.function.is_global_var(v.base_var)
        }

        # Group SSA vars by base variable
        base_groups: Dict[str, List[MLILVariableSSA]] = defaultdict(list)
        for ssa_var in allocatable_vars:
            base_groups[ssa_var.base_var.name].append(ssa_var)

        # For each base variable group, try to coalesce
        for base_name, ssa_vars in base_groups.items():
            # Sort by version for deterministic output (version 0 gets base name priority)
            ssa_vars.sort(key = lambda v: v.version)
            base_var = ssa_vars[0].base_var

            # classes[0] is the base-name class; classes[i >= 1] get a minted "{base_name}_vN"
            # suffix. Each version joins the first existing class it doesn't interfere with,
            # preferring one already holding a direct copy_affinity partner so the self-assignment
            # skip in _apply_mapping_to_inst can elide that copy. A new class is minted only when
            # nothing fits - previously, the allocator only ever tried the base-name class, so every
            # conflicting version minted its own fresh suffix instead of reusing an earlier one.
            classes: List[List[MLILVariableSSA]] = [[]]

            for ssa_var in ssa_vars:
                interferes_with = self.interference.get(ssa_var, set())
                partners = self.copy_affinity.get(ssa_var, set())

                fitting = [i for i, members in enumerate(classes)
                          if not any(m in interferes_with for m in members)]

                chosen = next((i for i in fitting if any(m in partners for m in classes[i])), None)

                if chosen is None and fitting:
                    chosen = fitting[0]

                if chosen is None:
                    classes.append([])
                    chosen = len(classes) - 1

                classes[chosen].append(ssa_var)

            # Mint each suffix class a real, collision-free name. MLILVariable equality is
            # name-only, so a minted name must never collide with a real local, parameter, or
            # global. The counter only ever advances (never resets or aligns to class
            # position), so a name skipped for colliding is never handed to a different class
            # later.
            names_in_use = _names_in_use(self.function)
            suffix_counter = 0

            for class_index, members in enumerate(classes):
                if class_index == 0:
                    class_var = base_var

                else:
                    while True:
                        candidate = f'{base_name}_v{suffix_counter}'
                        suffix_counter += 1
                        if candidate not in names_in_use:
                            break

                    class_var = MLILVariable(candidate, base_var.slot_index)
                    self.function.locals[candidate] = class_var
                    names_in_use.add(candidate)

                for ssa_var in members:
                    self.var_mapping[ssa_var] = class_var

    def _apply_mapping(self):
        '''Replace SSA variables with allocated variables'''
        for block in self.function.basic_blocks:
            new_insts = []
            for inst in block.instructions:
                new_inst = self._apply_mapping_to_inst(inst)
                if new_inst is not None:
                    new_insts.append(new_inst)
            block.instructions = new_insts

    def _apply_mapping_to_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Apply variable mapping to instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_var = self.var_mapping.get(inst.var, inst.var.base_var)
            new_value = self._apply_mapping_to_expr(inst.value)
            global_index = self.function.global_index_of(new_var)

            # Skip self-assignment (var = var) from coalesced phi copies
            if isinstance(new_value, MLILVar) and new_value.var == new_var:
                return None

            # Same hazard for a global: a phi copy between two versions of the same global
            # lowers its value side to MLILLoadGlobal (not MLILVar), so the check above never
            # matches it - without this, coalesced phi copies show up as GLOBALS[n] = GLOBALS[n]
            if global_index is not None and isinstance(new_value, MLILLoadGlobal) and new_value.index == global_index:
                return None

            # Skip undef assignments (pseudo-definitions for call output parameters)
            if isinstance(inst.value, MLILUndef):
                return None

            # A global write lowers back to a GLOBALS[n] store - never a plain variable assignment
            if global_index is not None:
                return MLILStoreGlobal(global_index, new_value, address = inst.address).copy_metadata_from(inst)

            return MLILSetVar(new_var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILPhi):
            raise RuntimeError('Phi node not eliminated')

        else:
            return self._apply_mapping_to_stmt(inst)

    def _apply_mapping_to_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Apply variable mapping to expression'''
        if isinstance(expr, MLILVarSSA):
            if expr.var in self.undefined_reg_versions:
                return MLILLoadReg(self.reg_index_by_var[expr.var.base_var])

            new_var = self.var_mapping.get(expr.var, expr.var.base_var)

            # Every surviving global read lowers back to GLOBALS[n], defined-in-function or not -
            # globals are excluded from coalescing (_allocate_variables), so this is unconditional
            global_index = self.function.global_index_of(new_var)
            if global_index is not None:
                return MLILLoadGlobal(global_index).copy_metadata_from(expr)

            return MLILVar(new_var)

        elif isinstance(expr, MLILBinaryOp):
            new_lhs = self._apply_mapping_to_expr(expr.lhs)
            new_rhs = self._apply_mapping_to_expr(expr.rhs)
            if new_lhs is expr.lhs and new_rhs is expr.rhs:
                return expr
            constructor = SSAConstructor(self.function)
            return constructor._rebuild_binary_op(expr, new_lhs, new_rhs)

        elif isinstance(expr, MLILUnaryOp):
            new_operand = self._apply_mapping_to_expr(expr.operand)
            if new_operand is expr.operand:
                return expr
            constructor = SSAConstructor(self.function)
            return constructor._rebuild_unary_op(expr, new_operand)

        else:
            return expr

    def _apply_mapping_to_stmt(self, stmt: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Apply variable mapping to statement'''
        if isinstance(stmt, MLILIf):
            new_cond = self._apply_mapping_to_expr(stmt.condition)
            if new_cond is not stmt.condition:
                return MLILIf(new_cond, stmt.true_target, stmt.false_target, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILRet):
            if stmt.value:
                new_value = self._apply_mapping_to_expr(stmt.value)
                if new_value is not stmt.value:
                    return MLILRet(new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MediumLevelILCall):
            if stmt.output is not None:
                stmt.output = self.var_mapping.get(stmt.output, stmt.output.base_var)

            new_args = [self._apply_mapping_to_expr(arg) for arg in stmt.args]
            if any(new_args[i] is not stmt.args[i] for i in range(len(stmt.args))):
                return stmt.rebuild(new_args)

        elif isinstance(stmt, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._apply_mapping_to_expr(stmt.value)
            if new_value is not stmt.value:
                if isinstance(stmt, MLILStoreGlobal):
                    return MLILStoreGlobal(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

                else:
                    return MLILStoreReg(stmt.index, new_value, address = stmt.address).copy_metadata_from(stmt)

        elif isinstance(stmt, MLILStoreDeref):
            new_dest = self._apply_mapping_to_expr(stmt.dest)
            new_value = self._apply_mapping_to_expr(stmt.value)
            if new_dest is not stmt.dest or new_value is not stmt.value:
                return stmt.rebuild(new_dest, new_value)

        return stmt

    def _retarget_branch(self, block: MediumLevelILBasicBlock,
                         old_target: MediumLevelILBasicBlock,
                         new_target: MediumLevelILBasicBlock):
        '''Point block's terminal at new_target wherever it named old_target'''
        if not block.instructions:
            return

        terminal = block.instructions[-1]

        if isinstance(terminal, MLILIf):
            if terminal.true_target is old_target:
                terminal.true_target = new_target

            if terminal.false_target is old_target:
                terminal.false_target = new_target

        elif isinstance(terminal, MLILGoto):
            if terminal.target is old_target:
                terminal.target = new_target

    def _split_critical_edge(self, pred_block: MediumLevelILBasicBlock,
                             succ_block: MediumLevelILBasicBlock) -> MediumLevelILBasicBlock:
        '''Insert a block of its own along the pred -> succ edge'''
        split = MediumLevelILBasicBlock(pred_block.index, succ_block.start,
                                        f'{pred_block.label}_to_{succ_block.label}')
        split.instructions.append(MLILGoto(succ_block, address = succ_block.start))

        self._retarget_branch(pred_block, succ_block, split)

        pred_block.outgoing_edges = [split if b is succ_block else b
                                     for b in pred_block.outgoing_edges]
        succ_block.incoming_edges = [b for b in succ_block.incoming_edges
                                     if b is not pred_block]
        succ_block.incoming_edges.append(split)

        split.incoming_edges.append(pred_block)
        split.outgoing_edges.append(succ_block)

        # Keep it next to the block it came from so the dump stays readable
        position = self.function.basic_blocks.index(pred_block) + 1
        self.function.basic_blocks.insert(position, split)
        self.split_blocks.append(split)

        return split

    def _phi_copy_block(self, pred_block: MediumLevelILBasicBlock,
                        succ_block: MediumLevelILBasicBlock,
                        split_cache: Dict) -> MediumLevelILBasicBlock:
        '''Block a phi copy for the pred -> succ edge belongs in

        Putting it in pred_block is only correct when that edge is the only way
        out. On a critical edge - pred branches several ways and succ is joined
        from several places - the copy would sit alongside the other successor's
        own reads, and per-block liveness reports it as interfering with them
        even though the two never run together. That is the classic lost-copy
        problem, and it surfaces as a shadow variable in the output. Giving the
        copy a block of its own narrows its live-out to that one edge.
        '''
        if len(pred_block.outgoing_edges) <= 1 or len(succ_block.incoming_edges) <= 1:
            return pred_block

        cached = split_cache.get((pred_block, succ_block))

        if cached is not None:
            return cached

        split = self._split_critical_edge(pred_block, succ_block)
        split_cache[(pred_block, succ_block)] = split

        return split

    def _remove_redundant_splits(self):
        '''Drop split blocks whose copy coalesced away, leaving only the jump'''
        removed = False

        for split in self.split_blocks:
            if len(split.instructions) != 1 or not isinstance(split.instructions[0], MLILGoto):
                continue

            if len(split.incoming_edges) != 1 or len(split.outgoing_edges) != 1:
                continue

            pred_block = split.incoming_edges[0]
            succ_block = split.outgoing_edges[0]

            self._retarget_branch(pred_block, split, succ_block)

            pred_block.outgoing_edges = [succ_block if b is split else b
                                         for b in pred_block.outgoing_edges]
            succ_block.incoming_edges = [b for b in succ_block.incoming_edges
                                         if b is not split]

            if pred_block not in succ_block.incoming_edges:
                succ_block.incoming_edges.append(pred_block)

            self.function.basic_blocks.remove(split)
            removed = True

        self.split_blocks = []

        if removed:
            self.function.renumber_blocks()

    def _eliminate_phi_nodes(self):
        '''Replace Phi nodes with SSA copies in predecessor blocks'''
        # Build set of parameter variables for quick lookup
        param_vars = set(self.function.parameters)

        # Build SSA variable → defining instruction address map
        def_addr = {}
        for block in self.function.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    def_addr[inst.var] = inst.address

        split_cache: Dict[Tuple[MediumLevelILBasicBlock, MediumLevelILBasicBlock],
                          MediumLevelILBasicBlock] = {}

        for block in list(self.function.basic_blocks):
            phi_nodes = [inst for inst in block.instructions if isinstance(inst, MLILPhi)]

            if not phi_nodes:
                continue

            # Remove Phi nodes from this block
            block.instructions = [inst for inst in block.instructions if not isinstance(inst, MLILPhi)]

            # Insert SSA copies in predecessors
            for phi in phi_nodes:
                for ssa_var, pred_block in phi.sources:
                    # Skip if source and dest are the exact same SSA variable
                    if phi.dest == ssa_var:
                        continue

                    # Skip version 0 for local variables (undefined initial value)
                    # Version 0 is only valid for parameters (input values)
                    if ssa_var.version == 0 and ssa_var.base_var not in param_vars:
                        continue

                    # Insert SSA copy: phi.dest = ssa_var
                    # This preserves SSA info for liveness analysis
                    copy = MLILSetVarSSA(phi.dest, MLILVarSSA(ssa_var),
                                         address = def_addr.get(ssa_var, 0))

                    copy_block = self._phi_copy_block(pred_block, block, split_cache)

                    # Insert before terminal instruction
                    if copy_block.instructions and copy_block.has_terminal:
                        copy_block.instructions.insert(-1, copy)

                    else:
                        copy_block.instructions.append(copy)

        if split_cache:
            self.function.renumber_blocks()

# ============================================================================
# Public API
# ============================================================================

def convert_to_ssa(function: MediumLevelILFunction) -> MediumLevelILFunction:
    '''Convert MLIL to SSA (in-place)'''
    constructor = SSAConstructor(function)
    return constructor.construct()


def convert_from_ssa(function: MediumLevelILFunction) -> MediumLevelILFunction:
    '''Convert from SSA to non-SSA (in-place)'''
    deconstructor = SSADeconstructor(function)
    return deconstructor.deconstruct()
