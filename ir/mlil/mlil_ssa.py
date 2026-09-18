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

        # Step 2: Collect variable definitions
        self._collect_defs()

        # Step 3: Insert Phi nodes
        self._insert_phi_nodes()

        # Step 4: Rename variables (iterative)
        self._rename_variables_iterative()

        return self.function

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
        '''Variables a call writes: its output plus the registers and globals it clobbers

        A callee may change any register or global, so every one of them other than the
        variable receiving the result becomes undefined across the call.
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
            # Find variables passed via AddressOf (output parameters)
            addr_vars = []
            for arg in inst.args:
                if isinstance(arg, MLILAddressOf) and isinstance(arg.operand, MLILVar):
                    addr_vars.append(arg.operand.var)

            # Rename the call (uses current SSA versions)
            renamed = self._rename_stmt(inst)

            # The call result defines a new version of the output variable
            output_var = renamed.output
            if output_var is not None:
                new_ver = self._new_version(output_var)
                pushed.append(output_var)
                renamed.output = MLILVariableSSA(output_var, new_ver)

            # Registers and globals the call clobbers, plus address-taken variables it may write,
            # get pseudo-definitions so later reads do not see the older value
            clobbered_vars = list(self.function.register_vars.values()) + list(self.function.global_vars.values())
            clobbered = [var for var in clobbered_vars if var != output_var]

            if not addr_vars and not clobbered:
                return renamed

            result = [renamed]
            for var in clobbered + addr_vars:
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

        return stmt

    def _rebuild_binary_op(self, expr: MLILBinaryOp, lhs, rhs) -> MediumLevelILInstruction:
        '''Rebuild binary operation (explicit, not type())'''
        if isinstance(expr, MLILAdd):
            return MLILAdd(lhs, rhs)

        elif isinstance(expr, MLILSub):
            return MLILSub(lhs, rhs)

        elif isinstance(expr, MLILMul):
            return MLILMul(lhs, rhs)

        elif isinstance(expr, MLILDiv):
            return MLILDiv(lhs, rhs)

        elif isinstance(expr, MLILMod):
            return MLILMod(lhs, rhs)

        elif isinstance(expr, MLILAnd):
            return MLILAnd(lhs, rhs)

        elif isinstance(expr, MLILOr):
            return MLILOr(lhs, rhs)

        elif isinstance(expr, MLILXor):
            return MLILXor(lhs, rhs)

        elif isinstance(expr, MLILShl):
            return MLILShl(lhs, rhs)

        elif isinstance(expr, MLILShr):
            return MLILShr(lhs, rhs)

        elif isinstance(expr, MLILLogicalAnd):
            return MLILLogicalAnd(lhs, rhs)

        elif isinstance(expr, MLILLogicalOr):
            return MLILLogicalOr(lhs, rhs)

        elif isinstance(expr, MLILEq):
            return MLILEq(lhs, rhs)

        elif isinstance(expr, MLILNe):
            return MLILNe(lhs, rhs)

        elif isinstance(expr, MLILLt):
            return MLILLt(lhs, rhs)

        elif isinstance(expr, MLILLe):
            return MLILLe(lhs, rhs)

        elif isinstance(expr, MLILGt):
            return MLILGt(lhs, rhs)

        elif isinstance(expr, MLILGe):
            return MLILGe(lhs, rhs)

        else:
            raise NotImplementedError(f'Unknown binary op: {type(expr).__name__}')

    def _rebuild_unary_op(self, expr: MLILUnaryOp, operand) -> MediumLevelILInstruction:
        '''Rebuild unary operation (explicit, not type())'''
        if isinstance(expr, MLILNeg):
            return MLILNeg(operand)

        elif isinstance(expr, MLILLogicalNot):
            return MLILLogicalNot(operand)

        elif isinstance(expr, MLILBitwiseNot):
            return MLILBitwiseNot(operand)

        elif isinstance(expr, MLILTestZero):
            return MLILTestZero(operand)

        elif isinstance(expr, MLILAddressOf):
            return MLILAddressOf(operand)

        else:
            raise NotImplementedError(f'Unknown unary op: {type(expr).__name__}')

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

        return self.function

    def _collect_ssa_vars(self):
        '''Collect all SSA variables and their definition/use sites'''
        for block in self.function.basic_blocks:
            for inst_idx, inst in enumerate(block.instructions):
                if isinstance(inst, MLILSetVarSSA):
                    self.all_ssa_vars.add(inst.var)
                    self.var_defs[inst.var] = (block, inst_idx)
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
        '''Allocate final variable names using graph coloring / coalescing'''
        # Filter out dead variables (defined but never used). Globals are excluded entirely - they
        # always lower back to GLOBALS[n] by index (_apply_mapping_to_inst/_expr), so coalescing
        # them would only mint unused global0_v0-style names into function.locals.
        live_vars = {
            v for v in self.all_ssa_vars
            if self.var_uses[v] and not self.function.is_global_var(v.base_var)
        }

        # Group SSA vars by base variable
        base_groups: Dict[str, List[MLILVariableSSA]] = defaultdict(list)
        for ssa_var in live_vars:
            base_groups[ssa_var.base_var.name].append(ssa_var)

        # For each base variable group, try to coalesce
        for base_name, ssa_vars in base_groups.items():
            if not ssa_vars:
                continue

            # Sort by version for deterministic output (version 0 gets base name priority)
            ssa_vars.sort(key = lambda v: v.version)
            base_var = ssa_vars[0].base_var

            # Find connected components of non-interfering variables
            # Variables in the same component can share the base name
            assigned: Dict[MLILVariableSSA, MLILVariable] = {}
            suffix_counter = 0

            for ssa_var in ssa_vars:
                if ssa_var in assigned:
                    continue

                # Check if this var interferes with any already assigned to base_var
                can_use_base = True
                for other_var, other_assigned in assigned.items():
                    if other_assigned.name == base_name and other_var in self.interference.get(ssa_var, set()):
                        can_use_base = False
                        break

                if can_use_base:
                    assigned[ssa_var] = base_var

                else:
                    # Need a new name
                    new_name = f'{base_name}_v{suffix_counter}'
                    suffix_counter += 1
                    new_var = MLILVariable(new_name, base_var.slot_index)
                    assigned[ssa_var] = new_var
                    # Add to function's locals
                    if new_name not in self.function.locals:
                        self.function.locals[new_name] = new_var

            self.var_mapping.update(assigned)

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

        return stmt

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

        for block in self.function.basic_blocks:
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

                    # Insert before terminal instruction
                    if pred_block.instructions and pred_block.has_terminal:
                        pred_block.instructions.insert(-1, copy)

                    else:
                        pred_block.instructions.append(copy)

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
