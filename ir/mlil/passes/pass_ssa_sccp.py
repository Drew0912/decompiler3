'''SCCP - Sparse Conditional Constant Propagation'''

from typing import Dict, List, Set

from ir.core import constant_values_equal
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILBasicBlock,
    MediumLevelILCall,
    MLILConst,
    MLILBinaryOp,
    MLILUnaryOp,
    MLILAdd,
    MLILSub,
    MLILMul,
    MLILDiv,
    MLILMod,
    MLILAnd,
    MLILOr,
    MLILXor,
    MLILShl,
    MLILShr,
    MLILLogicalAnd,
    MLILLogicalOr,
    MLILEq,
    MLILNe,
    MLILLt,
    MLILLe,
    MLILGt,
    MLILGe,
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILTestZero,
    MLILAddressOf,
    MLILIf,
    MLILGoto,
    MLILRet,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILStoreDeref,
)
from ..mlil_ssa import (
    iter_ssa_reads,
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILUndef,
)


class LatticeValue:
    '''Lattice value for SCCP: TOP → CONSTANT → BOTTOM'''
    TOP = 'top'        # Undefined/unknown
    BOTTOM = 'bottom'  # Multiple possible values

    def __init__(self, state: str = TOP, value: any = None):
        self.state = state
        self.value = value  # Only valid when state == 'constant'

    @classmethod
    def top(cls) -> 'LatticeValue':
        return cls(cls.TOP)

    @classmethod
    def constant(cls, value: any) -> 'LatticeValue':
        return cls('constant', value)

    @classmethod
    def bottom(cls) -> 'LatticeValue':
        return cls(cls.BOTTOM)

    def is_top(self) -> bool:
        return self.state == self.TOP

    def is_constant(self) -> bool:
        return self.state == 'constant'

    def is_bottom(self) -> bool:
        return self.state == self.BOTTOM

    def meet(self, other: 'LatticeValue') -> 'LatticeValue':
        '''Meet operation: combine two lattice values'''
        # TOP meet x = x
        if self.is_top():
            return other

        if other.is_top():
            return self

        # BOTTOM meet x = BOTTOM
        if self.is_bottom() or other.is_bottom():
            return LatticeValue.bottom()

        # CONSTANT meet CONSTANT
        if constant_values_equal(self.value, other.value):
            return self

        return LatticeValue.bottom()

    def __eq__(self, other) -> bool:
        if not isinstance(other, LatticeValue):
            return False

        if self.state != other.state:
            return False

        if self.is_constant():
            return constant_values_equal(self.value, other.value)

        return True

    def __repr__(self) -> str:
        if self.is_top():
            return '⊤'

        elif self.is_bottom():
            return '⊥'

        else:
            return f'C({self.value})'


class SCCP:
    '''Sparse Conditional Constant Propagation'''

    def __init__(self, function: MediumLevelILFunction, remove_unreachable: bool = False):
        self.function = function
        self.remove_unreachable = remove_unreachable

        # Variables replaced with constants (for DCE to skip debug.string)
        self.replaced_vars: Set[MLILVariableSSA] = set()

        # Lattice values for SSA variables
        self.var_values: Dict[MLILVariableSSA, LatticeValue] = {}

        # Edge reachability: (from_block, to_block) -> reachable
        self.edge_reachable: Dict[tuple, bool] = {}

        # Block reachability
        self.block_reachable: Dict[MediumLevelILBasicBlock, bool] = {}

        # Worklists
        self.ssa_worklist: List[MLILVariableSSA] = []
        self.cfg_worklist: List[tuple] = []  # (from_block, to_block)

        # SSA def-use chains
        self.ssa_defs: Dict[MLILVariableSSA, MediumLevelILInstruction] = {}
        self.ssa_uses: Dict[MLILVariableSSA, List[MediumLevelILInstruction]] = {}

        # Block containing each instruction
        self.inst_block: Dict[MediumLevelILInstruction, MediumLevelILBasicBlock] = {}

    def run(self) -> bool:
        '''Run SCCP and return True if any changes were made'''
        self._initialize()
        self._propagate()
        return self._apply_results()

    def _initialize(self):
        '''Initialize SCCP state'''
        # Build def-use chains and instruction-to-block mapping
        for block in self.function.basic_blocks:
            self.block_reachable[block] = False

            for inst in block.instructions:
                self.inst_block[inst] = block

                if isinstance(inst, MLILSetVarSSA):
                    self.ssa_defs[inst.var] = inst

                elif isinstance(inst, MLILPhi):
                    self.ssa_defs[inst.dest] = inst

                for var, _ in iter_ssa_reads(inst):
                    self.ssa_uses.setdefault(var, []).append(inst)

        # Initialize all variables to TOP
        for var in self.ssa_defs:
            self.var_values[var] = LatticeValue.top()

        # Initialize all edges to unreachable
        for block in self.function.basic_blocks:
            for succ in block.outgoing_edges:
                self.edge_reachable[(block, succ)] = False

        # Mark entry block as reachable
        if self.function.basic_blocks:
            entry = self.function.basic_blocks[0]
            self.block_reachable[entry] = True
            # Add entry block's instructions to worklist
            self._process_block(entry)

    def _propagate(self):
        '''Main SCCP propagation loop'''
        while self.ssa_worklist or self.cfg_worklist:
            # Process CFG edges first
            while self.cfg_worklist:
                from_block, to_block = self.cfg_worklist.pop(0)

                if self.edge_reachable.get((from_block, to_block), False):
                    continue

                self.edge_reachable[(from_block, to_block)] = True

                # Check if this is first time block becomes reachable
                was_reachable = self.block_reachable.get(to_block, False)
                self.block_reachable[to_block] = True

                if not was_reachable:
                    # First time visiting this block
                    self._process_block(to_block)

                else:
                    # Block already reachable, just update Phis
                    self._update_phis(to_block)

            # Process SSA worklist
            while self.ssa_worklist:
                var = self.ssa_worklist.pop(0)

                for user in self.ssa_uses.get(var, []):
                    user_block = self.inst_block.get(user)

                    if user_block and self.block_reachable.get(user_block, False):
                        self._visit_instruction(user)

    def _process_block(self, block: MediumLevelILBasicBlock):
        '''Process all instructions in a newly reachable block'''
        for inst in block.instructions:
            self._visit_instruction(inst)

    def _update_phis(self, block: MediumLevelILBasicBlock):
        '''Update Phi nodes when a new edge becomes reachable'''
        for inst in block.instructions:
            if isinstance(inst, MLILPhi):
                self._visit_phi(inst)

    def _visit_instruction(self, inst: MediumLevelILInstruction):
        '''Visit and evaluate an instruction'''
        if isinstance(inst, MLILSetVarSSA):
            self._visit_assignment(inst)

        elif isinstance(inst, MLILPhi):
            self._visit_phi(inst)

        elif isinstance(inst, MLILIf):
            self._visit_branch(inst)

        elif isinstance(inst, MLILGoto):
            self._visit_goto(inst)

        elif isinstance(inst, MLILRet):
            pass  # No successors

        else:
            # Other instructions: mark all successors reachable
            block = self.inst_block.get(inst)
            if block:
                for succ in block.outgoing_edges:
                    self._mark_edge_reachable(block, succ)

    def _visit_assignment(self, inst: MLILSetVarSSA):
        '''Evaluate assignment instruction'''
        new_value = self._evaluate_expr(inst.value)
        self._update_var_value(inst.var, new_value)

    def _visit_phi(self, inst: MLILPhi):
        '''Evaluate Phi node'''
        result = LatticeValue.top()
        block = self.inst_block.get(inst)

        for src_var, pred_block in inst.sources:
            # Only consider reachable edges
            if self.edge_reachable.get((pred_block, block), False):
                # If source variable has no definition, it's uninitialized (BOTTOM)
                if src_var not in self.ssa_defs:
                    src_value = LatticeValue.bottom()

                else:
                    src_value = self.var_values.get(src_var, LatticeValue.top())

                result = result.meet(src_value)

        self._update_var_value(inst.dest, result)

    def _visit_branch(self, inst: MLILIf):
        '''Evaluate conditional branch'''
        block = self.inst_block.get(inst)
        if not block:
            return

        cond_value = self._evaluate_expr(inst.condition)

        if cond_value.is_constant():
            # Condition is constant, only one branch is reachable
            if cond_value.value:
                self._mark_edge_reachable(block, inst.true_target)

            else:
                self._mark_edge_reachable(block, inst.false_target)

        else:
            # Condition unknown, both branches reachable
            self._mark_edge_reachable(block, inst.true_target)
            self._mark_edge_reachable(block, inst.false_target)

    def _visit_goto(self, inst: MLILGoto):
        '''Evaluate unconditional jump'''
        block = self.inst_block.get(inst)
        if block and inst.target:
            self._mark_edge_reachable(block, inst.target)

    def _evaluate_expr(self, expr: MediumLevelILInstruction) -> LatticeValue:
        '''Evaluate expression to lattice value'''
        if isinstance(expr, MLILConst):
            return LatticeValue.constant(expr.value)

        elif isinstance(expr, MLILUndef):
            # Undefined value - could be anything
            return LatticeValue.bottom()

        elif isinstance(expr, MLILVarSSA):
            # If variable has no definition, it's uninitialized - could be any value (BOTTOM)
            # This prevents incorrect constant propagation through Phi nodes
            if expr.var not in self.ssa_defs:
                return LatticeValue.bottom()

            return self.var_values.get(expr.var, LatticeValue.top())

        elif isinstance(expr, MLILBinaryOp):
            lhs = self._evaluate_expr(expr.lhs)
            rhs = self._evaluate_expr(expr.rhs)

            # If either is BOTTOM, result is BOTTOM
            if lhs.is_bottom() or rhs.is_bottom():
                return LatticeValue.bottom()

            # If either is TOP, result is TOP
            if lhs.is_top() or rhs.is_top():
                return LatticeValue.top()

            # Both constants, evaluate
            return self._eval_binary_op(type(expr), lhs.value, rhs.value)

        elif isinstance(expr, MLILUnaryOp):
            operand = self._evaluate_expr(expr.operand)

            if operand.is_bottom():
                return LatticeValue.bottom()

            if operand.is_top():
                return LatticeValue.top()

            return self._eval_unary_op(type(expr), operand.value)

        else:
            # Unknown expression type
            return LatticeValue.bottom()

    def _eval_binary_op(self, op_type, lhs, rhs) -> LatticeValue:
        '''Evaluate binary operation on constants'''
        try:
            if op_type == MLILAdd:
                return LatticeValue.constant(lhs + rhs)

            elif op_type == MLILSub:
                return LatticeValue.constant(lhs - rhs)

            elif op_type == MLILMul:
                return LatticeValue.constant(lhs * rhs)

            elif op_type in (MLILDiv, MLILMod):
                # Not folded: Python's // is confirmed wrong for VM float division, and the rest
                # of DIV/MOD (int width, overflow, MOD's sign) is unverified without running the
                # game - ScpValue's 30-bit-int/float32 shape is the constant encoding, not proof
                # of runtime arithmetic width. See docs/FUTURE_WORK.md. Folding wrong is worse
                # than not folding.
                return LatticeValue.bottom()

            elif op_type == MLILAnd:
                return LatticeValue.constant(lhs & rhs)

            elif op_type == MLILOr:
                return LatticeValue.constant(lhs | rhs)

            elif op_type == MLILXor:
                return LatticeValue.constant(lhs ^ rhs)

            elif op_type == MLILShl:
                return LatticeValue.constant(lhs << rhs)

            elif op_type == MLILShr:
                return LatticeValue.constant(lhs >> rhs)

            elif op_type == MLILLogicalAnd:
                return LatticeValue.constant(1 if (lhs and rhs) else 0)

            elif op_type == MLILLogicalOr:
                return LatticeValue.constant(1 if (lhs or rhs) else 0)

            elif op_type == MLILEq:
                return LatticeValue.constant(1 if lhs == rhs else 0)

            elif op_type == MLILNe:
                return LatticeValue.constant(1 if lhs != rhs else 0)

            elif op_type == MLILLt:
                return LatticeValue.constant(1 if lhs < rhs else 0)

            elif op_type == MLILLe:
                return LatticeValue.constant(1 if lhs <= rhs else 0)

            elif op_type == MLILGt:
                return LatticeValue.constant(1 if lhs > rhs else 0)

            elif op_type == MLILGe:
                return LatticeValue.constant(1 if lhs >= rhs else 0)

        except (OverflowError, TypeError):
            pass

        return LatticeValue.bottom()

    def _eval_unary_op(self, op_type, operand) -> LatticeValue:
        '''Evaluate unary operation on constant'''
        try:
            if op_type == MLILNeg:
                return LatticeValue.constant(-operand)

            elif op_type == MLILLogicalNot:
                return LatticeValue.constant(1 if not operand else 0)

            elif op_type == MLILBitwiseNot:
                return LatticeValue.constant(~operand)

            elif op_type == MLILTestZero:
                return LatticeValue.constant(1 if operand == 0 else 0)

        except (OverflowError, TypeError):
            pass

        return LatticeValue.bottom()

    def _update_var_value(self, var: MLILVariableSSA, new_value: LatticeValue):
        '''Update variable value and add to worklist if changed'''
        old_value = self.var_values.get(var, LatticeValue.top())

        if new_value != old_value:
            self.var_values[var] = new_value
            self.ssa_worklist.append(var)

    def _mark_edge_reachable(self, from_block: MediumLevelILBasicBlock,
                              to_block: MediumLevelILBasicBlock):
        '''Mark CFG edge as reachable'''
        if not self.edge_reachable.get((from_block, to_block), False):
            self.cfg_worklist.append((from_block, to_block))

    def _apply_results(self) -> bool:
        '''Apply SCCP results: remove unreachable code, replace constants'''
        changed = False

        # Optionally remove unreachable blocks
        if self.remove_unreachable:
            reachable_blocks = [b for b in self.function.basic_blocks
                               if self.block_reachable.get(b, False)]

            if len(reachable_blocks) < len(self.function.basic_blocks):
                self.function.basic_blocks = reachable_blocks
                self.function.renumber_blocks()
                changed = True

        # Replace constant variables
        for block in self.function.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = self._replace_constants_in_inst(inst)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _replace_constants_in_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Replace constant SSA variables in instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._replace_constants_in_expr(inst.value)

            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_cond = self._replace_constants_in_expr(inst.condition)

            if new_cond is not inst.condition:
                return MLILIf(new_cond, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILRet):
            if inst.value:
                new_value = self._replace_constants_in_expr(inst.value)

                if new_value is not inst.value:
                    return MLILRet(new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MediumLevelILCall):
            new_args = [self._replace_constants_in_expr(arg) for arg in inst.args]

            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                return inst.rebuild(new_args)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._replace_constants_in_expr(inst.value)

            if new_value is not inst.value:
                if isinstance(inst, MLILStoreGlobal):
                    return MLILStoreGlobal(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

                else:
                    return MLILStoreReg(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._replace_constants_in_expr(inst.dest)
            new_value = self._replace_constants_in_expr(inst.value)

            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _replace_constants_in_expr(self, expr: MediumLevelILInstruction, is_bitwise: bool = False) -> MediumLevelILInstruction:
        '''Replace constant SSA variables with constants'''
        if isinstance(expr, MLILVarSSA):
            val = self.var_values.get(expr.var, LatticeValue.bottom())

            if val.is_constant():
                self.replaced_vars.add(expr.var)
                return MLILConst(val.value, is_hex = is_bitwise)

            return expr

        elif isinstance(expr, MLILConst):
            # Update existing const to hex format if in bitwise context
            if is_bitwise and not expr.is_hex:
                return MLILConst(expr.value, is_hex = True)

            return expr

        elif isinstance(expr, MLILBinaryOp):
            # Bitwise operations use hex format for constants
            child_is_bitwise = isinstance(expr, (MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr))
            new_lhs = self._replace_constants_in_expr(expr.lhs, child_is_bitwise)
            new_rhs = self._replace_constants_in_expr(expr.rhs, child_is_bitwise)

            if new_lhs is not expr.lhs or new_rhs is not expr.rhs:
                return expr.rebuild(new_lhs, new_rhs)

        elif isinstance(expr, MLILAddressOf):
            # &x names x's storage, not its value - never substitute a constant under it
            return expr

        elif isinstance(expr, MLILUnaryOp):
            child_is_bitwise = isinstance(expr, MLILBitwiseNot)
            new_operand = self._replace_constants_in_expr(expr.operand, child_is_bitwise)

            if new_operand is not expr.operand:
                return expr.rebuild(new_operand)

        return expr
