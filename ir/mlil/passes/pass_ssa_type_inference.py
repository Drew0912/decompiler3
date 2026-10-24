"""SSA Type Inference Pass

Infer types for SSA variables using:
1. Parameter types from source_params
2. Constant types
3. Type propagation through assignments
"""

from typing import Dict, Optional

from ir.pipeline import Pass
from ..mlil import *
from ..mlil_ssa import *
from ..mlil_types import *

SSA_TYPE_PROPAGATION_MAX_ITERATIONS = 20
USAGE_INFERENCE_PASSES = 3

# Expressions whose value is always an int
INT_RESULT_OPS = (
    MLILAnd, MLILOr, MLILXor, MLILShl, MLILShr, MLILLogicalAnd, MLILLogicalOr,
    MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe, MLILLogicalNot, MLILBitwiseNot, MLILTestZero, MLILLoadReg,
)

# IRParameter.type_name -> the parameter's type
PARAM_TYPES = {
    'int'       : MLILType.int_type(),
    'str'       : MLILType.string_type(),
    'pointer'   : MLILType.pointer_type(),
}


class SSATypeInferencePass(Pass):
    """Infer types for SSA variables"""

    def __init__(self):
        self.function: MediumLevelILFunction = None
        self.var_types: Dict[MLILVariableSSA, MLILType] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Infer types and store in var_types"""
        self.function = func
        self.var_types = {}

        self._initialize_types()
        self._propagate_types()
        self._infer_from_usage()

        func.var_types = self._map_to_base_types()
        return func

    def _initialize_types(self):
        """Initialize parameter types from source_params, others as unknown"""
        # Parameter types from source_params
        for i, param in enumerate(self.function.parameters):
            if param is None:
                continue

            ssa_var = MLILVariableSSA(param, 0)

            if i < len(self.function.source_params):
                type_name = self.function.source_params[i].type_name
                self.var_types[ssa_var] = PARAM_TYPES.get(type_name, MLILType.unknown())
            else:
                self.var_types[ssa_var] = MLILType.unknown()

        # All other SSA variables as unknown
        for block in self.function.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    if inst.var not in self.var_types:
                        self.var_types[inst.var] = MLILType.unknown()
                elif isinstance(inst, MLILPhi):
                    if inst.dest not in self.var_types:
                        self.var_types[inst.dest] = MLILType.unknown()

    def _propagate_types(self):
        """Propagate types through assignments until convergence"""
        changed = True
        iterations = 0

        while changed and iterations < SSA_TYPE_PROPAGATION_MAX_ITERATIONS:
            changed = False
            iterations += 1

            for block in self.function.basic_blocks:
                for inst in block.instructions:
                    if isinstance(inst, MLILSetVarSSA):
                        new_type = self._infer_expr_type(inst.value)
                        if self._update_type(inst.var, new_type):
                            changed = True
                    elif isinstance(inst, MLILPhi):
                        unified = MLILType.unknown()
                        for src_var, _ in inst.sources:
                            src_type = self.var_types.get(src_var, MLILType.unknown())
                            unified = unify_types(unified, src_type)

                        if self._update_type(inst.dest, unified):
                            changed = True
                    elif isinstance(inst, MLILStoreDeref):
                        # A lowered address-taken local (ir/mlil/mlil_ssa.py's
                        # _lower_address_taken_vars) has no MLILSetVarSSA target to type -
                        # every *(&x) = v store is its only source of type evidence
                        target = self._ssa_var_from_address(inst.dest)
                        if target is not None:
                            new_type = self._infer_expr_type(inst.value)
                            if self._update_type(target, new_type):
                                changed = True

    def _infer_from_usage(self):
        """Infer types from how variables are used (backward inference)"""
        for _ in range(USAGE_INFERENCE_PASSES):
            for block in self.function.basic_blocks:
                for inst in block.instructions:
                    if isinstance(inst, MLILIf):
                        self._infer_from_condition(inst.condition)

    @classmethod
    def _ssa_var_from_address(cls, expr: MediumLevelILInstruction) -> Optional[MLILVariableSSA]:
        """The lowered local an exact AddressOf(VarSSA) names - this codebase's *(&x)
        address-taken lowering (ir/mlil/mlil_ssa.py's _lower_address_taken_vars) always
        produces exactly this shape, never some other pointer expression. Used both as an
        MLILStoreDeref dest (a write) and, wrapped in a further MLILDeref, as a read - see
        _as_ssa_var."""
        if isinstance(expr, MLILAddressOf) and isinstance(expr.operand, MLILVarSSA):
            return expr.operand.var

        return None

    @classmethod
    def _as_ssa_var(cls, expr: MediumLevelILInstruction) -> Optional[MLILVariableSSA]:
        """An SSA variable read, direct or through this codebase's *(&x) address-taken
        lowering - so backward inference over a lowered local's comparisons/arithmetic works
        the same as over an ordinary scalar SSA variable."""
        if isinstance(expr, MLILVarSSA):
            return expr.var

        if isinstance(expr, MLILDeref):
            return cls._ssa_var_from_address(expr.operand)

        return None

    def _infer_expr_type(self, expr: MediumLevelILInstruction) -> MLILType:
        """Infer type of expression"""
        if isinstance(expr, MLILConst):
            return self._infer_const_type(expr)
        elif isinstance(expr, (MLILVarSSA, MLILDeref)):
            target = self._as_ssa_var(expr)
            return self.var_types.get(target, MLILType.unknown()) if target is not None else MLILType.unknown()
        elif isinstance(expr, MLILAddressOf):
            return MLILType.pointer_type()
        elif isinstance(expr, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod)):
            lhs_type = self._infer_expr_type(expr.lhs)
            rhs_type = self._infer_expr_type(expr.rhs)
            unified = unify_types(lhs_type, rhs_type)
            return unified if unified.is_numeric() else MLILType.int_type()
        elif isinstance(expr, INT_RESULT_OPS):
            return MLILType.int_type()
        elif isinstance(expr, MLILNeg):
            operand_type = self._infer_expr_type(expr.operand)
            return operand_type if operand_type.is_numeric() else MLILType.int_type()

        return MLILType.unknown()

    def _infer_const_type(self, const: MLILConst) -> MLILType:
        """Infer type from constant value"""
        if not const.is_hex and isinstance(const.value, str):
            return MLILType.string_type()

        if isinstance(const.value, int):
            return MLILType.int_type()
        elif isinstance(const.value, float):
            return MLILType.float_type()

        return MLILType.unknown()

    def _infer_from_condition(self, cond: MediumLevelILInstruction):
        """Infer type from conditional expression"""
        if isinstance(cond, (MLILEq, MLILNe, MLILLt, MLILLe, MLILGt, MLILGe)):
            self._infer_from_comparison(cond)
        elif isinstance(cond, (MLILAdd, MLILSub, MLILMul, MLILDiv, MLILMod)):
            self._infer_from_arithmetic(cond)
        else:
            cond_var = self._as_ssa_var(cond)
            if cond_var is not None:
                var_type = self.var_types.get(cond_var, MLILType.unknown())
                if var_type.is_unknown():
                    self._update_type(cond_var, MLILType.int_type())

    def _infer_from_comparison(self, comp: MediumLevelILInstruction):
        """Infer type from comparison operation"""
        lhs, rhs = comp.lhs, comp.rhs

        if isinstance(rhs, MLILConst):
            const_type = self._infer_const_type(rhs)
            lhs_var = self._as_ssa_var(lhs)
            if lhs_var is not None and not const_type.is_unknown():
                self._update_type(lhs_var, const_type)
        elif isinstance(lhs, MLILConst):
            const_type = self._infer_const_type(lhs)
            rhs_var = self._as_ssa_var(rhs)
            if rhs_var is not None and not const_type.is_unknown():
                self._update_type(rhs_var, const_type)

    def _infer_from_arithmetic(self, arith: MediumLevelILInstruction):
        """Infer that variables in arithmetic are numeric"""
        for operand in (arith.lhs, arith.rhs):
            operand_var = self._as_ssa_var(operand)
            if operand_var is None:
                continue

            var_type = self.var_types.get(operand_var, MLILType.unknown())
            if var_type.is_unknown():
                self._update_type(operand_var, MLILType.int_type())

    def _update_type(self, var: MLILVariableSSA, new_type: MLILType) -> bool:
        """Update variable type, return True if changed"""
        old_type = self.var_types.get(var, MLILType.unknown())
        unified = unify_types(old_type, new_type)

        if unified != old_type:
            self.var_types[var] = unified
            return True

        return False

    def _map_to_base_types(self) -> Dict[str, MLILType]:
        """Map SSA types to base variable names"""
        base_types = {}

        for ssa_var, typ in self.var_types.items():
            # Globals always lower back to GLOBALS[n] (see SSADeconstructor), never surviving as a
            # named variable - recording a type for them here would be a stale, unused entry
            if self.function.is_global_var(ssa_var.base_var):
                continue

            name = ssa_var.base_var.name

            if name in base_types:
                base_types[name] = unify_types(base_types[name], typ)
            else:
                base_types[name] = typ

        return base_types
