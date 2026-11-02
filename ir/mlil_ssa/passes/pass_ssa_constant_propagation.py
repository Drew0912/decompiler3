"""Constant Propagation Pass

Replace SSA variables with constant values (no folding)
"""

from ir.pipeline import Pass
from ir.mlil.mlil import (
    map_operands,
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MLILConst,
    MLILAddressOf,
    MLILTestZero,
)
from ..mlil_ssa import (
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
)


class ConstantPropagationPass(Pass):
    """Replace SSA variables with constant values"""

    def __init__(self):
        self.constants: dict[MLILVariableSSA, int] = {}
        # Every variable substituted in any run: its string already sits in its uses, so a removed string assignment
        # of it needs no debug comment (string_debug_comment)
        self.replaced_vars: set[MLILVariableSSA] = set()

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        """Propagate constants through the function"""
        self._build_constants(func)
        changed = True

        while changed:
            changed = self._propagate_once(func)

        return func

    def _build_constants(self, func: MediumLevelILFunction):
        """Build constant map from SSA definitions"""
        self.constants = {}

        for inst in func.iter_instructions():
            if isinstance(inst, MLILSetVarSSA):
                if isinstance(inst.value, MLILConst):
                    self.constants[inst.var] = inst.value.value

    def _propagate_once(self, func: MediumLevelILFunction) -> bool:
        """Single propagation pass"""
        changed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = map_operands(inst, self._propagate_in_expr)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _propagate_in_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        """Replace SSA variables with constants"""
        if isinstance(expr, MLILVarSSA):
            if expr.var in self.constants:
                self.replaced_vars.add(expr.var)
                return MLILConst(self.constants[expr.var], is_hex=False)

            return expr
        elif isinstance(expr, MLILAddressOf):
            # &x's operand is a location: a constant is no substitute
            return expr
        elif isinstance(expr, MLILTestZero):
            # Its operand is left alone: entering it changes the output (work order, "Uneven MLIL pass coverage")
            return expr
        else:
            return map_operands(expr, self._propagate_in_expr)
