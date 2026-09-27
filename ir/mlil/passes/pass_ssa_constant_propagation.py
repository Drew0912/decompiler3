'''Constant Propagation Pass

Replace SSA variables with constant values (no folding).
'''

from typing import Dict, List, Optional
from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MediumLevelILInstruction,
    MediumLevelILCall,
    MLILConst,
    MLILBinaryOp,
    MLILNeg,
    MLILLogicalNot,
    MLILBitwiseNot,
    MLILRet,
    MLILStoreGlobal,
    MLILStoreReg,
    MLILDeref,
    MLILStoreDeref,
)
from ..mlil_ssa import (
    MLILVariableSSA,
    MLILVarSSA,
    MLILSetVarSSA,
    MLILPhi,
    MLILIf,
)


class ConstantPropagationPass(Pass):
    '''Replace SSA variables with constant values'''

    def __init__(self):
        self.constants: Dict[MLILVariableSSA, int] = {}

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Propagate constants through the function'''
        self._build_constants(func)
        changed = True

        while changed:
            changed = self._propagate_once(func)

        return func

    def _build_constants(self, func: MediumLevelILFunction):
        '''Build constant map from SSA definitions'''
        self.constants = {}

        for block in func.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVarSSA):
                    if isinstance(inst.value, MLILConst):
                        self.constants[inst.var] = inst.value.value

    def _propagate_once(self, func: MediumLevelILFunction) -> bool:
        '''Single propagation pass'''
        changed = False

        for block in func.basic_blocks:
            new_instructions = []

            for inst in block.instructions:
                new_inst = self._propagate_in_inst(inst)
                new_instructions.append(new_inst)

                if new_inst is not inst:
                    changed = True

            block.instructions = new_instructions

        return changed

    def _propagate_in_inst(self, inst: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Propagate constants in a single instruction'''
        if isinstance(inst, MLILSetVarSSA):
            new_value = self._propagate_in_expr(inst.value)
            if new_value is not inst.value:
                return MLILSetVarSSA(inst.var, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILIf):
            new_condition = self._propagate_in_expr(inst.condition)
            if new_condition is not inst.condition:
                return MLILIf(new_condition, inst.true_target, inst.false_target, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILRet):
            if inst.value is not None:
                new_value = self._propagate_in_expr(inst.value)
                if new_value is not inst.value:
                    return MLILRet(new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MediumLevelILCall):
            new_args = [self._propagate_in_expr(arg) for arg in inst.args]
            if any(new_args[i] is not inst.args[i] for i in range(len(inst.args))):
                return inst.rebuild(new_args)

        elif isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            new_value = self._propagate_in_expr(inst.value)
            if new_value is not inst.value:
                if isinstance(inst, MLILStoreGlobal):
                    return MLILStoreGlobal(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

                else:
                    return MLILStoreReg(inst.index, new_value, address = inst.address).copy_metadata_from(inst)

        elif isinstance(inst, MLILStoreDeref):
            new_dest = self._propagate_in_expr(inst.dest)
            new_value = self._propagate_in_expr(inst.value)
            if new_dest is not inst.dest or new_value is not inst.value:
                return inst.rebuild(new_dest, new_value)

        return inst

    def _propagate_in_expr(self, expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
        '''Replace SSA variables with constants'''
        if isinstance(expr, MLILVarSSA):
            if expr.var in self.constants:
                return MLILConst(self.constants[expr.var], is_hex = False)

        elif isinstance(expr, MLILBinaryOp):
            lhs = self._propagate_in_expr(expr.lhs)
            rhs = self._propagate_in_expr(expr.rhs)

            if lhs is not expr.lhs or rhs is not expr.rhs:
                return expr.rebuild(lhs, rhs)

        elif isinstance(expr, (MLILNeg, MLILLogicalNot, MLILBitwiseNot, MLILDeref)):
            operand = self._propagate_in_expr(expr.operand)

            if operand is not expr.operand:
                return expr.rebuild(operand)

        return expr
