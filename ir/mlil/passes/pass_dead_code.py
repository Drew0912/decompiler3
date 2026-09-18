'''Dead code elimination pass'''

from ir.pipeline import Pass
from ..mlil import (
    MediumLevelILFunction,
    MLILVar, MLILBinaryOp, MLILUnaryOp, MLILSetVar,
    MLILIf, MLILRet, MLILCall, MLILSyscall, MLILCallScript,
    MLILStoreGlobal, MLILStoreReg
)


class DeadCodeEliminationPass(Pass):
    '''Remove unused variable assignments'''

    def run(self, mlil_func: MediumLevelILFunction) -> MediumLevelILFunction:
        '''Eliminate dead code'''
        var_uses = {}

        def count_uses(expr):
            if isinstance(expr, MLILVar):
                var_name = expr.var.name
                var_uses[var_name] = var_uses.get(var_name, 0) + 1

            elif isinstance(expr, MLILBinaryOp):
                count_uses(expr.lhs)
                count_uses(expr.rhs)

            elif isinstance(expr, MLILUnaryOp):
                count_uses(expr.operand)

            elif isinstance(expr, (MLILCall, MLILSyscall, MLILCallScript)):
                for arg in expr.args:
                    count_uses(arg)

        # Scan all instructions to count uses
        for block in mlil_func.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILSetVar):
                    count_uses(inst.value)

                elif isinstance(inst, MLILIf):
                    count_uses(inst.condition)

                elif isinstance(inst, MLILRet):
                    if inst.value:
                        count_uses(inst.value)

                elif isinstance(inst, (MLILCall, MLILSyscall, MLILCallScript)):
                    for arg in inst.args:
                        count_uses(arg)

                elif isinstance(inst, MLILStoreGlobal):
                    count_uses(inst.value)

                elif isinstance(inst, MLILStoreReg):
                    count_uses(inst.value)

        # Remove unused assignments
        for block in mlil_func.basic_blocks:
            new_instructions = []
            for inst in block.instructions:
                if not isinstance(inst, MLILSetVar):
                    new_instructions.append(inst)
                    continue

                # A global write is an observable cross-function side effect - keep it even with
                # zero in-function reads (not on the live Falcom path today, but harden anyway:
                # a global is never expected to sit in MLILSetVar form outside the SSA window)
                var_name = inst.var.name
                if var_uses.get(var_name, 0) > 0 or mlil_func.is_global_var(inst.var):
                    new_instructions.append(inst)

            block.instructions = new_instructions

        return mlil_func
