"""Return value pass - a return passes the result register on (REG[r] = v; return REG[r]); this returns the stored value
itself where nothing runs between, return v. Exact and removable: v is evaluated where the store evaluated it, with only
line markers and nops after it, and a return passes the result register on only as its value"""

from ir.pipeline import Pass
from ..mlil import (
    is_nop_instr,
    MediumLevelILFunction,
    MLILLoadReg,
    MLILRet,
    MLILStoreReg,
)


class ReturnValuePass(Pass):
    """A block ending in return REG[r], r the function's result register, whose statement before it (line markers and
    nops skipped) is REG[r] = v: the store dropped, the return returns v. Only the block's tail is read: linear in the
    function. A function without a result register is left as it is"""

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        register = func.result_register
        if register is None:
            return func

        for block in func.basic_blocks:
            insts = block.instructions
            ret = insts[-1] if insts else None
            if not (isinstance(ret, MLILRet) and isinstance(ret.value, MLILLoadReg) and ret.value.index == register):
                continue

            at = len(insts) - 2
            while at >= 0 and is_nop_instr(insts[at]):
                at -= 1
            store = insts[at] if at >= 0 else None
            if isinstance(store, MLILStoreReg) and store.index == register:
                insts[-1] = ret.rebuild(store.value)
                del insts[at]

        return func
