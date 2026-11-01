"""The MLIL operation of each LLIL operation that maps one to one, for every LLIL -> MLIL translator"""

from ir.llil import *
from .mlil import *


# Keyed by exact type: none of these classes has a subclass today, and a future one needs its own entry here (or an arm
# before these lookups)
BINARY_OP_TYPES = {
    LowLevelILAdd           : MLILAdd,
    LowLevelILSub           : MLILSub,
    LowLevelILMul           : MLILMul,
    LowLevelILDiv           : MLILDiv,
    LowLevelILMod           : MLILMod,
    LowLevelILAnd           : MLILAnd,
    LowLevelILOr            : MLILOr,
    LowLevelILLogicalAnd    : MLILLogicalAnd,
    LowLevelILLogicalOr     : MLILLogicalOr,
    LowLevelILEq            : MLILEq,
    LowLevelILNe            : MLILNe,
    LowLevelILLt            : MLILLt,
    LowLevelILLe            : MLILLe,
    LowLevelILGt            : MLILGt,
    LowLevelILGe            : MLILGe,
}
UNARY_OP_TYPES = {
    LowLevelILNeg           : MLILNeg,
    LowLevelILBitwiseNot    : MLILBitwiseNot,
    LowLevelILTestZero      : MLILTestZero,
}
