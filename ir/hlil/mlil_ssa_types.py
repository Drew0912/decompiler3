"""The SSA path's type hand-off: the types its type pass inferred, given to the converted HLIL function. It loads the
SSA package, so ir/hlil/__init__.py does not import it: only the SSA path's HLIL entry point does"""

from ir.mlil.mlil_types import MLILTypeKind
from ir.mlil_ssa import MediumLevelILFunctionSSA
from .hlil import HighLevelILFunction, HLILTypeKind

MLIL_TYPE_HINTS = {
    MLILTypeKind.UNKNOWN  : None,
    MLILTypeKind.INT      : HLILTypeKind.INT,
    MLILTypeKind.FLOAT    : HLILTypeKind.FLOAT,
    MLILTypeKind.STRING   : HLILTypeKind.STRING,
    MLILTypeKind.BOOL     : HLILTypeKind.INT,
    MLILTypeKind.POINTER  : HLILTypeKind.POINTER,
    MLILTypeKind.VARIANT  : None,
    MLILTypeKind.VOID     : HLILTypeKind.VOID,
}


def apply_inferred_types(mlil_func: MediumLevelILFunctionSSA, hlil_func: HighLevelILFunction):
    """Give each HLIL parameter and local the type the SSA path inferred for its name"""
    for var in [*hlil_func.parameters, *hlil_func.variables]:
        mlil_type = mlil_func.var_types.get(var.name)
        if mlil_type is not None:
            var.type_hint = MLIL_TYPE_HINTS[mlil_type.kind]
