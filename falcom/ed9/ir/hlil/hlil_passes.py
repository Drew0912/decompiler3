"""Falcom HLIL Passes"""

from ir.pipeline import Pass
from ir.hlil import HighLevelILFunction, HLILTypeKind
from ...assembler.function import Function


# Declared parameter type (ScpParamFlags.get_python_type()) -> HLIL type
PARAM_TYPE_KINDS = {
    'Value32'       : HLILTypeKind.NUMBER,
    'Nullable32'    : HLILTypeKind.NUMBER,
    'str'           : HLILTypeKind.STRING,
    'NullableStr'   : HLILTypeKind.STRING,
    'Pointer'       : HLILTypeKind.POINTER,
}


class FalcomTypeInferencePass(Pass):
    """Falcom-specific types: each parameter's type comes from the flag the script declares for it,
    not from inference. The home of future Falcom semantic types (e.g. character IDs)."""

    def __init__(self, scp_func: Function):
        self.scp_func = scp_func

    def run(self, hlil_func: HighLevelILFunction) -> HighLevelILFunction:
        """Set each parameter's type_hint from its declared flag"""
        for index, param in enumerate(hlil_func.parameters):
            # HLIL keeps the declared parameters, in declaration order
            kind = PARAM_TYPE_KINDS.get(self.scp_func.params[index].type.get_python_type())
            if kind is not None:
                param.type_hint = kind

        return hlil_func
