'''Falcom HLIL Passes'''

from ir.pipeline import Pass
from ir.hlil import HighLevelILFunction, HLILTypeKind
from ...parser.types_parser import Function


# Declared parameter type (ScpParamFlags.get_python_type()) -> HLIL type
PARAM_TYPE_KINDS = {
    'Value32'       : HLILTypeKind.NUMBER,
    'Nullable32'    : HLILTypeKind.NUMBER,
    'str'           : HLILTypeKind.STRING,
    'NullableStr'   : HLILTypeKind.STRING,
    'Pointer'       : HLILTypeKind.POINTER,
}


class FalcomTypeInferencePass(Pass):
    '''Falcom-specific types: each parameter's type comes from the flag the script declares for it,
    not from inference. The home of future Falcom semantic types (e.g. character IDs).'''

    def __init__(self, scp_func: Function):
        self.scp_func = scp_func

    def run(self, hlil_func: HighLevelILFunction) -> HighLevelILFunction:
        '''Set each parameter's type_hint from its declared flag'''
        for param in hlil_func.parameters:
            # Parameters are named arg1..argN in declaration order
            if not param.name.startswith('arg'):
                continue

            try:
                index = int(param.name.removeprefix('arg')) - 1
            except ValueError:
                continue

            if 0 <= index < len(self.scp_func.params):
                kind = PARAM_TYPE_KINDS.get(self.scp_func.params[index].type.get_python_type())
                if kind is not None:
                    param.type_hint = kind

        return hlil_func
