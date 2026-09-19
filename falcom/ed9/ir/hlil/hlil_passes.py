'''Falcom HLIL Passes'''

from typing import Optional
from ir.pipeline import Pass
from ir.hlil import HighLevelILFunction
from ...parser.types_parser import Function


class FalcomTypeInferencePass(Pass):
    '''Falcom type inference pass'''

    def __init__(self, scp_func: Optional[Function] = None):
        '''Initialize'''
        self.scp_func = scp_func

    def run(self, hlil_func: HighLevelILFunction) -> HighLevelILFunction:
        '''Add type information to HLIL function'''
        if not self.scp_func:
            return hlil_func

        # Add type information to parameters
        for param in hlil_func.parameters:
            # Extract parameter index from name (arg0 -> 0, arg1 -> 1, etc.)
            if not param.name.startswith('arg'):
                continue

            try:
                param_index = int(param.name[3:])  # Skip 'arg' prefix (arg1 -> 1)
            except ValueError:
                continue

            # Convert to 0-based index (arg1 -> params[0])
            scp_param_index = param_index - 1
            if scp_param_index < 0 or scp_param_index >= len(self.scp_func.params):
                continue

            # Get SCP parameter type and default value
            scp_param = self.scp_func.params[scp_param_index]
            python_type = scp_param.type.get_python_type()

            # Map to TypeScript type
            param.type_hint = self._python_type_to_ts_type(python_type)

            # Get default value if available
            if scp_param.default_value is not None:
                param.default_value = self._scpvalue_to_ts_literal(scp_param.default_value)

        return hlil_func

    @classmethod
    def _python_type_to_ts_type(cls, python_type: str) -> str:
        '''Map Python parameter type to TypeScript type'''
        type_map = {
            'Value32': 'number',            # int | float
            'str': 'string',
            'Nullable32': 'number',         # Optional parameter with default value
            'NullableStr': 'string',        # Optional parameter with default value
            'Pointer': 'number',            # Output parameter (use addr_of() at call site)
        }
        return type_map.get(python_type, 'any')

    @classmethod
    def _scpvalue_to_ts_literal(cls, scpvalue) -> str:
        '''Convert ScpValue to TypeScript literal'''
        from common import format_float

        # Get the actual value from ScpValue
        value = scpvalue.value

        # Convert to TypeScript literal
        if isinstance(value, str):
            # Escape string and wrap in quotes
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'

        elif isinstance(value, bool):
            return 'true' if value else 'false'

        elif isinstance(value, float):
            return format_float(value)

        elif isinstance(value, int):
            return str(value)

        elif value is None:
            return 'null'

        else:
            return str(value)
