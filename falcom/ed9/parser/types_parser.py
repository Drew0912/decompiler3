from .types_scp import *
from .crc32 import hash_func_Name
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..disasm import BasicBlock

class GlobalVar:
    index       : int
    name        : str
    type        : ScpGlobalVar.Type

    def __init__(self, index: int, name: str, type: ScpGlobalVar.Type):
        self.index = index
        self.name = name
        self.type = type

    def __str__(self) -> str:
        return f'global(index = {self.index}, name = {self.name!r}, type = {self.type})'

    __repr__ = __str__


class FunctionCallDebugInfo:
    class ArgInfo(StrictBase):
        value : ScpValue
        type  : int

        def __init__(self, type: int, value: ScpValue):
            self.type = type
            self.value = value

    func_name   : str
    call_type   : ScpFunctionCallDebugInfo.CallType
    args        : list[ArgInfo]

    def __init__(self):
        self.args = []

    def __str__(self) -> str:
        lines = [f'debug_info(func_name={self.func_name}, call_type={self.call_type})']
        if self.args:
            indent = default_indent()
            for arg in self.args:
                lines.append(f'{indent}arg(type={arg.type}, value={arg.value})')
        return '\n'.join(lines)

    __repr__ = __str__


class FunctionParam:
    type            : ScpParamFlags
    default_value   : ScpValue | None

    def __init__(self, type: ScpParamFlags, default_value: ScpValue | None = None):
        self.type           = type
        self.default_value  = default_value

    def __str__(self) -> str:
        if self.default_value is not None:
            return f'param({self.type.get_python_type()}, default = {self.default_value})'
        else:
            return f'param({self.type.get_python_type()})'

    __repr__ = __str__

class Function:
    name            : str
    offset          : int
    params          : list[FunctionParam]
    is_common_func  : bool
    debug_info      : list[FunctionCallDebugInfo]
    call_debug_argc : dict[str, int]    # CALL return label -> args passed explicitly, when fewer than the callee's params
    entry_block     : BasicBlock | None
    unreachable_blocks : list[BasicBlock]   # code no branch reaches, linearly decoded (not linked into the CFG)

    def __init__(self):
        self.params     = []
        self.debug_info = []
        self.call_debug_argc = {}
        self.entry_block = None
        self.unreachable_blocks = []

    def name_hash(self) -> int:
        return hash_func_Name(self.name)

    def __str__(self) -> str:
        params = ', '.join([
            param.type.get_python_type() if param.default_value is None
                else f'{param.type.get_python_type()} = {param.default_value.value!r}'
            for param in self.params
        ])

        lines = [
            f'{self.name}({params})',
        ]

        indent = default_indent()

        # if self.debug_info:
        #     for dbg in self.debug_info:
        #         dbg_lines = str(dbg).splitlines()
        #         for dbg_line in dbg_lines:
        #             lines.append(f'{indent}{dbg_line}')

        #         lines.append('')

        return '\n'.join(lines)

    __repr__ = __str__
