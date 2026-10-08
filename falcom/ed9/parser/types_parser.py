from .types_scp import *
from .crc32 import hash_func_Name
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..disasm import BasicBlock, Instruction

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


@dataclass(frozen = True)
class SlotRef:
    """The stack slot an offset opcode addresses, counted from the stack bottom, and what may be in it at that point.
    An empty one is outside the live stack: below it when slot < 0, else at or above sp"""
    slot            : int
    params          : tuple[int, ...] = ()  # parameter numbers; arg1 is the highest parameter slot
    local           : bool = False          # a value this function put there
    caller_frame    : bool = False          # a slot of a PUSH_CALLER_FRAME
    call_setup      : bool = False          # a local call's function ID or return address

    @property
    def unusual(self) -> bool:
        """Anything but exactly one parameter or a local: outside the live stack, a caller-frame or call-setup slot, or
        more than one kind of value"""
        return len(self.params) + self.local != 1 or self.caller_frame or self.call_setup

    def __str__(self) -> str:
        """'slot 2 = arg1', 'slot 3' (a local), 'slot 2 = arg1 or local', 'slot -1 (below the stack)'"""
        kinds = [f'arg{number}' for number in self.params]
        kinds += [kind for kind, held in (('local', self.local), ('caller frame', self.caller_frame),
                                          ('call setup', self.call_setup)) if held]
        if kinds == ['local']:
            return f'slot {self.slot}'

        if kinds:
            return f'slot {self.slot} = {" or ".join(kinds)}'

        return f'slot {self.slot} (below the stack)' if self.slot < 0 else f'slot {self.slot} (above the stack)'


@dataclass
class StackLayout:
    """The parser's simulated stack of a disassembled function, kept for comments; keyed by instruction offset"""
    sp_before       : dict[int, int] = field(default_factory = dict)        # slots on the stack before each instruction
    slot_refs       : dict[int, SlotRef] = field(default_factory = dict)    # the slot each offset opcode addresses
    local_slots     : dict[int, int] = field(default_factory = dict)        # an addressed local's instruction -> slot
    arg_numbers     : dict[int, tuple[int, ...]] = field(default_factory = dict)   # an argument's push -> argN per call


class Function(StrictBase):
    name            : str
    index           : int | None        # position in the function table, what PUSH_CURRENT_FUNC_ID pushes
    offset          : int
    params          : list[FunctionParam]
    is_common_func  : bool
    debug_info      : list[FunctionCallDebugInfo]
    call_debug_argc : dict[str, int]    # CALL return label -> args passed explicitly, when fewer than the callee's params
    entry_block     : BasicBlock | None
    unreachable_blocks : list[BasicBlock]   # code no branch reaches, linearly decoded (not linked into the CFG)
    stack_layout    : StackLayout | None    # set by the parser; a hand-built function has none
    runs_on         : Instruction | None    # the instruction that runs on past its end into the next function's code

    def __init__(self):
        self.index      = None
        self.params     = []
        self.debug_info = []
        self.call_debug_argc = {}
        self.entry_block = None
        self.unreachable_blocks = []
        self.stack_layout = None
        self.runs_on = None

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
