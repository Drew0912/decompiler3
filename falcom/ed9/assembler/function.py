"""An ED9 function as the parser reads and disassembles it: its parameters, call debug records and simulated stack"""

from dataclasses import dataclass, field

import assembler.function
from assembler import Instruction
from ..structs.scp_types import ScpFunctionCallDebugInfo, ScpParamFlags, ScpValue


@dataclass(eq=False, repr=False)
class FunctionParam:
    type            : ScpParamFlags
    default_value   : ScpValue | None = None

    def __str__(self) -> str:
        if self.default_value is not None:
            return f'param({self.type.get_python_type()}, default = {self.default_value})'
        else:
            return f'param({self.type.get_python_type()})'

    __repr__ = __str__


@dataclass(frozen=True)
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
            return f'slot {self.slot} = {' or '.join(kinds)}'

        return f'slot {self.slot} (below the stack)' if self.slot < 0 else f'slot {self.slot} (above the stack)'


@dataclass
class StackLayout:
    """The parser's simulated stack of a disassembled function, kept for comments; keyed by instruction offset"""

    sp_before       : dict[int, int] = field(default_factory=dict)          # slots on the stack before each instruction
    slot_refs       : dict[int, SlotRef] = field(default_factory=dict)      # the slot each offset opcode addresses
    local_slots     : dict[int, int] = field(default_factory=dict)          # an addressed local's instruction -> slot
    arg_numbers     : dict[int, tuple[int, ...]] = field(default_factory=dict)     # an argument's push -> argN per call
    carried_before  : dict[int, int] = field(default_factory=dict)          # bytes a split pop carries into a later POP


@dataclass(eq=False, repr=False, slots=True)
class Function(assembler.function.Function):
    index               : int | None = None     # position in the function table, what PUSH_CURRENT_FUNC_ID pushes
    params              : list[FunctionParam] = field(default_factory=list)
    is_common_func      : bool = False
    # round_trip: the raw call debug records, against the file's bytes
    debug_info          : list[ScpFunctionCallDebugInfo] = field(default_factory=list)
    # local CALL offset -> args its debug record keeps, every paired local call
    call_written_argc   : dict[int, int] = field(default_factory=dict)
    # the same, only where that isn't the compiler's rule (canonical_argc)
    call_debug_argc     : dict[int, int] = field(default_factory=dict)
    # local CALL offsets the compiler left without a record (align_records)
    call_unrecorded     : set[int] = field(default_factory=set)
    stack_layout        : StackLayout | None = None     # set by the parser; a hand-built function has none
    runs_on             : Instruction | None = None     # the instruction that runs on into the next function's code
    # call offset -> (call, warning) of each backward return
    backward_returns    : dict[int, tuple[Instruction, str]] = field(default_factory=dict)

    def __str__(self) -> str:
        params = ', '.join(param.type.get_python_type() if param.default_value is None
                           else f'{param.type.get_python_type()} = {param.default_value.value!r}'
                           for param in self.params)
        return f'{self.name}({params})'

    __repr__ = __str__
