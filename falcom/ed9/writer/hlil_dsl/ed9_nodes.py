"""The HLIL DSL's ED9-only nodes (docs/dsl/HLIL_DSL.md, Form), beside the VM-neutral ones in nodes.py: Raw words, the
registers, engine calls and the two intrinsic statements"""

from ...assembler.vm import REGISTER_COUNT
from ...structs.scp_types import RawInt
from .build import dsl_error
from .calls import Call, dsl_call_maker
from .nodes import Const, Statement, Variable, claim, is_int_not_bool


def Raw(value: int) -> Const:
    """A Raw word, untyped: Return() returns Raw(0)"""
    if not is_int_not_bool(value):
        raise dsl_error(f'Raw takes an int, not {value!r}')

    return Const(RawInt(value))


class Register(Variable):
    """REGS[n], the VM's register n (REGS[0] holds a call's result)"""

    def __init__(self, index: int):
        self.index = index

    def __repr__(self) -> str:
        return f'REGS[{self.index}]'


class _Registers:
    """REGS: REGS[n] is register n, n a constant"""

    def __getitem__(self, index: int) -> Register:
        if not is_int_not_bool(index) or not 0 <= index < REGISTER_COUNT:
            raise dsl_error(f'REGS[n] takes a register number 0..{REGISTER_COUNT - 1}, not {index!r}')

        return Register(index)

    def __setitem__(self, index, value):
        raise dsl_error(f'REGS[{index!r}] = ... sets nothing in the game: write Set(REGS[{index!r}], value)')

    def __repr__(self) -> str:
        return 'REGS'


REGS = _Registers()


class SyscallCall(Call):
    """Syscall(subsystem, cmd, ...), an engine call (SYSCALL), its arguments popped after it"""

    def __init__(self, subsystem: int, cmd: int, args: tuple, kwargs: dict):
        build = self.join_build('Syscall(...)')
        for what, number in (('subsystem', subsystem), ('cmd', cmd)):
            if not is_int_not_bool(number):
                raise build.fail(f'Syscall\'s {what} is a constant number, not {number!r}')

        self.subsystem = subsystem
        self.cmd = cmd
        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'Syscall({self.subsystem}, {self.cmd}, ...)'


@dsl_call_maker
def Syscall(subsystem: int, cmd: int, *args, **kwargs) -> SyscallCall:
    return SyscallCall(subsystem, cmd, args, kwargs)


class PopN(Statement):
    """PopN(values...): pushes the values and pops them again (POPN), with nothing logged"""

    def __init__(self, *values):
        build = self.join_build('PopN(...)')
        if not values:
            raise build.fail('PopN takes one value or more')

        self.values = tuple(claim(build, value, self) for value in values)
        self.children = self.values

    def __repr__(self) -> str:
        return 'PopN(...)'


class DebugInt(Statement):
    """DebugInt(n): DEBUG_INT, a constant the engine logs at a level its logger drops"""

    def __init__(self, value: int):
        build = self.join_build('DebugInt(...)')
        if not is_int_not_bool(value):
            raise build.fail(f'DebugInt takes a constant int, not {value!r}')

        self.value = value
        self.children = ()

    def __repr__(self) -> str:
        return f'DebugInt({self.value})'
