"""The HLIL DSL's nodes (docs/dsl/HLIL_DSL.md, Form): what an HLIL body's statements and expressions build while it
runs. Composite nodes (operators, calls, statements) register in the active build and are used once; leaves are
reusable: constants, locals (by name), registers and globals anywhere, a parameter only in its own body. The concrete
expression classes are siblings: Python tries a right operand's reflected operator first only when its class
subclasses the left's"""

import inspect

from ...assembler import ED9Opcode
from ...assembler.vm import REGISTER_COUNT
from ...structs.scp_types import RawInt
from .build import Build, active_build, dsl_error

_MISSING = object()     # Return() and Let(x): no value given


class Node:
    """Every node: Python's truth test, conversions, text, hashing, a subscript or a call on it are mistakes"""

    def __bool__(self):
        raise dsl_error(f'{self!r} has no truth value while the script compiles: Python\'s if / and / or / not and a '
                        'chained comparison test it; use And(...), Or(...), Not(...)')

    def __int__(self):
        raise dsl_error(f'{self!r} is a game value, not a Python number')

    __float__ = __index__ = __int__

    def __str__(self):
        raise dsl_error(f'{self!r} is a game value; text is fixed when the script compiles, so it can\'t hold one')

    def __format__(self, format_spec: str):
        return self.__str__()

    def __getitem__(self, key):
        raise dsl_error(f'{self!r}[...]: missing comma? (a line starting with [ continues the one before)')

    def __call__(self, *args, **kwargs):
        raise dsl_error(f'{self!r}(...): missing comma? (a line starting with ( continues the one before)')

    __hash__ = None


class Expr(Node):
    """A value: the operators build operation nodes, in the VM's order (left operand pushed first); defining __eq__
    leaves it unhashable, as Node is"""

    def __add__(self, other):
        return BinaryOp(ED9Opcode.ADD, self, other)

    def __radd__(self, other):
        return BinaryOp(ED9Opcode.ADD, other, self)

    def __sub__(self, other):
        return BinaryOp(ED9Opcode.SUB, self, other)

    def __rsub__(self, other):
        return BinaryOp(ED9Opcode.SUB, other, self)

    def __mul__(self, other):
        return BinaryOp(ED9Opcode.MUL, self, other)

    def __rmul__(self, other):
        return BinaryOp(ED9Opcode.MUL, other, self)

    def __truediv__(self, other):
        return BinaryOp(ED9Opcode.DIV, self, other)

    def __rtruediv__(self, other):
        return BinaryOp(ED9Opcode.DIV, other, self)

    def __mod__(self, other):
        return BinaryOp(ED9Opcode.MOD, self, other)

    def __rmod__(self, other):
        return BinaryOp(ED9Opcode.MOD, other, self)

    def __and__(self, other):
        return BinaryOp(ED9Opcode.BITWISE_AND, self, other)

    def __rand__(self, other):
        return BinaryOp(ED9Opcode.BITWISE_AND, other, self)

    def __or__(self, other):
        return BinaryOp(ED9Opcode.BITWISE_OR, self, other)

    def __ror__(self, other):
        return BinaryOp(ED9Opcode.BITWISE_OR, other, self)

    # A literal on the left reaches these reflected (5 < x is x > 5): the same test, its operands swapped
    def __eq__(self, other):
        return BinaryOp(ED9Opcode.EQ, self, other)

    def __ne__(self, other):
        return BinaryOp(ED9Opcode.NE, self, other)

    def __lt__(self, other):
        return BinaryOp(ED9Opcode.LT, self, other)

    def __le__(self, other):
        return BinaryOp(ED9Opcode.LE, self, other)

    def __gt__(self, other):
        return BinaryOp(ED9Opcode.GT, self, other)

    def __ge__(self, other):
        return BinaryOp(ED9Opcode.GE, self, other)

    def __neg__(self):
        return UnaryOp(ED9Opcode.NEG, self)

    def __invert__(self):
        return UnaryOp(ED9Opcode.NOT, self)


# Leaves

class Const(Expr):
    """A constant, pushed by opcode (PUSH_INT, PUSH_FLOAT, PUSH_STR or PUSH_RAW)"""

    def __init__(self, opcode: ED9Opcode, value: int | float | str | RawInt):
        self.opcode = opcode
        self.value = value

    def __repr__(self) -> str:
        return repr(self.value)


def Int(value: int) -> Const:
    """An Integer constant, where Python would fold or mirror a bare literal: Int(8) | 16, ~Int(8), Int(9) < arg1"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise dsl_error(f'Int takes an int, not {value!r}')

    return Const(ED9Opcode.PUSH_INT, int(value))


def Float(value: float) -> Const:
    """A Float constant, where Python would fold a bare literal: Float(0.293) * 2"""
    if not isinstance(value, float):
        raise dsl_error(f'Float takes a float (2.0, not 2), not {value!r}')

    return Const(ED9Opcode.PUSH_FLOAT, value)


def Str(value: str) -> Const:
    """A String constant, where Python would format a bare literal: Str("...") % arg1"""
    if not isinstance(value, str):
        raise dsl_error(f'Str takes a str, not {value!r}')

    return Const(ED9Opcode.PUSH_STR, value)


def Raw(value: int) -> Const:
    """A Raw word, untyped: Return() returns Raw(0)"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise dsl_error(f'Raw takes an int, not {value!r}')

    return Const(ED9Opcode.PUSH_RAW, RawInt(value))


class Param(Expr):
    """A parameter of the body its build runs: position counts from 1, as arg1 does"""

    def __init__(self, build: Build, position: int, name: str):
        self.build = build
        self.position = position
        self.name = name

    def __repr__(self) -> str:
        return self.name


class Local(Expr):
    """A local variable, by name: x = Local('x'), declared in each body with Let(x) or Let(x, value)"""

    def __init__(self, name: str):
        if not isinstance(name, str) or not name:
            raise dsl_error(f'Local takes the local\'s name, not {name!r}')

        self.name = name

    def __repr__(self) -> str:
        return self.name


class Register(Expr):
    """REGS[n], the VM's register n (REGS[0] holds a call's result)"""

    def __init__(self, index: int):
        self.index = index

    def __repr__(self) -> str:
        return f'REGS[{self.index}]'


class _Registers:
    """REGS: REGS[n] is register n, n a constant"""

    def __getitem__(self, index: int) -> Register:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < REGISTER_COUNT:
            raise dsl_error(f'REGS[n] takes a register number 0..{REGISTER_COUNT - 1}, not {index!r}')

        return Register(index)

    def __setitem__(self, index, value):
        raise dsl_error(f'REGS[{index!r}] = ... sets nothing in the game: write Set(REGS[{index!r}], value)')

    def __repr__(self) -> str:
        return 'REGS'


REGS = _Registers()


class Global(Expr):
    """this.name, a script global"""

    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return f'this.{self.name}'


class _This:
    """this: this.name is the script global name"""

    def __getattr__(self, name: str) -> Global:
        # Python's own dunder probes (copy, pickle, inspect) are not globals and expect AttributeError
        if name.startswith('__'):
            raise AttributeError(name)

        return Global(name)

    def __setattr__(self, name: str, value):
        raise dsl_error(f'this.{name} = ... sets nothing in the game: write Set(this.{name}, value)')

    def __repr__(self) -> str:
        return 'this'


this = _This()


# Composite nodes: each joins the active build, then claims its operands

def constant(value) -> Const:
    """A Python value as a DSL constant: int an Integer, float a Float, str a String, RawInt a Raw word"""
    if isinstance(value, bool) or value is None:
        raise dsl_error(f'{value!r} is not a DSL value: the VM has no bool or None (write 1 / 0)')

    if isinstance(value, RawInt):
        return Const(ED9Opcode.PUSH_RAW, value)

    if isinstance(value, int):
        return Const(ED9Opcode.PUSH_INT, int(value))  # an IntEnum, an ID's name: its number

    if isinstance(value, float):
        return Const(ED9Opcode.PUSH_FLOAT, value)

    if isinstance(value, str):
        return Const(ED9Opcode.PUSH_STR, value)

    raise dsl_error(f'{value!r} ({type(value).__name__}) is not a DSL value')


def claim(build: Build, value, parent: Composite) -> Node:
    """value as parent's operand: a literal becomes a constant; a composite node is used once, in its own build; a
    parameter only in its own body"""
    if isinstance(value, Param):
        if value.build is not build:
            raise build.fail(f'{value.name} belongs to {value.build.function_name}\'s body; to keep a value between '
                             f'functions, store it in a global: Set(this.name, {value.name})')

        return value

    if isinstance(value, Statement):
        raise build.fail(f'{value!r} is a statement, not a value')

    if isinstance(value, Composite):
        if value.build is not build:
            raise build.fail(f'{value!r} was made in another HLIL body (or outside one) and kept: a node is used in '
                             'the body that makes it')

        if value.parent is not None:
            raise build.fail(f'{value!r} is used twice: a call or an operation runs once, where it is used; keep a '
                             'value with Let(x, value) and read x')

        value.parent = parent
        return value

    if isinstance(value, Node):
        return value

    return constant(value)


def require_build(what: str) -> Build:
    build = active_build()
    if build is None:
        raise dsl_error(f'{what} builds an HLIL node: it is written only in an HLIL body (@scena.HLILCode())')

    return build


class Composite:
    """A node the body's run makes: registered in its build at its creation site, used once (parent)"""

    build: Build
    site: object
    parent: Composite | None
    children: tuple

    def join_build(self, what: str) -> Build:
        """Register in the active build (what names the node in the error when there is none)"""
        build = require_build(what)
        build.register(self)
        return build


class BinaryOp(Composite, Expr):
    def __init__(self, opcode: ED9Opcode, lhs, rhs):
        build = self.join_build(f'an operation ({opcode.name})')
        self.opcode = opcode
        self.lhs = claim(build, lhs, self)
        self.rhs = claim(build, rhs, self)
        self.children = (self.lhs, self.rhs)

    def __repr__(self) -> str:
        return f'({self.lhs!r} {self.opcode.name} {self.rhs!r})'


class UnaryOp(Composite, Expr):
    def __init__(self, opcode: ED9Opcode, operand):
        build = self.join_build(f'an operation ({opcode.name})')
        self.opcode = opcode
        self.operand = claim(build, operand, self)
        self.children = (self.operand,)

    def __repr__(self) -> str:
        return f'{self.opcode.name}({self.operand!r})'


def And(first, second, *rest) -> BinaryOp:
    """The VM's eager logical and of two or more values (LOGICAL_AND), left to right"""
    node = BinaryOp(ED9Opcode.LOGICAL_AND, first, second)
    for value in rest:
        node = BinaryOp(ED9Opcode.LOGICAL_AND, node, value)

    return node


def Or(first, second, *rest) -> BinaryOp:
    """The VM's eager logical or of two or more values (LOGICAL_OR), left to right"""
    node = BinaryOp(ED9Opcode.LOGICAL_OR, first, second)
    for value in rest:
        node = BinaryOp(ED9Opcode.LOGICAL_OR, node, value)

    return node


def Not(value) -> UnaryOp:
    """The VM's logical not (EZ): 1 when value is 0"""
    return UnaryOp(ED9Opcode.EZ, value)


class Call(Composite, Expr):
    """A call: a statement when nothing uses it, else its result (REGS[0] after the call)"""

    def claim_args(self, build: Build, args: tuple, kwargs: dict):
        if kwargs:
            raise build.fail(f'{self!r} takes its arguments by position (the VM passes them so), not '
                             f'{', '.join(kwargs)}=')

        self.args = tuple(claim(build, arg, self) for arg in args)
        self.children = self.args


class LocalCall(Call):
    """A call of a script or library function (CALL): every parameter given, since a local CALL ignores defaults"""

    def __init__(self, function, body, args: tuple, kwargs: dict):
        """function is what CALL takes, as an LLIL body passes it (the stub its name is bound to); body its body"""
        build = self.join_build(f'{function.__name__}(...)')
        self.function = function
        self.name = function.__name__
        # Counted as registration counts them: a functools.wraps wrapper has its wrapped function's
        param_count = len(inspect.signature(body).parameters)
        if not kwargs and len(args) != param_count:
            raise build.fail(f'{self.name} takes {param_count} arguments, {len(args)} given: a local call passes every '
                             'one, defaults too (a local CALL ignores defaults)')

        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'{self.name}(...)'


class ScriptCall(Call):
    """script.module.name(...), a call of another script's function (CALL_SCRIPT): the arguments as written, since a
    script call may leave out trailing defaults"""

    def __init__(self, module: str, name: str, args: tuple, kwargs: dict):
        build = self.join_build(f'script.{module}.{name}(...)')
        self.module = module
        self.name = name
        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'script.{self.module}.{self.name}(...)'


class SyscallCall(Call):
    """Syscall(subsystem, cmd, ...), an engine call (SYSCALL), its arguments popped after it"""

    def __init__(self, subsystem: int, cmd: int, args: tuple, kwargs: dict):
        build = self.join_build('Syscall(...)')
        for what, number in (('subsystem', subsystem), ('cmd', cmd)):
            if isinstance(number, bool) or not isinstance(number, int):
                raise build.fail(f'Syscall\'s {what} is a constant number, not {number!r}')

        self.subsystem = subsystem
        self.cmd = cmd
        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'Syscall({self.subsystem}, {self.cmd}, ...)'


def Syscall(subsystem: int, cmd: int, *args, **kwargs) -> SyscallCall:
    return SyscallCall(subsystem, cmd, args, kwargs)


class ScriptFunction:
    def __init__(self, module: str, name: str):
        self.module = module
        self.name = name

    def __call__(self, *args, **kwargs) -> ScriptCall:
        return ScriptCall(self.module, self.name, args, kwargs)

    def __repr__(self) -> str:
        return f'script.{self.module}.{self.name}'


class _ScriptModule:
    def __init__(self, module: str):
        self.module = module

    def __getattr__(self, name: str) -> ScriptFunction:
        if name.startswith('__'):
            raise AttributeError(name)

        return ScriptFunction(self.module, name)

    def __repr__(self) -> str:
        return f'script.{self.module}'


class _Script:
    """script: script.module.name(...) calls another script's function"""

    def __getattr__(self, module: str) -> _ScriptModule:
        if module.startswith('__'):
            raise AttributeError(module)

        return _ScriptModule(module)

    def __repr__(self) -> str:
        return 'script'


script = _Script()


# Statements

class Statement(Composite, Node):
    """A statement: used by nothing, it stands where it was made"""


class Set(Statement):
    """Set(target, value): stores value in a parameter, a local, this.x or REGS[n]"""

    def __init__(self, target, value):
        build = self.join_build('Set(...)')
        if not isinstance(target, (Param, Local, Global, Register)):
            raise build.fail(f'Set\'s target is a parameter, a local, this.x or REGS[n], not {target!r}')

        self.target = claim(build, target, self)
        self.value = claim(build, value, self)
        self.children = (self.value,)

    def __repr__(self) -> str:
        return f'Set({self.target!r}, ...)'


class Let(Statement):
    """Let(x) declares local x (PUSH_RAW 0); Let(x, value) declares and stores it"""

    def __init__(self, local, value=_MISSING):
        build = self.join_build('Let(...)')
        if not isinstance(local, Local):
            raise build.fail(f'Let declares a local (x = Local(\'x\')), not {local!r}')

        self.local = local
        self.value = None if value is _MISSING else claim(build, value, self)
        self.children = () if self.value is None else (self.value,)

    def __repr__(self) -> str:
        return f'Let({self.local!r}, ...)'


class Return(Statement):
    """Return(value) ends the body with value in REGS[0]; Return() with the Raw 0 the compiler writes"""

    def __init__(self, value=_MISSING):
        build = self.join_build('Return(...)')
        self.value = Raw(0) if value is _MISSING else claim(build, value, self)
        self.children = (self.value,)

    def __repr__(self) -> str:
        return 'Return(...)'


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
        if isinstance(value, bool) or not isinstance(value, int):
            raise build.fail(f'DebugInt takes a constant int, not {value!r}')

        self.value = value
        self.children = ()

    def __repr__(self) -> str:
        return f'DebugInt({self.value})'
