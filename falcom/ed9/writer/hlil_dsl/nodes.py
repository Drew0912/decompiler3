"""The HLIL DSL's nodes (docs/dsl/HLIL_DSL.md, Form): what an HLIL body's statements and expressions build while it
runs, keyed by HLIL's own operators and by the constant's value, so no VM's opcode (the ED9-only nodes are in
ed9_nodes.py, the ED9 opcodes in lowering.py). Composite nodes (operators, calls, statements) register in the active
build and are used once; leaves are reusable: constants, locals (by name) and globals anywhere, a parameter only in
its own body. The concrete expression classes are siblings: Python tries a right operand's reflected operator first
only when its class subclasses the left's"""

import inspect
from enum import Enum

from ir.core import operators
from .build import Build, active_build, dsl_error

_MISSING = object()     # Return() and Let(x): no value given

# The functions whose call makes a DSL call besides the stubs and script.module.name (ED9's Syscall), each registered
# where it is defined; a wrapper of one is not one, as a stub's wrapper is not a stub
_dsl_call_makers: list = []


def dsl_call_maker(function):
    _dsl_call_makers.append(function)
    return function


def makes_dsl_call(callee) -> bool:
    """callee's call makes a DSL call: script.module.name, or a registered function itself (the source check reads
    a helper's calls by it; a stub it tells by the stub's code)"""
    return isinstance(callee, ScriptFunction) or any(callee is maker for maker in _dsl_call_makers)


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
        return BinaryOp(operators.BinaryOp.ADD, self, other)

    def __radd__(self, other):
        return BinaryOp(operators.BinaryOp.ADD, other, self)

    def __sub__(self, other):
        return BinaryOp(operators.BinaryOp.SUB, self, other)

    def __rsub__(self, other):
        return BinaryOp(operators.BinaryOp.SUB, other, self)

    def __mul__(self, other):
        return BinaryOp(operators.BinaryOp.MUL, self, other)

    def __rmul__(self, other):
        return BinaryOp(operators.BinaryOp.MUL, other, self)

    def __truediv__(self, other):
        return BinaryOp(operators.BinaryOp.DIV, self, other)

    def __rtruediv__(self, other):
        return BinaryOp(operators.BinaryOp.DIV, other, self)

    def __mod__(self, other):
        return BinaryOp(operators.BinaryOp.MOD, self, other)

    def __rmod__(self, other):
        return BinaryOp(operators.BinaryOp.MOD, other, self)

    def __and__(self, other):
        return BinaryOp(operators.BinaryOp.BIT_AND, self, other)

    def __rand__(self, other):
        return BinaryOp(operators.BinaryOp.BIT_AND, other, self)

    def __or__(self, other):
        return BinaryOp(operators.BinaryOp.BIT_OR, self, other)

    def __ror__(self, other):
        return BinaryOp(operators.BinaryOp.BIT_OR, other, self)

    def __xor__(self, other):
        return BinaryOp(operators.BinaryOp.BIT_XOR, self, other)

    def __rxor__(self, other):
        return BinaryOp(operators.BinaryOp.BIT_XOR, other, self)

    def __lshift__(self, other):
        return BinaryOp(operators.BinaryOp.SHL, self, other)

    def __rlshift__(self, other):
        return BinaryOp(operators.BinaryOp.SHL, other, self)

    def __rshift__(self, other):
        return BinaryOp(operators.BinaryOp.SHR, self, other)

    def __rrshift__(self, other):
        return BinaryOp(operators.BinaryOp.SHR, other, self)

    # A literal on the left reaches these reflected (5 < x is x > 5): the same test, its operands swapped
    def __eq__(self, other):
        return BinaryOp(operators.BinaryOp.EQ, self, other)

    def __ne__(self, other):
        return BinaryOp(operators.BinaryOp.NE, self, other)

    def __lt__(self, other):
        return BinaryOp(operators.BinaryOp.LT, self, other)

    def __le__(self, other):
        return BinaryOp(operators.BinaryOp.LE, self, other)

    def __gt__(self, other):
        return BinaryOp(operators.BinaryOp.GT, self, other)

    def __ge__(self, other):
        return BinaryOp(operators.BinaryOp.GE, self, other)

    def __neg__(self):
        return UnaryOp(operators.UnaryOp.NEG, self)

    def __invert__(self):
        return UnaryOp(operators.UnaryOp.BIT_NOT, self)


# Leaves

class Const(Expr):
    """A constant, its kind its value's type: int, float, str, or a VM's own (ED9's RawInt, ed9_nodes.Raw)"""

    def __init__(self, value: int | float | str):
        self.value = value

    def __repr__(self) -> str:
        return repr(self.value)


def Int(value: int) -> Const:
    """An Integer constant, where Python would fold or mirror a bare literal: Int(8) | 16, ~Int(8), Int(9) < arg1"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise dsl_error(f'Int takes an int, not {value!r}')

    return Const(int(value))


def Float(value: float) -> Const:
    """A Float constant, where Python would fold a bare literal: Float(0.293) * 2"""
    if not isinstance(value, float):
        raise dsl_error(f'Float takes a float (2.0, not 2), not {value!r}')

    return Const(value)


def Str(value: str) -> Const:
    """A String constant, where Python would format a bare literal: Str("...") % arg1"""
    if not isinstance(value, str):
        raise dsl_error(f'Str takes a str, not {value!r}')

    return Const(value)


class Variable(Expr):
    """What Set stores into: a parameter, a local, a global, or a VM's own (ED9's register)"""


class Param(Variable):
    """A parameter of the body its build runs: position counts from 1, as arg1 does"""

    def __init__(self, build: Build, position: int, name: str):
        self.build = build
        self.position = position
        self.name = name

    def __repr__(self) -> str:
        return self.name


class Local(Variable):
    """A local variable, by name: x = Local('x'), declared in each body with Let(x) or Let(x, value)"""

    def __init__(self, name: str):
        if not isinstance(name, str) or not name:
            raise dsl_error(f'Local takes the local\'s name, not {name!r}')

        self.name = name

    def __repr__(self) -> str:
        return self.name


class Global(Variable):
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
    """A Python value as a DSL constant: an int an Integer, a float a Float, a str a String; an enum (an ID's name) its
    number; any other int kind (ED9's RawInt) as it is, for the VM to push by it"""
    if isinstance(value, bool) or value is None:
        raise dsl_error(f'{value!r} is not a DSL value: the VM has no bool or None (write 1 / 0)')

    if isinstance(value, Enum) and isinstance(value, int):
        return Const(int(value))

    if isinstance(value, (int, float, str)):
        return Const(value)

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
    def __init__(self, op: operators.BinaryOp, lhs, rhs):
        build = self.join_build(f'an operation ({op.name})')
        self.op = op
        self.lhs = claim(build, lhs, self)
        self.rhs = claim(build, rhs, self)
        self.children = (self.lhs, self.rhs)

    def __repr__(self) -> str:
        return f'({self.lhs!r} {self.op.name} {self.rhs!r})'


class UnaryOp(Composite, Expr):
    def __init__(self, op: operators.UnaryOp, operand):
        build = self.join_build(f'an operation ({op.name})')
        self.op = op
        self.operand = claim(build, operand, self)
        self.children = (self.operand,)

    def __repr__(self) -> str:
        return f'{self.op.name}({self.operand!r})'


def And(first, second, *rest) -> BinaryOp:
    """The VM's eager logical and of two or more values, left to right"""
    node = BinaryOp(operators.BinaryOp.AND, first, second)
    for value in rest:
        node = BinaryOp(operators.BinaryOp.AND, node, value)

    return node


def Or(first, second, *rest) -> BinaryOp:
    """The VM's eager logical or of two or more values, left to right"""
    node = BinaryOp(operators.BinaryOp.OR, first, second)
    for value in rest:
        node = BinaryOp(operators.BinaryOp.OR, node, value)

    return node


def Not(value) -> UnaryOp:
    """The logical not: 1 when value is 0"""
    return UnaryOp(operators.UnaryOp.NOT, value)


class Call(Composite, Expr):
    """A call: a statement when nothing uses it, else its result (the VM's result register after the call)"""

    def claim_args(self, build: Build, args: tuple, kwargs: dict):
        if kwargs:
            raise build.fail(f'{self!r} takes its arguments by position (the VM passes them so), not '
                             f'{', '.join(kwargs)}=')

        self.args = tuple(claim(build, arg, self) for arg in args)
        self.children = self.args


class LocalCall(Call):
    """A call of a script or library function: every parameter given, since a local call ignores defaults"""

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
    """script.module.name(...), a call of another script's function: the arguments as written, since a script call
    may leave out trailing defaults"""

    def __init__(self, module: str, name: str, args: tuple, kwargs: dict):
        build = self.join_build(f'script.{module}.{name}(...)')
        self.module = module
        self.name = name
        self.claim_args(build, args, kwargs)

    def __repr__(self) -> str:
        return f'script.{self.module}.{self.name}(...)'


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
        if not isinstance(target, Variable):
            raise build.fail(f'Set\'s target is a parameter, a local, this.x or REGS[n], not {target!r}')

        self.target = claim(build, target, self)
        self.value = claim(build, value, self)
        self.children = (self.value,)

    def __repr__(self) -> str:
        return f'Set({self.target!r}, ...)'


class Let(Statement):
    """Let(x) declares local x; Let(x, value) declares and stores it"""

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
    """Return(value) ends the body with value as its result; Return() with the value the VM's compiler returns (ED9: a
    Raw 0)"""

    def __init__(self, value=_MISSING):
        build = self.join_build('Return(...)')
        self.value = None if value is _MISSING else claim(build, value, self)
        self.children = () if self.value is None else (self.value,)

    def __repr__(self) -> str:
        return 'Return(...)'
