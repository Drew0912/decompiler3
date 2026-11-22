"""The HLIL DSL's nodes (docs/dsl/HLIL_DSL.md, Form): what an HLIL body's statements and expressions build while it
runs, keyed by HLIL's own operators and by the constant's value, so no VM's opcode (the calls are in calls.py, the
ED9-only nodes in ed9_nodes.py, the ED9 opcodes in lowering.py). Tracked nodes (operators, calls, statements) register
in the active build and are used once; leaves are reusable: constants, locals (by name) and globals anywhere, a
parameter only in its own body. The concrete expression classes are siblings: Python tries a right operand's
reflected operator first only when its class subclasses the left's"""

from enum import Enum

from ir.core import operators
from .build import Build, Origin, active_build, dsl_error

_MISSING = object()     # Return() and Let(x): no value given


def is_int_not_bool(value) -> bool:
    """An int the VM takes: a bool is an int to Python, not a VM value (the VM has no bool)"""
    return isinstance(value, int) and not isinstance(value, bool)


class Node:
    """Every node: Python's truth test, conversions, text, hashing, a subscript or a call on it are mistakes"""

    def __bool__(self):
        raise dsl_error(f'{self!r} has no truth value while the script compiles: Python\'s if / while / and / or / not '
                        'and a chained comparison test it; use If(...), While(...), And(...), Or(...), Not(...)')

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
        return BinaryOperation(operators.BinaryOp.ADD, self, other)

    def __radd__(self, other):
        return BinaryOperation(operators.BinaryOp.ADD, other, self)

    def __sub__(self, other):
        return BinaryOperation(operators.BinaryOp.SUB, self, other)

    def __rsub__(self, other):
        return BinaryOperation(operators.BinaryOp.SUB, other, self)

    def __mul__(self, other):
        return BinaryOperation(operators.BinaryOp.MUL, self, other)

    def __rmul__(self, other):
        return BinaryOperation(operators.BinaryOp.MUL, other, self)

    def __truediv__(self, other):
        return BinaryOperation(operators.BinaryOp.DIV, self, other)

    def __rtruediv__(self, other):
        return BinaryOperation(operators.BinaryOp.DIV, other, self)

    def __mod__(self, other):
        return BinaryOperation(operators.BinaryOp.MOD, self, other)

    def __rmod__(self, other):
        return BinaryOperation(operators.BinaryOp.MOD, other, self)

    def __and__(self, other):
        return BinaryOperation(operators.BinaryOp.BIT_AND, self, other)

    def __rand__(self, other):
        return BinaryOperation(operators.BinaryOp.BIT_AND, other, self)

    def __or__(self, other):
        return BinaryOperation(operators.BinaryOp.BIT_OR, self, other)

    def __ror__(self, other):
        return BinaryOperation(operators.BinaryOp.BIT_OR, other, self)

    def __xor__(self, other):
        return BinaryOperation(operators.BinaryOp.BIT_XOR, self, other)

    def __rxor__(self, other):
        return BinaryOperation(operators.BinaryOp.BIT_XOR, other, self)

    def __lshift__(self, other):
        return BinaryOperation(operators.BinaryOp.SHL, self, other)

    def __rlshift__(self, other):
        return BinaryOperation(operators.BinaryOp.SHL, other, self)

    def __rshift__(self, other):
        return BinaryOperation(operators.BinaryOp.SHR, self, other)

    def __rrshift__(self, other):
        return BinaryOperation(operators.BinaryOp.SHR, other, self)

    # A literal on the left reaches these reflected (5 < x is x > 5): the same test, its operands swapped
    def __eq__(self, other):
        return BinaryOperation(operators.BinaryOp.EQ, self, other)

    def __ne__(self, other):
        return BinaryOperation(operators.BinaryOp.NE, self, other)

    def __lt__(self, other):
        return BinaryOperation(operators.BinaryOp.LT, self, other)

    def __le__(self, other):
        return BinaryOperation(operators.BinaryOp.LE, self, other)

    def __gt__(self, other):
        return BinaryOperation(operators.BinaryOp.GT, self, other)

    def __ge__(self, other):
        return BinaryOperation(operators.BinaryOp.GE, self, other)

    def __neg__(self):
        return UnaryOperation(operators.UnaryOp.NEG, self)

    def __invert__(self):
        return UnaryOperation(operators.UnaryOp.BIT_NOT, self)


# Leaves

class Const(Expr):
    """A constant, its kind its value's type: int, float, str, or a VM's own (ED9's RawInt, ed9_nodes.Raw)"""

    def __init__(self, value: int | float | str):
        self.value = value

    def __repr__(self) -> str:
        return repr(self.value)


def Int(value: int) -> Const:
    """An Integer constant, where Python would fold or mirror a bare literal: Int(8) | 16, ~Int(8), Int(9) < arg1"""
    if not is_int_not_bool(value):
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


# Tracked nodes: each joins the active build, then claims its operands

class TrackedNode:
    """A node the body's run makes: registered in its build at its creation site, used once (parent)"""

    build: Build
    site: object
    parent: TrackedNode | None
    children: tuple
    index: int                  # its place in build.nodes, its creation order
    origin: Origin              # where it was made, while its build keeps it (build.py)
    leading: tuple = ()         # the statements a macro made for a value under it, run just before it
    holder = None               # what holds it among its leading: a node, or a Carried nothing used yet
    leads = None                # the statement or condition it runs just before, once that is placed
    uncarried = None            # the type of a macro's result that could not carry it
    carries = 0                 # how many macros, from the one that made it outwards, returned it with their value
    read_first = None           # the first operand it took that reads the game (not a constant)
    stands_alone = False        # a statement or a call: it may stand on a line of its own

    def join_build(self, what: str) -> Build:
        """Register in the active build (what names the node in the error when there is none)"""
        build = require_build(what)
        build.register(self)
        return build


def require_build(what: str) -> Build:
    build = active_build()
    if build is None:
        raise dsl_error(f'{what} builds an HLIL node: it is written only in an HLIL body (@scena.HLILCode())')

    return build


def as_constant(value) -> Const:
    """A Python value as a DSL constant: an int an Integer, a float a Float, a str a String; an enum (an ID's name) its
    number; any other int kind (ED9's RawInt) as it is, for the VM to push by it"""
    if isinstance(value, bool) or value is None:
        raise dsl_error(f'{value!r} is not a DSL value: the VM has no bool or None (write 1 / 0)')

    if isinstance(value, Enum) and isinstance(value, int):
        return Const(int(value))

    if isinstance(value, (int, float, str)):
        return Const(value)

    raise dsl_error(f'{value!r} ({type(value).__name__}) is not a DSL value')


def hold_leading(holder, statements: list | tuple):
    """statements run just before holder, after the ones it already holds"""
    holder.leading = (*holder.leading, *statements)
    for statement in statements:
        statement.holder = holder


def take_leading(build: Build, parent: TrackedNode, statements: list | tuple):
    """statements a macro made for one of parent's operands, run before the whole statement holding parent: refused
    when parent took an operand that reads the game before it, as that read would then come after them"""
    if statements and parent.read_first is not None:
        earlier = parent.read_first
        raise build.fail(f'{statements[0]!r}, made by a macro, would run before {earlier!r}, which this expression '
                         "takes first: a macro's statements run before the whole statement holding its value; keep "
                         f'{earlier!r} in a Let on a line before, or call the macro first')

    hold_leading(parent, statements)


class Carried(Expr):
    """A leaf a macro returned after making statements of its own: the leaf, used once, its statements run just before
    what uses it (macro_statements.py). Never in a tree: claim() takes it apart"""

    def __init__(self, leading: list, value: Node):
        self.value = value
        self.leading = ()
        self.used = False
        hold_leading(self, leading)

    def claimed_by(self, build: Build, parent: TrackedNode) -> Node:
        if self.used:
            raise build.fail(f"{self!r}, a macro's value, is used twice: the statements the macro made run once, "
                             'where the value is used; keep a value with Let(x, value) and read x')

        self.used = True
        take_leading(build, parent, self.leading)
        return self.value

    def __repr__(self) -> str:
        return repr(self.value)


def claim(build: Build, value, parent: TrackedNode, reads: bool = True) -> Node:
    """value as parent's operand: a literal becomes a constant; a tracked node is used once, in its own build; a
    parameter only in its own body; the statements a macro made for it become parent's leading ones. reads: the
    operand is read where parent runs (a Set's target and a condition of an If or a While are not, for it)"""
    operand = _claimed(build, value, parent)
    if reads and parent.read_first is None and reads_game(operand):
        parent.read_first = operand

    return operand


def reads_game(operand: Node) -> bool:
    """operand reads the game where it runs: any but a constant, or an operation that took no reading operand (whose
    place in the order the code runs things changes nothing)"""
    if isinstance(operand, Const):
        return False

    if isinstance(operand, (BinaryOperation, UnaryOperation)):
        return operand.read_first is not None

    return True


def _claimed(build: Build, value, parent: TrackedNode) -> Node:
    if isinstance(value, Carried):
        value = value.claimed_by(build, parent)

    if isinstance(value, Param):
        if value.build is not build:
            raise build.fail(f'{value.name} belongs to {value.build.function_name}\'s body; to keep a value between '
                             f'functions, store it in a global: Set(this.name, {value.name})')

        return value

    if isinstance(value, Statement):
        raise build.fail(f'{value!r} is a statement, not a value')

    if isinstance(value, TrackedNode):
        if value.build is not build:
            raise build.fail(f'{value!r} was made in another HLIL body (or outside one) and kept: a node is used in '
                             'the body that makes it')

        if value.parent is not None:
            raise build.fail(f'{value!r} is used twice: a call or an operation runs once, where it is used; keep a '
                             'value with Let(x, value) and read x')

        value.parent = parent
        if value.leading:
            take_leading(build, parent, value.leading)
            value.leading = ()

        return value

    if isinstance(value, Node):
        return value

    return as_constant(value)


def _claim_if_given(build: Build, value, parent: TrackedNode) -> Node | None:
    """claim(value), None when Let or Return got no value"""
    return None if value is _MISSING else claim(build, value, parent)


class BinaryOperation(TrackedNode, Expr):
    def __init__(self, op: operators.BinaryOp, lhs, rhs):
        build = self.join_build(f'an operation ({op.name})')
        self.op = op
        self.lhs = claim(build, lhs, self)
        self.rhs = claim(build, rhs, self)
        self.children = (self.lhs, self.rhs)

    def __repr__(self) -> str:
        return f'({self.lhs!r} {self.op.name} {self.rhs!r})'


class UnaryOperation(TrackedNode, Expr):
    def __init__(self, op: operators.UnaryOp, operand):
        build = self.join_build(f'an operation ({op.name})')
        self.op = op
        self.operand = claim(build, operand, self)
        self.children = (self.operand,)

    def __repr__(self) -> str:
        return f'{self.op.name}({self.operand!r})'


def And(first, second, *rest) -> BinaryOperation:
    """The VM's eager logical and of two or more values, left to right"""
    return _left_fold(operators.BinaryOp.AND, first, second, rest)


def Or(first, second, *rest) -> BinaryOperation:
    """The VM's eager logical or of two or more values, left to right"""
    return _left_fold(operators.BinaryOp.OR, first, second, rest)


def _left_fold(op: operators.BinaryOp, first, second, rest: tuple) -> BinaryOperation:
    node = BinaryOperation(op, first, second)
    for value in rest:
        node = BinaryOperation(op, node, value)

    return node


def Not(value) -> UnaryOperation:
    """The logical not: 1 when value is 0"""
    return UnaryOperation(operators.UnaryOp.NOT, value)


# Statements

class Statement(TrackedNode, Node):
    """A statement: used by nothing, it stands where it was made"""

    stands_alone = True


class Set(Statement):
    """Set(target, value): stores value in a parameter, a local, this.x or REGS[n]"""

    def __init__(self, target, value):
        build = self.join_build('Set(...)')
        if isinstance(target, Carried):
            target = target.claimed_by(build, self)

        if not isinstance(target, Variable):
            raise build.fail(f'Set\'s target is a parameter, a local, this.x or REGS[n], not {target!r}')

        self.target = claim(build, target, self, reads=False)
        self.value = claim(build, value, self)
        self.children = (self.value,)

    def __repr__(self) -> str:
        return f'Set({self.target!r}, ...)'


class Let(Statement):
    """Let(x) declares local x; Let(x, value) declares and stores it"""

    def __init__(self, local, value=_MISSING):
        build = self.join_build('Let(...)')
        if isinstance(local, Carried):
            local = local.claimed_by(build, self)

        if not isinstance(local, Local):
            raise build.fail(f'Let declares a local (x = Local(\'x\')), not {local!r}')

        self.local = local
        self.value = _claim_if_given(build, value, self)
        self.children = () if self.value is None else (self.value,)

    def __repr__(self) -> str:
        return f'Let({self.local!r}, ...)'


class Return(Statement):
    """Return(value) ends the body with value as its result; Return() with the value the VM's compiler returns (ED9: a
    Raw 0)"""

    def __init__(self, value=_MISSING):
        build = self.join_build('Return(...)')
        self.value = _claim_if_given(build, value, self)
        self.children = () if self.value is None else (self.value,)

    def __repr__(self) -> str:
        return 'Return(...)'
