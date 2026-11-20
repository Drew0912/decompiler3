"""The HLIL DSL's control flow (docs/dsl/HLIL_DSL.md, Form): If with its .ElseIf / .Else arms, While, Break and
Continue, and the blocks If and While hold - each a Python list of the statements made for it, in order. A statement
ends its path when no code after it runs: Return, Break, Continue, or an If with an Else whose every block ends its
path; a While never does, as its test can be 0"""

from typing import NamedTuple

from .build import Build
from .calls import BodyStatement
from .nodes import Node, Return, Statement, TrackedNode, claim, require_build

_MISSING = object()     # an argument not given

Block = tuple[BodyStatement, ...]


class Arm(NamedTuple):
    """One of a statement's blocks: the condition tested before it (None for an If's else), the block, and where its
    If(...), .ElseIf(...), .Else(...) or While(...) is"""

    condition: Node | None
    block: Block
    site: object


def claim_block(build: Build, block, owner: TrackedNode) -> Block:
    """block as one of owner's blocks: a list whose every element is a statement or a call of this build, in no block
    yet. A bad element is reported at its own line when it is a node of this build, else at the owner's"""
    if not isinstance(block, list):
        raise build.fail(f'a block is a list of statements, [...], not {block!r}')

    for element in block:
        if not isinstance(element, BodyStatement):
            own = isinstance(element, TrackedNode) and element.build is build
            raise build.fail_at(element.site if own else build.site_of(), _not_a_statement(element))

        if element.build is not build:
            raise build.fail(f'{element!r} was made in another HLIL body (or outside one) and kept: a statement stands '
                             'in the body that makes it')

        if element.parent is not None or element is owner:
            raise build.fail(f'{element!r} is in two blocks (or a block is used twice): a statement runs once, where '
                             'it stands')

        element.parent = owner

    return tuple(block)


def _not_a_statement(element) -> str:
    if isinstance(element, Node):
        return (f'{element!r} in a block is not a statement: each element of [...] is a call or a statement (a '
                'missing comma joins two lines into one value)')

    if isinstance(element, type) and issubclass(element, LoopExit):
        return f'{element.__name__} in a block is not a statement: write {element.__name__}(), its call'

    if callable(element):
        name = getattr(element, '__name__', repr(element))
        return f'{name} in a block is not a statement: write {name}(...), its call'

    return f'{element!r} in a block is not a statement: each element of [...] is a call or a statement'


def ends_path(statement: BodyStatement) -> bool:
    """No code after statement runs: Return, Break, Continue, or an If with an Else whose every block ends its path"""
    match statement:
        case Return() | LoopExit():
            return True

        case If():
            return statement.else_block is not None and all(block_ends_path(block) for block in statement.blocks())

    return False


def block_ends_path(block: Block | list) -> bool:
    return bool(block) and ends_path(block[-1])


class BlockStatement(Statement):
    """A statement holding blocks (If, While): the lists it was given, kept for the build to check them unchanged, and
    how many nodes its build held once it took its last block"""

    def join_build(self, what: str) -> Build:
        """Register in the active build, holding no block yet"""
        build = super().join_build(what)
        self.given_blocks: list[tuple[list, object]] = []  # each block's list as given, and where its arm is
        self.arms_end = 0                                   # len(build.nodes) once its last block was taken
        self.children = ()
        return build

    def arms_in_order(self) -> list[Arm]:
        """Its blocks in the order the code holds them, each with the condition tested before it"""
        raise NotImplementedError

    def blocks(self) -> list[Block]:
        return [arm.block for arm in self.arms_in_order()]

    def _take_block(self, build: Build, block, site) -> Block:
        """block as the arm's at site: its list kept (the build checks it unchanged), the nodes made so far counted"""
        held = claim_block(build, block, self)
        self.given_blocks.append((block, site))
        self.arms_end = len(build.nodes)
        return held


def _require_condition_and_block(build: Build, what: str, condition, block, extra: tuple, keywords: dict, tail: str):
    """what's arguments are a condition and a block, by position; tail ends the message about any others"""
    if keywords:
        raise build.fail(f'{what} takes its condition and its block by position, not {', '.join(keywords)}=')

    if extra or condition is _MISSING or block is _MISSING:
        raise build.fail(f'{what} takes a condition and a block, {what}(condition, [...]){tail}')


class If(BlockStatement):
    """If(condition, [...]): the block runs when condition is not 0. .ElseIf(condition, [...]) and .Else([...]) add arms
    after it, each tried when the ones before were 0; each returns the If, so a chain is one statement. The chain is
    closed after .Else, and once a block holds the If"""

    def __init__(self, condition=_MISSING, block=_MISSING, /, *extra, **keywords):
        build = self.join_build('If(...)')
        self.arms: list[Arm] = []
        self.else_block: Block | None = None
        self._add_arm(build, 'If', condition, block, extra, keywords, self.site)

    def ElseIf(self, condition=_MISSING, block=_MISSING, /, *extra, **keywords) -> If:
        build = self._open_build('.ElseIf(...)')
        self._add_arm(build, '.ElseIf', condition, block, extra, keywords, build.site_of())
        return self

    def Else(self, block=_MISSING, /, *extra, **keywords) -> If:
        build = self._open_build('.Else(...)')
        if keywords:
            raise build.fail(f'.Else takes its block by position, not {', '.join(keywords)}=')

        if extra or block is _MISSING:
            raise build.fail('.Else takes one block, .Else([...]); a tested arm is .ElseIf(condition, [...])')

        self.else_block = self._take_block(build, block, build.site_of())
        return self

    def arms_in_order(self) -> list[Arm]:
        if self.else_block is None:
            return list(self.arms)

        return [*self.arms, Arm(None, self.else_block, self.given_blocks[-1][1])]

    def _add_arm(self, build: Build, what: str, condition, block, extra: tuple, keywords: dict, site):
        _require_condition_and_block(build, what, condition, block, extra, keywords,
                                     '; the else is .Else([...]) after it')
        test = claim(build, condition, self)
        self.arms.append(Arm(test, self._take_block(build, block, site), site))
        self.children = tuple(arm.condition for arm in self.arms)

    def _open_build(self, what: str) -> Build:
        """The If's build, for an arm added after the If is made: the chain still open"""
        build = require_build(what)
        if build is not self.build:
            raise build.fail(f'{what} on an If made in another HLIL body (or outside one): an If is used in the body '
                             'that makes it')

        if self.else_block is not None:
            raise build.fail(f'{what} after .Else(...), the last arm')

        if self.parent is not None:
            raise build.fail(f'{what} on an If already in a block: an If takes its arms before it is used')

        return build

    def __repr__(self) -> str:
        return 'If(...)'


class While(BlockStatement):
    """While(condition, [...]): the block runs while condition is not 0, tested before each run; Break() leaves it,
    Continue() goes to its next test"""

    def __init__(self, condition=_MISSING, block=_MISSING, /, *extra, **keywords):
        build = self.join_build('While(...)')
        _require_condition_and_block(build, 'While', condition, block, extra, keywords,
                                     ' (the DSL has no loop else)')
        self.condition = claim(build, condition, self)
        self.block = self._take_block(build, block, self.site)
        self.children = (self.condition,)

    def arms_in_order(self) -> list[Arm]:
        return [Arm(self.condition, self.block, self.site)]

    def __repr__(self) -> str:
        return 'While(...)'


class LoopExit(Statement):
    """Break() or Continue(): a jump out of the innermost While holding it, past its end or to its next test, the
    locals of the blocks it leaves popped first"""

    def __init__(self, *arguments, **keywords):
        build = self.join_build(f'{type(self).__name__}()')
        if arguments or keywords:
            raise build.fail(f'{type(self).__name__}() takes no arguments: it leaves the innermost While holding it')

        self.children = ()

    def __repr__(self) -> str:
        return f'{type(self).__name__}()'


class Break(LoopExit):
    """Break(): leaves the innermost While holding it"""


class Continue(LoopExit):
    """Continue(): goes to the next test of the innermost While holding it"""
