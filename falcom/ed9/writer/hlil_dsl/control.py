"""The HLIL DSL's control flow (docs/dsl/HLIL_DSL.md, Form): If with its .ElseIf / .Else arms, While, Break and
Continue, and the blocks If and While hold - each a Python list of the statements made for it, in order, each after
the statements a macro made for a value it uses (macro_statements.py). A statement ends its path when no code after it
runs: Return, Break, Continue, or an If with an Else whose every block ends its path; a While never does, as its test
can be 0"""

import sys
from typing import Iterator, NamedTuple

from .build import Build
from .calls import BodyStatement
from .nodes import Node, Return, Statement, TrackedNode, claim, require_build

_MISSING = object()     # an argument not given

Block = tuple[BodyStatement, ...]


class Arm(NamedTuple):
    """One of a statement's blocks: the condition tested before it (None for an If's else), the block, where its
    If(...), .ElseIf(...), .Else(...) or While(...) is, and the statements macros made for its condition, run before
    each test of it (their locals live through the arm)"""

    condition: Node | None
    block: Block
    site: object
    before: Block = ()


def claim_block(build: Build, block, owner: TrackedNode) -> Block:
    """block as one of owner's blocks: a list whose every element (block_elements) is a statement or a call of this
    build, in no block yet. A bad element is reported at its own line when it is a node of this build, else at the
    owner's"""
    if not isinstance(block, list):
        raise build.fail(f'a block is a list of statements, [...], not {block!r}')

    elements = tuple(block_elements(block))
    for element in elements:
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

    return elements


def led(statements: Block, owner: TrackedNode, build: Build) -> Block:
    """statements as owner's, each after its leading statements (those a macro made for a value it uses), in the
    order made"""
    held = []
    pending = [(statement, False) for statement in reversed(statements)]
    while pending:
        statement, leading_done = pending.pop()
        if leading_done or not statement.leading:
            statement.parent = owner
            held.append(statement)
            continue

        pending.append((statement, True))
        for leading in sorted(statement.leading, key=lambda node: node.index, reverse=True):
            if leading.parent is not None:
                raise build.fail(f'{leading!r} is in two blocks (or a block is used twice): a statement runs once, '
                                 'where it stands')

            leading.leads = statement
            pending.append((leading, False))

    return tuple(held)


def block_elements(block: list) -> Iterator:
    """block's elements in order, a list among them opened in place (a function's returned list, a macro's
    statements), at any depth, and a None skipped (a function returning nothing)"""
    for element in block:
        if isinstance(element, list):
            yield from block_elements(element)
        elif element is not None:
            yield element


def _not_a_statement(element) -> str:
    if isinstance(element, Node):
        return (f'{element!r} in a block is not a statement: each element of [...] is a call or a statement (a '
                'missing comma joins two lines into one value)')

    if isinstance(element, tuple):
        return f'{element!r} in a block is a tuple: a block holds statements and lists of them, [...]'

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
    """A statement holding blocks (If, While): the lists it was given with what it took from each, kept for the build
    to check them unchanged, and how many nodes its build held once it took its last block"""

    def join_build(self, what: str) -> Build:
        """Register in the active build, holding no block yet"""
        build = super().join_build(what)
        # Each block's list as given, the elements taken from it, and where its arm is
        self.given_blocks: list[tuple[list, Block, object]] = []
        self.arms_end = 0                   # len(build.nodes) once its last block was taken
        self.children = ()
        return build

    def arms_in_order(self) -> list[Arm]:
        """Its blocks in the order the code holds them, each with the condition tested before it"""
        raise NotImplementedError

    def blocks(self) -> list[Block]:
        return [arm.block for arm in self.arms_in_order()]

    def _take_block(self, build: Build, block, site) -> Block:
        """block as the arm's at site, each element after its leading statements. Its list is kept (the build checks
        it unchanged), the nodes made so far counted"""
        listed = claim_block(build, block, self)
        self.given_blocks.append((block, listed, site))
        self.arms_end = len(build.nodes)
        return led(listed, self, build)

    def _claim_condition(self, build: Build, condition) -> tuple[Node, Block]:
        """condition as one of its tests, and the statements macros made for it, to run before each test. A condition
        is an expression of its own: no read in the If's or While's other conditions comes before it"""
        own, self.leading = self.leading, ()
        test = claim(build, condition, self, reads=False)
        made, self.leading = self.leading, own
        before = led(tuple(sorted(made, key=lambda node: node.index)), self, build)
        for statement in made:
            statement.leads = test

        return test, before


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
        self._stand_here(build)
        return self

    def Else(self, block=_MISSING, /, *extra, **keywords) -> If:
        build = self._open_build('.Else(...)')
        if keywords:
            raise build.fail(f'.Else takes its block by position, not {', '.join(keywords)}=')

        if extra or block is _MISSING:
            raise build.fail('.Else takes one block, .Else([...]); a tested arm is .ElseIf(condition, [...])')

        self.else_block = self._take_block(build, block, build.site_of())
        self._stand_here(build)
        return self

    def arms_in_order(self) -> list[Arm]:
        if self.else_block is None:
            return list(self.arms)

        return [*self.arms, Arm(None, self.else_block, self.given_blocks[-1][2])]

    def _add_arm(self, build: Build, what: str, condition, block, extra: tuple, keywords: dict, site):
        """An arm testing condition: the statements macros made for an .ElseIf's condition run at its test; the If's
        first condition's stay before the If, run once as on the line above it"""
        _require_condition_and_block(build, what, condition, block, extra, keywords,
                                     '; the else is .Else([...]) after it')
        if self.arms:
            test, before = self._claim_condition(build, condition)
        else:
            test, before = claim(build, condition, self, reads=False), ()

        self.arms.append(Arm(test, self._take_block(build, block, site), site, before))
        self.children = tuple(arm.condition for arm in self.arms)

    def _stand_here(self, build: Build):
        """The If stands where its latest arm is added: its origin is that call's"""
        if build.body_codes:
            self.origin = build.origin(sys._getframe(2))

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
        self.condition, self.before = self._claim_condition(build, condition)
        self.block = self._take_block(build, block, self.site)
        self.children = (self.condition,)

    def arms_in_order(self) -> list[Arm]:
        return [Arm(self.condition, self.block, self.site, self.before)]

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
