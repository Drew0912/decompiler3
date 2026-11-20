"""The HLIL DSL's control flow (docs/dsl/HLIL_DSL.md, Form): If with its .ElseIf / .Else arms, and the blocks they
hold - each a Python list of the statements made for it, in order. A statement ends its path when no code after it
runs: Return, or an If with an Else whose every block ends its path"""

from typing import NamedTuple

from .build import Build
from .calls import BodyStatement
from .nodes import Node, Return, Statement, TrackedNode, claim, require_build

_MISSING = object()     # an argument not given

Block = tuple[BodyStatement, ...]


class Arm(NamedTuple):
    """One of an If's tested arms: its condition, its block, and where its If(...) or .ElseIf(...) is"""

    condition: Node
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

    if callable(element):
        name = getattr(element, '__name__', repr(element))
        return f'{name} in a block is not a statement: write {name}(...), its call'

    return f'{element!r} in a block is not a statement: each element of [...] is a call or a statement'


def ends_path(statement: BodyStatement) -> bool:
    """No code after statement runs: Return, or an If with an Else whose every block ends its path"""
    match statement:
        case Return():
            return True

        case If():
            return statement.else_block is not None and all(block_ends_path(block) for block in statement.blocks())

    return False


def block_ends_path(block: Block | list) -> bool:
    return bool(block) and ends_path(block[-1])


class If(Statement):
    """If(condition, [...]): the block runs when condition is not 0. .ElseIf(condition, [...]) and .Else([...]) add arms
    after it, each tried when the ones before were 0; each returns the If, so a chain is one statement. The chain is
    closed after .Else, and once a block holds the If"""

    def __init__(self, condition=_MISSING, block=_MISSING, /, *extra, **keywords):
        build = self.join_build('If(...)')
        self.arms: list[Arm] = []
        self.else_block: Block | None = None
        self.given_blocks: list[tuple[list, object]] = []  # each block's list as given, and where its arm is
        self.arms_end = 0                                   # len(build.nodes) once its last arm was taken
        self.children = ()
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

    def blocks(self) -> list[Block]:
        """Its blocks, in the order the code holds them"""
        blocks = [arm.block for arm in self.arms]
        return blocks if self.else_block is None else [*blocks, self.else_block]

    def _add_arm(self, build: Build, what: str, condition, block, extra: tuple, keywords: dict, site):
        if keywords:
            raise build.fail(f'{what} takes its condition and its block by position, not {', '.join(keywords)}=')

        if extra or condition is _MISSING or block is _MISSING:
            raise build.fail(f'{what} takes a condition and a block, {what}(condition, [...]); the else is '
                             '.Else([...]) after it')

        test = claim(build, condition, self)
        self.arms.append(Arm(test, self._take_block(build, block, site), site))
        self.children = tuple(arm.condition for arm in self.arms)

    def _take_block(self, build: Build, block, site) -> Block:
        """block as the arm's at site: its list kept (the build checks it unchanged), the nodes made so far counted"""
        held = claim_block(build, block, self)
        self.given_blocks.append((block, site))
        self.arms_end = len(build.nodes)
        return held

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
