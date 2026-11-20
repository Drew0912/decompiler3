"""An HLIL body's tree (docs/dsl/HLIL_DSL.md, Form): the body run under a build of its own, a parameter node per
parameter, then its statements checked - the nodes nothing uses, each a statement; each block as its list was when its
If or While took it; each statement and each condition made in one run, the runs in the order the code runs them,
none between an If's arms; each Break and Continue in a While; every path ending only at its block's last statement,
the body's at its end; each local declared in a block before it is used there"""

from itertools import pairwise
from typing import Callable, Iterator

from .build import Build, activated
from .calls import BodyStatement
from .control import Block, BlockStatement, Break, LoopExit, While, block_ends_path, ends_path
from .nodes import Let, Local, Param, Return, Set, TrackedNode


def build_tree(build: Build, body: Callable, param_names: list[str]) -> list[BodyStatement]:
    """body's statements, in order, run under build"""
    params = [Param(build, position, name) for position, name in enumerate(param_names, 1)]
    with activated(build):
        result = body(*params)

    # A DSL error the body caught still ends the build
    if build.first_error is not None:
        raise build.first_error

    if result is not None and not isinstance(result, Return):
        raise build.fail_at(None, f'the body returned {result!r}: an HLIL body returns with Return(...)')

    statements = [node for node in build.nodes if node.parent is None]
    _require_no_unused_values(build, statements)
    _require_blocks_unchanged(build, statements)
    _require_creation_order(build, statements)
    _require_exits_in_loops(build, statements, False)
    _require_path_ends(build, statements)
    _require_declared_locals(build, statements, set(), set())
    return statements


def _require_no_unused_values(build: Build, statements: list):
    for node in statements:
        if not isinstance(node, BodyStatement):
            raise build.fail_at(node.site, f'{node!r} is computed and never used: a line of its own is a call or a '
                                           'statement')


def _require_blocks_unchanged(build: Build, statements: list):
    """Each block holds what its list held when its If or While took it: a statement added to the list later would run
    after that statement, one removed later would still run in it"""
    for block in _blocks(statements):
        for statement in block:
            if not isinstance(statement, BlockStatement):
                continue

            for (given, site), held in zip(statement.given_blocks, statement.blocks()):
                if len(given) != len(held) or any(now is not taken for now, taken in zip(given, held)):
                    owner = type(statement).__name__
                    raise build.fail_at(site, f'a block changed after its {owner} took it: the {owner} holds the list '
                                              'as it was then, so finish the list before giving it')


def units_in_code_order(statements: Block | list) -> Iterator[tuple[TrackedNode, list[TrackedNode]]]:
    """The units of statements, in the order the code runs them, each (its head, its nodes): a statement with its
    operands; for an If or a While, each condition and then its block's units, the statement's own node in none"""
    for statement in statements:
        if not isinstance(statement, BlockStatement):
            yield statement, list(_tracked_nodes(statement))
            continue

        for arm in statement.arms_in_order():
            nodes = list(_tracked_nodes(arm.condition)) if arm.condition is not None else []
            if nodes:
                yield arm.condition, nodes

            yield from units_in_code_order(arm.block)


def _tracked_nodes(node) -> Iterator[TrackedNode]:
    """node and the tracked nodes under it, in no particular order"""
    pending = [node]
    while pending:
        node = pending.pop()
        if isinstance(node, TrackedNode):
            yield node
            pending.extend(node.children)


def _require_creation_order(build: Build, statements: list):
    """Each unit's nodes were made in one run, the runs in the order the code runs the units: a node made earlier,
    kept in a Python variable and used later, would run where it is used; so would a block made before its condition.
    No statement is made between an If and its last arm outside its blocks: no code runs between arms"""
    units = list(units_in_code_order(statements))
    unit_of = {id(node): position for position, (_, nodes) in enumerate(units) for node in nodes}
    current = -1
    arms_end = 0                # where the latest arm of an If made so far ends in build.nodes
    for index, node in enumerate(build.nodes):
        if node.parent is None and index < arms_end:
            raise build.fail_at(node.site, f"{node!r} is made between an If's arms, in no block: no code runs there; "
                                           'make it before the If, after its last arm, or in a block')

        if isinstance(node, BlockStatement):
            arms_end = max(arms_end, node.arms_end)
            continue

        position = unit_of[id(node)]
        if position == current:
            continue

        if position < current:
            raise build.fail_at(node.site, f'{node!r} is made here but runs before {units[current][0]!r}, made '
                                           'earlier: a block or a value kept in a Python variable runs where it is '
                                           'used; make it there')

        if position != current + 1:
            head, expected = units[position][0], units[current + 1][0]
            if head is not node:
                raise build.fail_at(node.site, f'{node!r} is made here but used by {head!r}, after {expected!r}: it '
                                               'would run where it is used; keep a value with Let(x, value)')

            raise build.fail_at(node.site, f'{node!r} is made here but runs after {expected!r}, made later: '
                                           f'{_condition_rule(node)}')

        current = position


def _condition_rule(node: TrackedNode) -> str:
    """The rule a unit made too early breaks: a condition is tested where its If or While stands; a block's statement
    runs after its condition"""
    owner = node.parent
    if isinstance(owner, BlockStatement) and any(arm.condition is node for arm in owner.arms_in_order()):
        name = type(owner).__name__
        return f"the {name}'s condition is tested where the {name} stands: make it there"

    return 'an If or a While runs its condition before its block'


def _blocks(statements: Block | list) -> Iterator[Block | list]:
    """statements and every block inside them"""
    yield statements
    for statement in statements:
        if isinstance(statement, BlockStatement):
            for block in statement.blocks():
                yield from _blocks(block)


def _require_exits_in_loops(build: Build, block: Block | list, in_loop: bool):
    """Each Break() and Continue() stands in a While's block, at any depth"""
    for statement in block:
        if isinstance(statement, LoopExit) and not in_loop:
            raise build.fail_at(statement.site, f'{statement!r} outside a While: it leaves the innermost While holding '
                                                'it')

        if isinstance(statement, BlockStatement):
            for inner in statement.blocks():
                _require_exits_in_loops(build, inner, in_loop or isinstance(statement, While))


def _require_path_ends(build: Build, statements: list):
    for block in _blocks(statements):
        for statement, following in pairwise(block):
            if isinstance(statement, Return):
                raise build.fail_at(following.site, 'a statement after Return(...), which ends the function')

            if isinstance(statement, LoopExit):
                jump = 'leaves the loop' if isinstance(statement, Break) else "goes to the loop's next test"
                raise build.fail_at(following.site, f'a statement after {statement!r}, which {jump}: it never runs')

            if ends_path(statement):
                raise build.fail_at(following.site, 'a statement after an If whose every arm, .Else included, ends '
                                                    'its path: it never runs')

    if statements and isinstance(statements[-1], While):
        raise build.fail_at(statements[-1].site, 'the body ends with While(...), which never ends its path (the code '
                                                 'after it runs when its test is 0): end the body with Return(...)')

    if not block_ends_path(statements):
        site = statements[-1].site if statements else None
        raise build.fail_at(site, 'the body does not end with Return(...), or with an If whose every arm, .Else '
                                  'included, ends with one (a Python return stops it early)')


def _require_declared_locals(build: Build, block: Block | list, live: set[str], declared: set[str]):
    """Let declares a local in its block, before any other statement reads or sets it, once while it lives (an
    outer one too); the block's end frees it. live: the names declared and not yet freed; declared: every name
    declared so far"""
    declared_here = []
    for statement in block:
        if isinstance(statement, BlockStatement):
            for arm in statement.arms_in_order():
                if arm.condition is not None:
                    _require_live_reads(build, arm.site, (arm.condition,), live, declared)

                _require_declared_locals(build, arm.block, live, declared)

            continue

        _require_live_reads(build, statement.site, statement.children, live, declared)
        match statement:
            case Let(local=Local(name=name)):
                if name in live:
                    raise build.fail_at(statement.site, f'a second Let({name}, ...)')

                live.add(name)
                declared.add(name)
                declared_here.append(name)

            case Set(target=Local(name=name)) if name not in live:
                raise build.fail_at(statement.site, f'Set({name}, ...) after the block that declares {name} ends'
                                    if name in declared else f'Set({name}, ...) before Let({name})')

    live.difference_update(declared_here)


def _require_live_reads(build: Build, site, operands: tuple, live: set[str], declared: set[str]):
    """Each local operands read (site: the statement's or the arm's) is live"""
    for name in _locals_read(operands):
        if name not in live:
            raise build.fail_at(site, f'local {name} is read after the block that declares it ends'
                                if name in declared else f'local {name} is read before Let({name}, ...)')


def _locals_read(operands: tuple) -> list[str]:
    """The locals operands read, at any depth"""
    names = []
    pending = list(operands)
    while pending:
        node = pending.pop()
        if isinstance(node, Local):
            names.append(node.name)
        elif isinstance(node, TrackedNode):
            pending.extend(node.children)

    return names
