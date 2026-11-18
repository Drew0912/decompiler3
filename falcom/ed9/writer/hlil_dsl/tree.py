"""An HLIL body's tree (docs/dsl/HLIL_DSL.md, Form): the body run under a build of its own, a parameter node per
parameter, then its statements checked - the nodes nothing uses, each a statement, in the order the body made them;
each statement's operands made right before it; Return(...) last; each local declared before it is used"""

from itertools import pairwise
from typing import Callable

from .build import Build, activated
from .nodes import Call, Composite, Let, Local, Param, Return, Set, Statement


def build_tree(build: Build, body: Callable, param_names: list[str]) -> list[Statement | Call]:
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
    _require_statements(build, statements)
    _require_creation_order(build)
    _require_return_last(build, statements)
    _require_declared_locals(build, statements)
    return statements


def _require_statements(build: Build, statements: list):
    for node in statements:
        if not isinstance(node, (Statement, Call)):
            raise build.fail_at(node.site, f'{node!r} is computed and never used: a line of its own is a call or a '
                                           'statement')


def _require_creation_order(build: Build):
    """The nodes of each statement were made in one run, ending at the statement: one made earlier, kept in a Python
    variable and used later would run where it is used, after the statements between"""
    statement_of = {}
    for node in reversed(build.nodes):  # a node's user is made after it
        statement_of[id(node)] = node if node.parent is None else statement_of[id(node.parent)]

    run_start = None    # the first node of the statement being made
    for node in build.nodes:
        statement = statement_of[id(node)]
        if run_start is None:
            run_start = node
        elif statement_of[id(run_start)] is not statement:
            raise build.fail_at(run_start.site, f'{run_start!r} is made here but used by '
                                                f'{statement_of[id(run_start)]!r}, after {statement!r}: it would run '
                                                'where it is used; keep a value with Let(x, value)')

        if node is statement:
            run_start = None


def _require_return_last(build: Build, statements: list):
    for statement, following in pairwise(statements):
        if isinstance(statement, Return):
            raise build.fail_at(following.site, 'a statement after Return(...), which ends the function')

    if not statements or not isinstance(statements[-1], Return):
        site = statements[-1].site if statements else None
        raise build.fail_at(site, 'the body does not end with Return(...) (a Python return stops it early)')


def _require_declared_locals(build: Build, statements: list):
    """Let declares a local once, before any other statement reads or sets it"""
    declared = set()
    for statement in statements:
        for name in _locals_read(statement):
            if name not in declared:
                raise build.fail_at(statement.site, f'local {name} is read before Let({name}, ...)')

        match statement:
            case Let(local=Local(name=name)):
                if name in declared:
                    raise build.fail_at(statement.site, f'a second Let({name}, ...)')

                declared.add(name)

            case Set(target=Local(name=name)) if name not in declared:
                raise build.fail_at(statement.site, f'Set({name}, ...) before Let({name})')


def _locals_read(statement) -> list[str]:
    """The locals statement's operands read"""
    names = []
    pending = list(statement.children)
    while pending:
        node = pending.pop()
        if isinstance(node, Local):
            names.append(node.name)
        elif isinstance(node, Composite):
            pending.extend(node.children)

    return names
