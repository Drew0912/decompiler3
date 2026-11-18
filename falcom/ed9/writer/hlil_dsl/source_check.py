"""The source check (docs/dsl/HLIL_DSL.md, Python traps): what Python does before the DSL sees it, read in the source of
an HLIL body - and of each helper and wrapper it runs - before its nodes are lowered. A problem at its line:
- a Python variable given a value holding a call: the call runs where the variable is used, after the arguments to
  its right, not where it is written. In a body any call but Local(...) and the constant constructors counts; in a
  helper only a call of the DSL's (a function's stub, Syscall, script.module.name), looked up in its globals, since a
  helper computes Python values too;
- / or % between two literals: Python computes it by its own rules (its / always gives a Float, its % floors), not
  by the VM's DIV and MOD, which truncate.
A body's own source, its innermost function, also may not:
- bind a parameter's or a local's name (=, for, with, except, import, def, match, del): that rebinds the Python name,
  not the game's variable;
- test a parameter or a local with is / is not, which compares Python objects (the VM has no None);
- return other than return Return(...): what follows the return is never built.
Nested defs and lambdas count for all but the returns, which are their own"""

import ast
import builtins
import inspect
import linecache
from types import CodeType
from typing import Callable, Iterable, Iterator, NamedTuple

from .calls import makes_dsl_call
from .stubs import STUB_CODE

# The calls a body's Python variable may hold: each makes a leaf (a constant or a local), nothing that runs in the game
LEAF_CONSTRUCTORS = ('Local', 'Int', 'Float', 'Str', 'Raw', 'FloatWord', 'RawInt')
LITERAL_WRAPPERS = {int: 'Int', float: 'Float', str: 'Str'}
# Python's operators on two literals whose rule is not the VM's: (symbol, the VM's opcode, Python's rule)
LITERAL_OPERATIONS = {ast.Div: ('/', 'DIV', 'its / always gives a Float'), ast.Mod: ('%', 'MOD', 'its % floors')}
NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
INDENTED_SOURCE_PREFIX = 'if 1:\n'     # makes an indented def (in a class or a function) parse on its own


class SourceProblem(NamedTuple):
    """A problem in a body's or a helper's source, at its line"""

    line: int
    text: str


def body_problem(code: CodeType) -> SourceProblem | None:
    """The first problem in a body's own source, as (file line, text), or None; an unreadable source is one"""
    try:
        function, line_offset = _parsed(code)
    except (OSError, SyntaxError) as e:
        return SourceProblem(code.co_firstlineno,
                             f"an HLIL body's source is checked before it runs; this one can't be read ({e})")

    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return SourceProblem(code.co_firstlineno, 'an HLIL body is a def')

    return parsed_body_problem(function, line_offset)


def parsed_body_problem(function: ast.FunctionDef, line_offset: int = 0) -> SourceProblem | None:
    """body_problem for a body's def already parsed (the decompiler's exact check parses the text it prints), its
    lines numbered from line_offset + 1"""
    return _earliest_problem(_body_problems(function), line_offset)


def helper_problem(code: CodeType, names: dict) -> SourceProblem | None:
    """The first problem in a helper's or a wrapper's source (names: its globals), or None; an unreadable source,
    or one that is no def, is not checked"""
    try:
        function, line_offset = _parsed(code)
    except (OSError, SyntaxError):
        return None

    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None

    nodes = _walk(function.body, into_nested=True)
    problems = _kept_call_or_literal_problems(nodes, lambda call: _is_dsl_call(call, names))
    return _earliest_problem(problems, line_offset)


def _parsed(code: CodeType) -> tuple[ast.stmt, int]:
    """The def code runs, parsed alone, and the number to add to its line numbers for the file's"""
    # The lines inspect.getsourcelines(code) reads, without its inspect.getmodule, which scans every loaded module
    first_line = code.co_firstlineno
    linecache.checkcache(code.co_filename)
    lines = linecache.getlines(code.co_filename)[first_line - 1:]
    if not lines:
        raise OSError(f'{code.co_filename} has no line {first_line}')

    source = ''.join(inspect.getblock(lines))
    if not source[:1].isspace():
        return ast.parse(source).body[0], first_line - 1

    prefix_lines = INDENTED_SOURCE_PREFIX.count('\n')
    return ast.parse(INDENTED_SOURCE_PREFIX + source).body[0].body[0], first_line - 1 - prefix_lines


def _earliest_problem(problems: Iterator[SourceProblem], line_offset: int) -> SourceProblem | None:
    """The problem at the smallest line (the first found there), its line counted in the file"""
    earliest = min(problems, key=lambda problem: problem.line, default=None)
    return None if earliest is None else SourceProblem(earliest.line + line_offset, earliest.text)


def _body_problems(function: ast.FunctionDef) -> Iterator[SourceProblem]:
    nodes = list(_walk(function.body, into_nested=True))
    variables, declaring_targets = _game_variables(function, nodes)
    yield from _kept_call_or_literal_problems(nodes, lambda call: not _is_call_to(call, *LEAF_CONSTRUCTORS))
    for node in nodes:
        yield from _rebinding_problems(node, variables, declaring_targets)
        yield from _identity_test_problems(node, variables)

    yield from _early_return_problems(function)


def _game_variables(function: ast.FunctionDef, nodes: list[ast.AST]) -> tuple[set[str], set[int]]:
    """The names that stand for the game's variables, the parameters and the locals x = Local('x') declares, and the
    id() of each declaring target"""
    params = {arg.arg for arg in function.args.posonlyargs + function.args.args}
    declarations = [node for node in nodes if isinstance(node, ast.Assign) and _is_call_to(node.value, 'Local')]
    local_names = {target.id for node in declarations for target in node.targets if isinstance(target, ast.Name)}
    declaring_targets = {id(target) for node in declarations for target in node.targets}
    return params | local_names, declaring_targets


def _rebinding_problems(node: ast.AST, variables: set[str], declaring_targets: set[int]) -> Iterator[SourceProblem]:
    for name in _bound_names(node):
        if name in variables and id(node) not in declaring_targets:
            yield SourceProblem(node.lineno, f'{name} = ... rebinds the Python name, not the game\'s {name}: write '
                                             f'Set({name}, value)')


def _identity_test_problems(node: ast.AST, variables: set[str]) -> Iterator[SourceProblem]:
    if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops) \
            and any(isinstance(operand, ast.Name) and operand.id in variables
                    for operand in [node.left, *node.comparators]):
        yield SourceProblem(node.lineno, f'{ast.unparse(node)}: is compares Python objects, never the game\'s value '
                                         '(the VM has no None); compare with == or !=')


def _early_return_problems(function: ast.FunctionDef) -> Iterator[SourceProblem]:
    """The body's own returns (a nested def's are its own) but return Return(...)"""
    for node in _walk(function.body, into_nested=False):
        if isinstance(node, ast.Return) and not _is_call_to(node.value, 'Return'):
            yield SourceProblem(node.lineno, 'return stops the body here, and what follows is never built: an HLIL '
                                             'body ends with Return(...) (return Return(...) is the one return it '
                                             'takes)')


def _kept_call_or_literal_problems(nodes: Iterable[ast.AST],
                                   runs_in_game: Callable[[ast.Call], bool]) -> Iterator[SourceProblem]:
    """What a body and a helper are both checked for, in nodes (a def's body, nested defs included): a call that runs
    in the game kept in a Python variable, and / or % on literals"""
    for node in nodes:
        yield from _kept_call_problems(node, runs_in_game)
        yield from _literal_operation_problems(node)


def _kept_call_problems(node: ast.AST, runs_in_game: Callable[[ast.Call], bool]) -> Iterator[SourceProblem]:
    targets, value = _assignment(node)
    # this.x = ... and REGS[n] = ... raise when they run, naming Set
    if value is not None and _only_names(targets) \
            and any(isinstance(call, ast.Call) and runs_in_game(call) for call in _walk([value], into_nested=False)):
        yield SourceProblem(node.lineno, f'{ast.unparse(node)}: a call kept in a Python variable runs where the '
                                         'variable is used, after the arguments to its right, not here; keep its '
                                         'value with Let(x, value), or make the call where its value is used')


def _literal_operation_problems(node: ast.AST) -> Iterator[SourceProblem]:
    if isinstance(node, ast.BinOp) and type(node.op) in LITERAL_OPERATIONS and _is_literal(node.left) \
            and _is_literal(node.right):
        yield SourceProblem(node.lineno, _literal_operation_text(node))


def _walk(nodes: list[ast.AST], into_nested: bool) -> Iterator[ast.AST]:
    """Every node under nodes; into nested defs, lambdas and classes only if into_nested"""
    pending = list(nodes)
    while pending:
        node = pending.pop()
        yield node
        pending.extend(child for child in ast.iter_child_nodes(node)
                       if into_nested or not isinstance(child, NESTED_SCOPES))


def _assignment(node: ast.AST) -> tuple[list[ast.expr], ast.expr | None]:
    """An assignment's targets and value, else ([], None)"""
    match node:
        case ast.Assign():
            return node.targets, node.value

        case ast.AnnAssign() | ast.AugAssign() | ast.NamedExpr():
            return [node.target], node.value

    return [], None


def _bound_names(node: ast.AST) -> list[str]:
    """The Python names node binds itself (an assignment's targets are its Name nodes, each its own node here)"""
    match node:
        case ast.Name(ctx=ast.Store() | ast.Del()):
            return [node.id]

        case ast.ExceptHandler(name=str()) | ast.MatchAs(name=str()) | ast.MatchStar(name=str()):
            return [node.name]

        case ast.MatchMapping(rest=str()):
            return [node.rest]

        case ast.alias():
            return [node.asname or node.name.split('.')[0]]

        case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.ClassDef():
            return [node.name]

    return []


def _only_names(targets: list[ast.expr]) -> bool:
    """Every target a Python name (or a tuple of them), none an attribute or a subscript (ast.walk also visits each
    name's Store context)"""
    return all(isinstance(node, (ast.Name, ast.Tuple, ast.List, ast.Starred, ast.Store))
               for target in targets for node in ast.walk(target))


def _is_call_to(value: ast.expr | None, *names: str) -> bool:
    return isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in names


def _is_dsl_call(call: ast.Call, names: dict) -> bool:
    """call's callee, looked up in names, is a function's stub, Syscall or script.module.name"""
    callee = _resolved(call.func, names)
    return getattr(callee, '__code__', None) is STUB_CODE or makes_dsl_call(callee)


def _resolved(node: ast.expr, names: dict):
    """The object a name or a dotted name stands for, None when it can't be told"""
    match node:
        case ast.Name():
            return names.get(node.id, getattr(builtins, node.id, None))

        case ast.Attribute():
            owner = _resolved(node.value, names)
            return None if owner is None else getattr(owner, node.attr, None)

    return None


def _is_literal(node: ast.expr) -> bool:
    """A value Python computes before the DSL sees it: a constant, or operators on constants only"""
    match node:
        case ast.Constant():
            return True

        case ast.UnaryOp():
            return _is_literal(node.operand)

        case ast.BinOp():
            return _is_literal(node.left) and _is_literal(node.right)

    return False


def _literal_operation_text(node: ast.BinOp) -> str:
    symbol, opcode, python_rule = LITERAL_OPERATIONS[type(node.op)]
    left = f'{_literal_wrapper_name(node)}({ast.unparse(node.left)})'
    return (f'{ast.unparse(node)}: Python computes it ({python_rule}), not the VM\'s {opcode}, which truncates; write '
            f'{left} {symbol} {ast.unparse(node.right)} for the VM\'s operation, or the value')


def _literal_wrapper_name(node: ast.BinOp) -> str:
    """The constructor node's left literal is written in: its constant's own, Int for a computed one"""
    if isinstance(node.left, ast.Constant):
        return LITERAL_WRAPPERS.get(type(node.left.value), 'Int')

    return 'Int'
