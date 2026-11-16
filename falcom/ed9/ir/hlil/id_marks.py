"""The ID rule: which parameters of a file's HLIL functions hold an ID (a mark, HLILVariable.id_kind) and which int
constants are one (a tag, HLILConst.id_kind), from the game's syscall rows: the argument at an ID slot, and a constant
compared with, a switch label over or assigned to a variable that holds an ID"""

from collections import Counter, defaultdict
from itertools import pairwise
from typing import TYPE_CHECKING

from ir.hlil import *

if TYPE_CHECKING:
    from ...assembler.syscalls import SyscallArgs


EQUALITY_OPS  = frozenset({BinaryOp.EQ, BinaryOp.NE})  # The comparisons that test a variable for an ID
NEVER_WRITTEN = -1                                      # The last write's position of a variable no statement writes


class ParameterUses:
    """A function's facts about its parameters, by index: the reads of each candidate, the ID kinds of its syscall
    passes, and its passes to this file's functions as ((callee, callee index), caller's parameter index)"""

    def __init__(self):
        self.reads: Counter[int] = Counter()
        self.syscall_kinds: dict[int, list[str]] = defaultdict(list)
        self.local_passes: list[tuple[tuple[str, int], int]] = []


def collect_parameter_uses(func: HighLevelILFunction, functions: dict[str, HighLevelILFunction],
                           syscall_args: 'SyscallArgs') -> ParameterUses:
    """What func does with its parameters over its reachable statements: the reads of each one never written or
    address-taken, and its passes at ID slots and to this file's functions' parameters"""
    excluded = excluded_parameters(func.body)
    candidates = {param.name: index for index, param in enumerate(func.parameters) if param.name not in excluded}
    uses = ParameterUses()
    for stmt in reachable_statements(func.body):
        for expr in statement_expressions(stmt):
            for node in iter_tree(expr):
                _record(node, candidates, functions, syscall_args, uses)

    return uses


def _record(node: HLILInstruction, candidates: dict[str, int], functions: dict[str, HighLevelILFunction],
            syscall_args: 'SyscallArgs', uses: ParameterUses):
    """One node's part in the facts: a read of a candidate, and a syscall's or a call's arguments that are one"""
    index = parameter_index(node, candidates)
    if index is not None:
        uses.reads[index] += 1
    elif isinstance(node, HLILSyscall):
        for slot, kind in syscall_args.id_kinds(node.subsystem, node.cmd, len(node.args)).items():
            index = parameter_index(node.args[slot], candidates) if slot < len(node.args) else None
            if index is not None:
                uses.syscall_kinds[index].append(kind)
    elif isinstance(node, HLILCall) and node.func_name in functions:
        callee = functions[node.func_name]
        for slot in range(min(len(node.args), len(callee.parameters))):
            index = parameter_index(node.args[slot], candidates)
            if index is not None:
                uses.local_passes.append(((node.func_name, slot), index))


class _Candidate:
    """A parameter that may be marked: its reads, the passes satisfied so far and their ID kinds"""

    def __init__(self, reads: int):
        self.reads = reads
        self.satisfied = 0
        self.kinds: set[str] = set()


def propagate_id_marks(collected: dict[str, ParameterUses]) -> dict[tuple[str, int], str]:
    """The ID marks of a file, (function, parameter index) -> kind: a parameter is marked when every one of its reads is
    a pass of one kind, a syscall's ID slot or a marked parameter of a callee. A worklist from the syscall passes gives
    the least fixpoint: a pass to a parameter never marked never counts, and a recursive pass counts only after the
    mark it needs, which it cannot have without a satisfied read of its own"""
    candidates = {}
    waiting = defaultdict(list)  # Callee parameter -> caller parameters, one entry per pass
    for name, uses in collected.items():
        for index, reads in uses.reads.items():
            candidates[(name, index)] = _Candidate(reads)
        for callee, index in uses.local_passes:
            waiting[callee].append((name, index))

    marks = {}
    ready = []

    def satisfy(key: tuple[str, int], kind: str):
        candidate = candidates.get(key)
        if candidate is None:
            return

        candidate.satisfied += 1
        candidate.kinds.add(kind)
        if candidate.satisfied == candidate.reads and len(candidate.kinds) == 1:
            marks[key] = kind
            ready.append(key)

    for name, uses in collected.items():
        for index, kinds in uses.syscall_kinds.items():
            for kind in kinds:
                satisfy((name, index), kind)

    while ready:
        callee = ready.pop()
        for caller in waiting[callee]:
            satisfy(caller, marks[callee])

    return marks


def tag_id_constants(func: HighLevelILFunction, marked: dict[str, dict[int, str]], syscall_args: 'SyscallArgs'):
    """Tag each int constant that is exactly the argument at an ID slot: of a syscall by the rows, of a call to this
    file's function by its marks"""
    tagged = []
    for node in iter_tree(func.body):
        tagged.extend((node.args[index], kind) for index, kind in id_slot_kinds(node, marked, syscall_args).items()
                      if is_id_constant(node.args[index]))

    for const, kind in tagged:
        const.id_kind = kind


class _ComparedVariable:
    """A local's or parameter's reads for the comparison rule: its ID passes' kinds, whether a read is none of the
    rule's, its first read's and last write's statement positions, and the constants it would name"""

    def __init__(self):
        self.kinds: set[str] = set()
        self.other_read = False
        self.first_read: int | None = None
        self.last_write = NEVER_WRITTEN
        self.constants: list[HLILConst] = []

    def holds_an_id(self) -> bool:
        """Its reads are ID passes of one kind and the rule's comparisons, and no write comes at or after the first"""
        return (len(self.kinds) == 1 and not self.other_read and self.first_read is not None
                and self.last_write < self.first_read)


def tag_compared_id_constants(func: HighLevelILFunction, marked: dict[str, dict[int, str]],
                              syscall_args: 'SyscallArgs'):
    """Tag each decimal int constant compared (==, !=) with, a switch label over or assigned to a local or parameter
    that holds an ID: passed at an ID slot, of one kind; every other read one side of such a comparison or a switch
    over decimal labels only; never address-taken; no write at or after its first read in reachable_statements order
    (a condition counts at its own statement). An assigned constant the next statement overwrites unread stays a
    number. Every variable is decided before a tag is set"""
    variables = defaultdict(_ComparedVariable)
    dead = dead_constant_assignments(func.body)
    for position, stmt in enumerate(reachable_statements(func.body)):
        _record_compared_reads(stmt, position, variables, dead, marked, syscall_args)

    excluded = address_taken_names(func.body)
    tagged = [(const, next(iter(variable.kinds))) for name, variable in variables.items()
              if name not in excluded and variable.holds_an_id() for const in variable.constants]
    for const, kind in tagged:
        const.id_kind = kind


def _record_compared_reads(stmt: HLILStatement, position: int, variables: dict[str, _ComparedVariable],
                           dead: set[HLILAssign], marked: dict[str, dict[int, str]], syscall_args: 'SyscallArgs'):
    """One statement's part: its write and an assigned constant, then each local or parameter read in its own
    expressions, as an ID pass, a compared side, a switch's scrutinee or another read"""
    written = None
    name = assigned_variable(stmt)
    if name is not None:
        written = stmt.dest
        variables[name].last_write = position
        if is_id_constant(stmt.src) and stmt not in dead:
            variables[name].constants.append(stmt.src)

    passes: dict[HLILVar, str] = {}                 # A read that is an ID pass -> its kind
    compared: dict[HLILVar, list[HLILConst]] = {}   # A read compared or switched over -> those constants
    if isinstance(stmt, HLILSwitch) and variable_name(stmt.scrutinee) is not None:
        labels = [value for case in stmt.cases for value in case.values or ()]
        if all(is_id_constant(label) for label in labels):
            compared[stmt.scrutinee] = labels

    nodes = [node for expr in statement_expressions(stmt) for node in iter_tree(expr)]
    for node in nodes:
        for index, kind in id_slot_kinds(node, marked, syscall_args).items():
            if variable_name(node.args[index]) is not None:
                passes[node.args[index]] = kind
        if isinstance(node, HLILBinaryOp) and node.op in EQUALITY_OPS:
            for side, other in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if variable_name(side) is not None and is_id_constant(other):
                    compared[side] = [other]

    for node in nodes:
        name = variable_name(node)
        if name is None or node is written:
            continue

        variable = variables[name]
        if variable.first_read is None:
            variable.first_read = position
        if node in passes:
            variable.kinds.add(passes[node])
        elif node in compared:
            variable.constants.extend(compared[node])
        else:
            variable.other_read = True


def dead_constant_assignments(body: HLILBlock) -> set[HLILAssign]:
    """The assignments of a decimal int constant that the next statement of the same block overwrites without reading
    the variable (comments passed over): the compiler's int x = 0; right before a real write"""
    dead = set()
    for block in iter_tree(body):
        if not isinstance(block, HLILBlock):
            continue

        for stmt, next_stmt in pairwise(code_statements(block)):
            name = assigned_variable(stmt)
            if (name is not None and is_id_constant(stmt.src) and assigned_variable(next_stmt) == name
                    and not reads_variable(next_stmt.src, name)):
                dead.add(stmt)

    return dead


def id_slot_kinds(node: HLILInstruction, marked: dict[str, dict[int, str]],
                  syscall_args: 'SyscallArgs') -> dict[int, str]:
    """The ID slots among node's arguments, by index: a syscall's by its row, a call to this file's function by its
    marks; none for any other node"""
    if isinstance(node, HLILSyscall):
        kinds = syscall_args.id_kinds(node.subsystem, node.cmd, len(node.args))
    elif isinstance(node, HLILCall):
        kinds = marked.get(node.func_name, {})
    else:
        return {}

    return {index: kind for index, kind in kinds.items() if index < len(node.args)}


def parameter_index(expr: HLILInstruction, candidates: dict[str, int]) -> int | None:
    """The index of the candidate parameter expr reads, or None: a local or parameter of that name, not a constant"""
    return candidates.get(variable_name(expr))


def variable_name(expr: HLILInstruction) -> str | None:
    """The name of the local or parameter expr is, or None: a global, a register or any other node"""
    if isinstance(expr, HLILVar) and expr.var.kind in (VariableKind.LOCAL, VariableKind.PARAM):
        return expr.var.name

    return None


def assigned_variable(stmt: HLILStatement) -> str | None:
    """The local or parameter stmt assigns, or None: an HLILAssign to a plain variable"""
    return variable_name(stmt.dest) if isinstance(stmt, HLILAssign) else None


def reads_variable(expr: HLILExpression, name: str) -> bool:
    return any(variable_name(node) == name for node in iter_tree(expr))


def excluded_parameters(body: HLILBlock) -> set[str]:
    """The names body writes (an assignment's plain variable) or takes the address of (which *(&x) does too): the
    value they pass need not be the caller's"""
    written = {node.dest.var.name for node in iter_tree(body)
               if isinstance(node, HLILAssign) and isinstance(node.dest, HLILVar)}
    return written | address_taken_names(body)


def address_taken_names(body: HLILBlock) -> set[str]:
    """The names body takes the address of, dead code included: a pointer may change the variable unseen"""
    return {node.operand.var.name for node in iter_tree(body)
            if isinstance(node, HLILAddressOf) and isinstance(node.operand, HLILVar)}


def is_id_constant(expr: HLILExpression) -> bool:
    """An exact int written in decimal: a bool, a Raw word, a float, a string or a hex mask is no ID"""
    return isinstance(expr, HLILConst) and type(expr.value) is int and not expr.is_hex
