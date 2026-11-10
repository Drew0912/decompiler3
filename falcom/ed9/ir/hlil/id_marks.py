"""The ID rule: which parameters of a file's HLIL functions hold an ID (a mark, HLILVariable.id_kind) and which int
constants are one (a tag, HLILConst.id_kind), from the game's syscall rows"""

from collections import Counter, defaultdict
from typing import TYPE_CHECKING

from ir.hlil import *

if TYPE_CHECKING:
    from ...assembler.ed9_syscalls import SyscallArgs


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
        if isinstance(node, HLILSyscall):
            kinds = syscall_args.id_kinds(node.subsystem, node.cmd, len(node.args))
        elif isinstance(node, HLILCall):
            kinds = marked.get(node.func_name, {})
        else:
            continue

        tagged.extend((node.args[index], kind) for index, kind in kinds.items()
                      if index < len(node.args) and is_id_constant(node.args[index]))

    for const, kind in tagged:
        const.id_kind = kind


def parameter_index(expr: HLILInstruction, candidates: dict[str, int]) -> int | None:
    """The index of the candidate parameter expr reads, or None: a local or parameter of that name, not a constant"""
    if isinstance(expr, HLILVar) and expr.var.kind in (VariableKind.LOCAL, VariableKind.PARAM):
        return candidates.get(expr.var.name)

    return None


def excluded_parameters(body: HLILBlock) -> set[str]:
    """The names body writes (an assignment's plain variable) or takes the address of (which *(&x) does too): the
    value they pass need not be the caller's"""
    names = set()
    for node in iter_tree(body):
        if isinstance(node, HLILAssign) and isinstance(node.dest, HLILVar):
            names.add(node.dest.var.name)
        elif isinstance(node, HLILAddressOf) and isinstance(node.operand, HLILVar):
            names.add(node.operand.var.name)

    return names


def is_id_constant(expr: HLILExpression) -> bool:
    """An exact int written in decimal: a bool, a Raw word, a float, a string or a hex mask is no ID"""
    return isinstance(expr, HLILConst) and type(expr.value) is int and not expr.is_hex
