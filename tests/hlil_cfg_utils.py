'''Small MLIL CFGs for HLIL structuring tests, and a trace oracle that runs MLIL and HLIL side by side.

A block calls named functions and ends in a return, a goto, or an if testing a parameter or a
constant. Run for one assignment of the parameters, a function gives the calls it makes, in
order, and how it ends. Structuring must keep that for every assignment; an unstructured-jump
node may cut a run short, but only where the MLIL run jumps to the node's target.

Such a run is decided by its parameters alone, so it either ends within one visit per block or
loops forever: with FUEL well above that, both levels run out of fuel exactly when they loop.
'''
from itertools import product
from pathlib import Path
import sys
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MLILIf, MLILGoto, MLILRet, MLILConst, MLILVar, MLILCall, MLILEq
from ir.hlil.hlil import (HighLevelILFunction, HLILBlock, HLILIf, HLILWhile, HLILDoWhile, HLILSwitch, HLILBreak,
                          HLILContinue, HLILReturn, HLILUnstructured, HLILExprStmt, HLILCall, HLILConst, HLILVar,
                          HLILUnaryOp, HLILBinaryOp, UnaryOp, BinaryOp, COMPARISON_FUNCTIONS, iter_tree,
                          reachable_statements)
from ir.hlil.mlil_to_hlil import MLILToHLILConverter, constant_condition_truth
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil

FUEL = 400

# Terminals: ('ret', value), ('goto', label), ('if', condition, true label, false label); a condition is
# a parameter name, a constant, or ('==', constant, constant)
BlockSpec = Tuple[Sequence[str], tuple]

# Shapes shared by the structuring and path-check tests

# if (a == 1120 && check()) return 1; rest - the rest is the merge, reached conditionally
EARLY_EXIT = {
    'C':    ([], ('if', 'a', 'REST', 'T')),
    'T':    (['check'], ('if', 'b', 'REST', 'R1')),
    'R1':   ([], ('ret', 1)),
    'REST': (['rest'], ('ret', 0)),
}

# The self-loop at B3 is repeated in both arms; the copy holds 5 statements, 1 at top level
SHARED_LOOP = {
    'B0': (['A0'], ('if', 'p0', 'B3', 'B1')),
    'B1': (['A1'], ('if', 'p1', 'B2', 'B3')),
    'B2': (['A2'], ('ret', 2)),
    'B3': (['A3'], ('if', 'p3', 'B3', 'B2')),
}
SHARED_LOOP_COPY_STATEMENTS = 5


def _condition(cond, variables: Dict[str, object]):
    if isinstance(cond, str):
        return MLILVar(variables[cond])

    if isinstance(cond, tuple):
        return MLILEq(MLILConst(cond[1]), MLILConst(cond[2]))

    return MLILConst(cond)


def build_function(name: str, blocks: Dict[str, BlockSpec]) -> MediumLevelILFunction:
    '''An MLIL function from {label: (calls, terminal)}; the first block is the entry'''
    func = MediumLevelILFunction(name, 0)
    params = sorted({t[1] for _, t in blocks.values() if t[0] == 'if' and isinstance(t[1], str)})
    variables = {p: func.get_or_create_parameter(i + 1, p) for i, p in enumerate(params)}
    mlil_blocks = {label: func.create_block(label = label) for label in blocks}

    for label, (calls, terminal) in blocks.items():
        block = mlil_blocks[label]
        instructions = [MLILCall(call, []) for call in calls]

        if terminal[0] == 'ret':
            instructions.append(MLILRet(MLILConst(terminal[1])))

        elif terminal[0] == 'goto':
            instructions.append(MLILGoto(mlil_blocks[terminal[1]]))
            block.add_outgoing_edge(mlil_blocks[terminal[1]])

        else:
            _, cond, true_label, false_label = terminal
            instructions.append(MLILIf(_condition(cond, variables), mlil_blocks[true_label], mlil_blocks[false_label]))
            block.add_outgoing_edge(mlil_blocks[true_label])
            block.add_outgoing_edge(mlil_blocks[false_label])

        block.instructions = instructions

    func.renumber_instructions()
    return func


def to_hlil(func: MediumLevelILFunction) -> HighLevelILFunction:
    '''The final HLIL, every pass included'''
    return convert_falcom_mlil_to_hlil(func)


def structure(blocks: Dict[str, BlockSpec], **limits) -> Tuple[MediumLevelILFunction, HighLevelILFunction]:
    '''(MLIL, HLIL straight from the converter, with its clone limits overridden)'''
    func = build_function('f', blocks)
    return func, MLILToHLILConverter(func, **limits).convert()


def parameters(func: MediumLevelILFunction) -> List[str]:
    return [p.name for p in func.parameters if p is not None]


def mlil_run(func: MediumLevelILFunction, env: Dict[str, bool]) -> Tuple[tuple, tuple, set]:
    '''(calls, end, {(block label, calls made before entering it)})'''
    trace, entries, fuel = [], set(), FUEL
    block = func.basic_blocks[0]

    while fuel > 0:
        entries.add((block.label, len(trace)))
        for inst in block.instructions:
            if isinstance(inst, MLILCall):
                trace.append(inst.target)

        term = block.instructions[-1]
        fuel -= 1 + len(block.instructions)

        if isinstance(term, MLILRet):
            return tuple(trace), ('ret', term.value.value), entries

        if isinstance(term, MLILGoto):
            block = term.target
            continue

        truth = constant_condition_truth(term.condition)
        taken = truth if truth is not None else env[term.condition.var.name]
        block = term.true_target if taken else term.false_target

    return tuple(trace), ('fuel',), entries


class _Flow(Exception):
    def __init__(self, kind: str, label: Optional[str] = None, value = None):
        super().__init__(kind)
        self.kind, self.label, self.value = kind, label, value


def _value(expr, env: Dict[str, bool]):
    if isinstance(expr, HLILConst):
        return expr.value

    if isinstance(expr, HLILVar):
        return env[expr.var.name]

    if isinstance(expr, HLILUnaryOp) and expr.op == UnaryOp.NOT:
        return not _value(expr.operand, env)

    if isinstance(expr, HLILBinaryOp) and expr.op == BinaryOp.AND:
        return bool(_value(expr.lhs, env)) and bool(_value(expr.rhs, env))

    if isinstance(expr, HLILBinaryOp) and expr.op == BinaryOp.OR:
        return bool(_value(expr.lhs, env)) or bool(_value(expr.rhs, env))

    if isinstance(expr, HLILBinaryOp) and expr.op in COMPARISON_FUNCTIONS:
        return COMPARISON_FUNCTIONS[expr.op](_value(expr.lhs, env), _value(expr.rhs, env))

    raise TypeError(f'unexpected condition {expr!r}')


def _spend(state: dict):
    state['fuel'] -= 1
    if state['fuel'] <= 0:
        raise _Flow('fuel')


def _run_block(block: Optional[HLILBlock], env: Dict[str, bool], state: dict):
    for stmt in (block.statements if block is not None else []):
        if isinstance(stmt, HLILUnstructured):
            raise _Flow('unstructured', value = stmt.target)

        if isinstance(stmt, HLILExprStmt) and isinstance(stmt.expr, HLILCall):
            state['trace'].append(stmt.expr.func_name)
            _spend(state)

        elif isinstance(stmt, HLILIf):
            _run_block(stmt.true_block if _value(stmt.condition, env) else stmt.false_block, env, state)

        elif isinstance(stmt, (HLILWhile, HLILDoWhile)):
            is_while = isinstance(stmt, HLILWhile)
            while not is_while or _value(stmt.condition, env):
                _spend(state)
                try:
                    _run_block(stmt.body, env, state)

                except _Flow as flow:
                    if flow.kind not in ('break', 'continue') or flow.label not in (None, stmt.label):
                        raise

                    if flow.kind == 'break':
                        break

                # A do-while checks its condition once after each run of the body
                if not is_while and not _value(stmt.condition, env):
                    break

        elif isinstance(stmt, HLILSwitch):
            raise TypeError('switch in a test CFG')

        elif isinstance(stmt, HLILBlock):
            _run_block(stmt, env, state)

        elif isinstance(stmt, HLILBreak):
            raise _Flow('break', stmt.label)

        elif isinstance(stmt, HLILContinue):
            raise _Flow('continue', stmt.label)

        elif isinstance(stmt, HLILReturn):
            raise _Flow('ret', value = _value(stmt.value, env) if stmt.value is not None else None)


def hlil_run(hlil: HighLevelILFunction, env: Dict[str, bool]) -> Tuple[tuple, tuple]:
    '''(calls, end): ('ret', value), ('falloff',), ('fuel',), ('unstructured', target) or an escaping exit'''
    state = {'trace': [], 'fuel': FUEL}
    try:
        _run_block(hlil.body, env, state)
        return tuple(state['trace']), ('falloff',)

    except _Flow as flow:
        if flow.kind == 'fuel':
            return tuple(state['trace']), ('fuel',)

        return tuple(state['trace']), (flow.kind,) if flow.kind in ('break', 'continue') else (flow.kind, flow.value)


def classify(func: MediumLevelILFunction, hlil: HighLevelILFunction) -> Tuple[str, Optional[dict]]:
    '''('ok' | 'loud' | 'wrong', the first assignment a wrong run was found for)

    ok: every run matches MLIL. loud: every run matches or stops at a node MLIL's run jumps to.
    '''
    names = parameters(func)
    loud = False

    for bits in product((False, True), repeat = len(names)):
        env = dict(zip(names, bits))
        m_trace, m_end, entries = mlil_run(func, env)
        h_trace, h_end = hlil_run(hlil, env)

        if h_end[0] == 'unstructured':
            loud = True
            if m_trace[:len(h_trace)] != h_trace or (h_end[1], len(h_trace)) not in entries:
                return 'wrong', env

        elif m_end == ('fuel',) or h_end == ('fuel',):
            common = min(len(m_trace), len(h_trace))
            if m_end != h_end or m_trace[:common] != h_trace[:common]:
                return 'wrong', env

        elif (m_trace, m_end) != (h_trace, h_end):
            return 'wrong', env

    return ('loud' if loud else 'ok'), None


def unstructured_nodes(hlil: HighLevelILFunction, reachable_only: bool = True) -> List[HLILUnstructured]:
    statements = reachable_statements(hlil.body) if reachable_only else iter_tree(hlil.body)
    return [stmt for stmt in statements if isinstance(stmt, HLILUnstructured)]


def calls_emitted(hlil: HighLevelILFunction, name: str) -> int:
    '''How many times the HLIL text contains a call to name'''
    return sum(1 for node in iter_tree(hlil.body) if isinstance(node, HLILCall) and node.func_name == name)
