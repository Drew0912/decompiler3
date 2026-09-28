#!/usr/bin/env python3
'''Check that the final HLIL keeps every MLIL control path.

HLIL has no goto: the converter restructures the MLIL CFG into ifs, loops and switches, and
a structuring mistake either loses a path (code that stops running on some input) or invents
one (code that runs when it should not). This check compares the two levels statement by
statement:

- Anchors are MLIL effect instructions. Calls and stores (globals, registers, through a
  pointer) are mandatory: every one reachable from the entry must appear in the HLIL, a call
  as the HLIL call built from it (same kind and target - also where it folded into another
  statement or a condition), a store as an assignment to the same destination. A local
  assignment is checked where it survives and is transparent where an HLIL pass removed it
  (a temporary folded into a condition).
- Every HLIL occurrence of an anchor - each copy of a repeated region on its own - must be
  followed by exactly the anchors MLIL can run next. Conditions are walked for the calls they
  evaluate (&&, || and ! short-circuit); constant conditions follow their live arm, decided the
  same way on both levels. Returns (keyed by constant value or variable), falling off the
  function end and an unstructured-jump node are successors of their own.

Not checked: which way a condition sends control (a negated condition passes), and values
other than the return keys.

Usage:
    python tools/hlil_path_check.py <scp file or directory> [--verbose]
'''

import argparse
import contextlib
import io
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.logging import log
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.ir.llil.vm_lifter import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILInstruction, MediumLevelILExpr, MediumLevelILCall,
    MLILCall, MLILSyscall, MLILCallScript, MLILSetVar, MLILStoreGlobal, MLILStoreReg, MLILStoreDeref,
    MLILIf, MLILGoto, MLILRet, MLILDebug, MLILNop, MLILConst, MLILVar, MLILLoadGlobal, MLILLoadReg,
)
from ir.hlil.hlil import (
    HighLevelILFunction, HLILInstruction, HLILStatement, HLILExpression, HLILBlock, HLILIf, HLILWhile,
    HLILDoWhile, HLILSwitch, HLILBreak, HLILContinue, HLILReturn, HLILUnstructured, HLILAssign,
    HLILExprStmt, HLILComment, HLILConst, HLILVar, HLILDeref, HLILBinaryOp, HLILUnaryOp, HLILCall,
    HLILSyscall, HLILExternCall, VariableKind, BinaryOp, UnaryOp, constant_truth, expr_children,
    resolve_exit_target,
)
from ir.hlil.mlil_to_hlil import constant_condition_truth

START = 'START'
FALLOFF = 'FALLOFF'
MLIL_STORES = (MLILStoreGlobal, MLILStoreReg, MLILStoreDeref)
HLIL_CALLS = (HLILCall, HLILSyscall, HLILExternCall)
SHOWN_EDGES = 6


@dataclass
class PathCheckResult:
    '''Differences between one function's MLIL and HLIL control paths'''
    missing: List[Tuple] = field(default_factory = list)    # (anchor, next) MLIL has and an HLIL copy lacks
    extra: List[Tuple] = field(default_factory = list)      # (anchor, next) an HLIL copy has and MLIL lacks
    uncovered: List[int] = field(default_factory = list)    # reachable calls/stores with no reachable HLIL copy
    anchors: int = 0
    unstructured: int = 0                                   # reachable unstructured-jump nodes

    @property
    def ok(self) -> bool:
        return not (self.missing or self.extra or self.uncovered)


def is_mandatory_anchor(inst: MediumLevelILInstruction) -> bool:
    '''Calls and stores have effects outside the function: the HLIL must keep every one'''
    return isinstance(inst, (MediumLevelILCall,) + MLIL_STORES)


def is_optional_anchor(inst: MediumLevelILInstruction) -> bool:
    '''Local assignments and other expression statements: checked where they survive'''
    if isinstance(inst, (MLILIf, MLILGoto, MLILRet, MLILDebug, MLILNop)) or is_mandatory_anchor(inst):
        return False

    return isinstance(inst, (MLILSetVar, MediumLevelILExpr))


def mlil_value_key(value: Optional[MediumLevelILInstruction]) -> str:
    if value is None:
        return 'RET'

    if isinstance(value, MLILConst):
        return f'RET const {value.value!r}'

    if isinstance(value, MLILVar):
        return f'RET var {value.var.name}'

    if isinstance(value, MLILLoadGlobal):
        return f'RET global {value.index}'

    if isinstance(value, MLILLoadReg):
        return f'RET reg {value.index}'

    return 'RET ?'


class _Copy:
    '''One HLIL occurrence of an anchor: a statement, or a call inside one'''
    __slots__ = ('anchor',)

    def __init__(self, anchor: int):
        self.anchor = anchor


class _UnstructuredJump:
    '''An unstructured-jump node as a successor'''
    __slots__ = ('target',)

    def __init__(self, target: str):
        self.target = target


class _ExitTarget:
    '''A loop or switch that break (for a loop, also continue) leaves: where each one goes'''

    def __init__(self, label: Optional[str], is_switch: bool = False):
        self.label = label
        self.is_switch = is_switch
        self.after: FrozenSet = frozenset()
        self.cont: FrozenSet = frozenset()


class PathChecker:
    '''Compares one function's MLIL and final HLIL (see the module docstring)'''

    def __init__(self, mlil_func: MediumLevelILFunction, hlil_func: HighLevelILFunction):
        self.mlil_func = mlil_func
        self.hlil_func = hlil_func
        self.instructions: Dict[int, MediumLevelILInstruction] = {
            inst.inst_index: inst for block in mlil_func.basic_blocks for inst in block.instructions
        }
        self.position: Dict[int, Tuple[int, int]] = {
            inst.inst_index: (b, i) for b, block in enumerate(mlil_func.basic_blocks)
            for i, inst in enumerate(block.instructions)
        }
        # One object per HLIL node, so loop fixpoints compare equal sets
        self.copies: Dict[int, _Copy] = {}
        self.jumps: Dict[int, _UnstructuredJump] = {}
        self.successors: Dict[object, Set] = {}

    # === MLIL ===

    def mlil_successors(self, anchors: Set[int]) -> Tuple[Set[int], Dict[object, Set]]:
        '''(anchors reachable from the entry, START or anchor -> anchors / return keys run next)'''
        blocks = self.mlil_func.basic_blocks
        if not blocks:
            return set(), {START: {'RET'}}

        def next_from(b_idx: int, i: int) -> Set:
            result, seen, stack = set(), set(), [(b_idx, i)]
            while stack:
                b, j = stack.pop()
                if (b, j) in seen:
                    continue

                seen.add((b, j))
                block = blocks[b]
                if j >= len(block.instructions):
                    if b + 1 < len(blocks):
                        stack.append((b + 1, 0))
                    continue

                inst = block.instructions[j]
                if inst.inst_index in anchors:
                    result.add(inst.inst_index)

                elif isinstance(inst, MLILIf):
                    truth = constant_condition_truth(inst.condition)
                    if truth is None:
                        targets = [inst.true_target, inst.false_target]

                    else:
                        targets = [inst.true_target if truth else inst.false_target]

                    stack.extend((t.index, 0) for t in targets if t is not None)

                elif isinstance(inst, MLILGoto):
                    if inst.target is not None:
                        stack.append((inst.target.index, 0))

                elif isinstance(inst, MLILRet):
                    result.add(mlil_value_key(inst.value))

                else:
                    stack.append((b, j + 1))

            return result

        succ: Dict[object, Set] = {START: next_from(0, 0)}
        todo = [a for a in succ[START] if isinstance(a, int)]
        while todo:
            anchor = todo.pop()
            if anchor in succ:
                continue

            b, i = self.position[anchor]
            succ[anchor] = next_from(b, i + 1)
            todo.extend(a for a in succ[anchor] if isinstance(a, int) and a not in succ)

        return {a for a in succ if a != START}, succ

    # === HLIL ===

    def is_call_copy(self, node: HLILExpression) -> bool:
        '''node is the HLIL call built from the MLIL call its provenance names'''
        inst = self.instructions.get(node.mlil_index)
        if isinstance(inst, MLILCall):
            return isinstance(node, HLILCall) and node.func_name == str(inst.target)

        if isinstance(inst, MLILSyscall):
            return isinstance(node, HLILSyscall) and (node.subsystem, node.cmd) == (inst.subsystem, inst.cmd)

        if isinstance(inst, MLILCallScript):
            return isinstance(node, HLILExternCall) and node.target == f'{inst.module}:{inst.func}'

        return False

    def is_statement_copy(self, stmt: HLILStatement) -> bool:
        '''stmt writes what the MLIL store or assignment its provenance names writes'''
        inst = self.instructions.get(stmt.mlil_index)
        if isinstance(stmt, HLILExprStmt):
            return is_optional_anchor(inst) and not isinstance(inst, MLILSetVar)

        if not isinstance(stmt, HLILAssign):
            return False

        dest = stmt.dest
        if isinstance(inst, MLILSetVar):
            return isinstance(dest, HLILVar) and dest.var.kind == VariableKind.LOCAL and dest.var.name == inst.var.name

        if isinstance(inst, (MLILStoreGlobal, MLILStoreReg)):
            kind = VariableKind.GLOBAL if isinstance(inst, MLILStoreGlobal) else VariableKind.REG
            return isinstance(dest, HLILVar) and dest.var.kind == kind and dest.var.index == inst.index

        if isinstance(inst, MLILStoreDeref):
            return isinstance(dest, HLILDeref)

        return False

    def hlil_value_key(self, value: Optional[HLILExpression]) -> str:
        if value is None:
            return 'RET'

        if isinstance(value, HLILConst):
            return f'RET const {value.value!r}'

        if isinstance(value, HLILVar):
            if value.var.kind == VariableKind.GLOBAL:
                return f'RET global {value.var.index}'

            if value.var.kind == VariableKind.REG:
                return f'RET reg {value.var.index}'

            return f'RET var {value.var.name}'

        # A call folded into the return: MLIL returns the variable the call wrote
        if isinstance(value, HLIL_CALLS) and self.is_call_copy(value):
            output = self.instructions[value.mlil_index].output
            if output is not None:
                return f'RET var {output.name}'

        return 'RET ?'

    def copy_of(self, node: HLILInstruction) -> _Copy:
        key = id(node)
        if key not in self.copies:
            self.copies[key] = _Copy(node.mlil_index)
        return self.copies[key]

    def calls_in(self, expr: Optional[HLILExpression]) -> List[HLILExpression]:
        '''The anchored calls expr evaluates, in evaluation order (arguments first)'''
        found: List[HLILExpression] = []

        def walk(node: HLILExpression):
            for child in expr_children(node):
                walk(child)

            if isinstance(node, HLIL_CALLS) and self.is_call_copy(node):
                found.append(node)

        if expr is not None:
            walk(expr)

        return found

    def sequence(self, nodes: List[HLILInstruction], follow: FrozenSet) -> FrozenSet:
        '''First of running nodes in order, then follow; records each node's successors'''
        first = follow
        for node in reversed(nodes):
            copy = self.copy_of(node)
            self.successors.setdefault(copy, set()).update(first)
            first = frozenset((copy,))

        return first

    def evaluate(self, expr: Optional[HLILExpression], follow: FrozenSet) -> FrozenSet:
        '''First of evaluating expr for its value; && and || skip their right side'''
        if isinstance(expr, HLILBinaryOp) and expr.op in (BinaryOp.AND, BinaryOp.OR):
            decided = constant_truth(expr.lhs)
            skips_rhs = decided is (expr.op == BinaryOp.OR)
            after_lhs = follow if skips_rhs else self.evaluate(expr.rhs, follow)

            # A left side that can go either way may or may not evaluate the right one
            if decided is None:
                after_lhs = after_lhs | follow

            return self.sequence(self.calls_in(expr.lhs), after_lhs)

        return self.sequence(self.calls_in(expr), follow)

    def branch(self, cond: HLILExpression, on_true: FrozenSet, on_false: FrozenSet) -> FrozenSet:
        '''First of evaluating a condition, then continuing at on_true or on_false'''
        truth = constant_truth(cond)
        if truth is not None:
            return self.evaluate(cond, on_true if truth else on_false)

        if isinstance(cond, HLILBinaryOp) and cond.op == BinaryOp.AND:
            return self.branch(cond.lhs, self.branch(cond.rhs, on_true, on_false), on_false)

        if isinstance(cond, HLILBinaryOp) and cond.op == BinaryOp.OR:
            return self.branch(cond.lhs, on_true, self.branch(cond.rhs, on_true, on_false))

        if isinstance(cond, HLILUnaryOp) and cond.op == UnaryOp.NOT:
            return self.branch(cond.operand, on_false, on_true)

        return self.evaluate(cond, on_true | on_false)

    def block(self, statements: List[HLILStatement], follow: FrozenSet, targets: List[_ExitTarget]) -> FrozenSet:
        first = follow
        for stmt in reversed(statements):
            first = self.statement(stmt, first, targets)

        return first

    def statement(self, stmt: HLILStatement, follow: FrozenSet, targets: List[_ExitTarget]) -> FrozenSet:
        '''First of running stmt, then follow'''
        if isinstance(stmt, HLILUnstructured):
            return frozenset((self.jumps.setdefault(id(stmt), _UnstructuredJump(stmt.target)),))

        if isinstance(stmt, HLILComment):
            return follow

        if isinstance(stmt, (HLILAssign, HLILExprStmt)):
            nodes: List[HLILInstruction] = []
            for expr in ((stmt.dest, stmt.src) if isinstance(stmt, HLILAssign) else (stmt.expr,)):
                nodes.extend(self.calls_in(expr))

            if self.is_statement_copy(stmt):
                nodes.append(stmt)

            return self.sequence(nodes, follow)

        if isinstance(stmt, HLILReturn):
            return self.evaluate(stmt.value, frozenset((self.hlil_value_key(stmt.value),)))

        if isinstance(stmt, (HLILBreak, HLILContinue)):
            target = resolve_exit_target(targets, stmt.label, loop_only = isinstance(stmt, HLILContinue))
            if target is None:
                return frozenset((f'BAD {stmt}',))

            return target.after if isinstance(stmt, HLILBreak) else target.cont

        if isinstance(stmt, HLILIf):
            on_true = self.block(stmt.true_block.statements, follow, targets)
            on_false = self.block(stmt.false_block.statements, follow, targets) if stmt.false_block else follow
            return self.branch(stmt.condition, on_true, on_false)

        if isinstance(stmt, (HLILWhile, HLILDoWhile)):
            loop = _ExitTarget(stmt.label)
            loop.after = follow
            start: FrozenSet = frozenset()

            # Loops back onto itself: grow the loop's first set to a fixpoint
            while True:
                if isinstance(stmt, HLILWhile):
                    loop.cont = start
                    body = self.block(stmt.body.statements, start, targets + [loop])
                    new_start = self.branch(stmt.condition, body, follow)

                else:
                    loop.cont = self.branch(stmt.condition, start, follow)
                    new_start = self.block(stmt.body.statements, loop.cont, targets + [loop])

                if new_start == start:
                    return start

                start = new_start

        if isinstance(stmt, HLILSwitch):
            switch = _ExitTarget(None, is_switch = True)
            switch.after = follow
            cases: FrozenSet = frozenset()
            for case in stmt.cases:
                cases = cases | self.block(case.body.statements, follow, targets + [switch])

            if not any(case.is_default() for case in stmt.cases):
                cases = cases | follow

            return self.evaluate(stmt.scrutinee, cases)

        if isinstance(stmt, HLILBlock):
            return self.block(stmt.statements, follow, targets)

        return follow

    # === Comparison ===

    def check(self) -> PathCheckResult:
        mandatory = {i for i, inst in self.instructions.items() if is_mandatory_anchor(inst)}
        optional = {i for i, inst in self.instructions.items() if is_optional_anchor(inst)}

        self.successors[START] = set(self.block(self.hlil_func.body.statements, frozenset((FALLOFF,)), []))

        # An optional anchor counts where the HLIL kept it, on both levels
        kept = {copy.anchor for copy in self.copies.values()}
        reachable, mlil_succ = self.mlil_successors(mandatory | (optional & kept))

        def key(item) -> object:
            if isinstance(item, _Copy):
                return item.anchor

            if isinstance(item, _UnstructuredJump):
                return f'UNSTRUCTURED {item.target}'

            return item

        seen, todo = set(), [START]
        while todo:
            node = todo.pop()
            if node in seen:
                continue

            seen.add(node)
            todo.extend(t for t in self.successors.get(node, ()) if isinstance(t, _Copy))

        result = PathCheckResult(anchors = len(reachable))
        covered: Set[int] = set()
        reached_jumps: Set[_UnstructuredJump] = set()
        for node in seen:
            anchor = START if node == START else node.anchor
            if node != START:
                covered.add(anchor)

            following = self.successors.get(node, set())
            reached_jumps.update(t for t in following if isinstance(t, _UnstructuredJump))
            hlil_keys = {key(t) for t in following}
            mlil_keys = mlil_succ.get(anchor, set())
            result.missing.extend((anchor, t) for t in mlil_keys - hlil_keys)
            result.extra.extend((anchor, t) for t in hlil_keys - mlil_keys)

        result.missing = sorted(set(result.missing), key = str)
        result.extra = sorted(set(result.extra), key = str)
        result.uncovered = sorted((reachable & mandatory) - covered)
        result.unstructured = len(reached_jumps)
        return result


def check_function(mlil_func: MediumLevelILFunction, hlil_func: HighLevelILFunction) -> PathCheckResult:
    return PathChecker(mlil_func, hlil_func).check()


def check_file(path: Path) -> List[Tuple[str, Optional[PathCheckResult], Optional[str]]]:
    '''(function name, result or None, error or None) for every function in path'''
    rows = []
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        parser, functions = ScpParser.load(path, round_trip = False, keep_unreachable_code = False)

    for func in functions:
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                llil_func = ED9VMLifter(parser = parser).lift_function(func)
                mlil_func = convert_falcom_llil_to_mlil(llil_func, parser, optimize = True, infer_types = True)
                hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

            rows.append((func.name, check_function(mlil_func, hlil_func), None))

        except Exception as exc:
            rows.append((func.name, None, f'{type(exc).__name__}: {exc}'))

    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description = 'Check that the final HLIL keeps every MLIL control path')
    parser.add_argument('scp_file', help = 'Path to an SCP file, or a directory to walk')
    parser.add_argument('--verbose', action = 'store_true', help = 'List the differing edges of each failing function')
    args = parser.parse_args()

    # The pipeline logs every function it translates
    log.setLevel(logging.WARNING)

    root = Path(args.scp_file)
    paths = sorted(root.rglob('*.dat')) if root.is_dir() else [root]
    functions = failing = unstructured = 0

    for path in paths:
        for name, result, error in check_file(path):
            functions += 1
            if error is not None:
                failing += 1
                print(f'{path.name} {name}: ERROR {error}')
                continue

            unstructured += result.unstructured
            if result.ok and not result.unstructured:
                continue

            failing += not result.ok
            print(f'{path.name} {name}: missing {len(result.missing)}, extra {len(result.extra)}, '
                  f'uncovered {len(result.uncovered)}, unstructured jumps {result.unstructured}')

            if args.verbose:
                for label, edges in (('missing', result.missing), ('extra', result.extra)):
                    for anchor, target in edges[:SHOWN_EDGES]:
                        print(f'    {label} {anchor} -> {target}')

    print(f'{functions} functions, {failing} with lost or invented paths, {unstructured} reachable unstructured jumps')
    return 1 if failing or unstructured else 0


if __name__ == '__main__':
    sys.exit(main())
