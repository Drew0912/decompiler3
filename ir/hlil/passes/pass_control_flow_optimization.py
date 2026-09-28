'''Control Flow Optimization Pass'''

from enum import Enum, auto
from typing import List, NamedTuple, Optional, Tuple
from ir.core import constant_values_equal
from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILStatement,
    HLILExpression,
    HLILVar,
    HLILConst,
    HLILBinaryOp,
    HLILUnaryOp,
    HLILDeref,
    HLILIf,
    HLILWhile,
    HLILDoWhile,
    HLILSwitch,
    HLILSwitchCase,
    HLILAssign,
    HLILExprStmt,
    HLILReturn,
    HLILBreak,
    HLILContinue,
    HLILComment,
    HLILUnstructured,
    HLILVariable,
    VariableKind,
    BinaryOp,
    UnaryOp,
    unwrap_address_taken_var,
    contains_bare_break,
    is_boolean_expr,
    iter_tree,
    read_children,
    sole_statement,
    sub_blocks,
    NEGATED_COMPARISON_OP,
)


# Below this a chain reads better as if/else-if than as a switch
SWITCH_MIN_CASES = 3


class ExitKind(Enum):
    '''How a path leaves the node being analyzed. A return leaves the function and is never
    absorbed by anything; a break/continue is absorbed by whichever construct owns it and
    rejoins at a real location, so it must survive until that owner is reached.'''

    RETURN = auto()
    BREAK = auto()
    CONTINUE = auto()


class ExitPath(NamedTuple):
    '''One non-local exit, and what var's killed-state was where it happens.

    label is None for a bare break/continue (owned by the nearest enclosing loop, or for a
    break the nearest enclosing switch); otherwise it names the loop it belongs to, which
    may be several levels out, so the exit passes through everything in between unchanged.
    '''

    kind: ExitKind
    label: Optional[str]
    killed: bool


class ControlFlowOptimizationPass(Pass):
    '''Control flow optimizations: if-to-switch (absorbing a switch already built from the rest of the chain),
    empty-if inversion, else-if flattening'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._func_body = func.body
        self._optimize_block(func.body)
        return func

    def _optimize_block(self, block: HLILBlock):
        if not block or not block.statements:
            return

        optimized = []
        i = 0

        while i < len(block.statements):
            stmt = block.statements[i]

            # Try inline: [nop*, assign, if] -> [nop*, if(bool_expr)]
            if isinstance(stmt, HLILAssign) and isinstance(stmt.dest, HLILVar):
                if is_boolean_expr(stmt.src):
                    if i + 1 < len(block.statements):
                        next_stmt = block.statements[i + 1]
                        inlined = self._try_inline_condition(stmt, next_stmt)
                        if inlined:
                            # Recursively optimize the inlined if's sub-blocks
                            for child in sub_blocks(inlined):
                                self._optimize_block(child)

                            # Remove redundant assignments
                            self._remove_redundant_else_assign(inlined, optimized)
                            optimized.append(inlined)
                            i += 2
                            continue

            # Skip nop to find [assign, if] pattern for inlining
            if self._is_nop_stmt(stmt):
                # Look ahead for [assign, if] pattern
                j = i + 1
                while j < len(block.statements) and self._is_nop_stmt(block.statements[j]):
                    j += 1

                if j < len(block.statements) - 1:
                    assign_stmt = block.statements[j]
                    if_stmt = block.statements[j + 1]
                    if isinstance(assign_stmt, HLILAssign) and isinstance(assign_stmt.dest, HLILVar):
                        if is_boolean_expr(assign_stmt.src):
                            inlined = self._try_inline_condition(assign_stmt, if_stmt)
                            if inlined:
                                # Collect leading nops
                                for k in range(i, j):
                                    optimized.append(block.statements[k])

                                for child in sub_blocks(inlined):
                                    self._optimize_block(child)

                                # Remove redundant assignments
                                self._remove_redundant_else_assign(inlined, optimized)
                                optimized.append(inlined)
                                i = j + 2
                                continue

            for child in sub_blocks(stmt):
                self._optimize_block(child)

            if isinstance(stmt, HLILIf):
                # Remove redundant var = source in else block for switch-case patterns
                self._remove_redundant_else_assign(stmt, optimized)

                # Convert nested if-chain to switch
                switch_stmt = self._try_convert_to_switch(stmt)
                if switch_stmt:
                    optimized.append(switch_stmt)
                    i += 1
                    continue

                # Invert empty if: if (c) {} else {...} -> if (!c) {...}
                # But skip if else block is [nop*, if] to preserve else-if chain
                if not stmt.true_block.statements and stmt.false_block and stmt.false_block.statements:
                    if not isinstance(sole_statement(stmt.false_block), HLILIf):
                        stmt.condition = self._negate_condition(stmt.condition)
                        stmt.true_block = stmt.false_block
                        stmt.false_block = None

            optimized.append(stmt)
            i += 1

        block.statements = optimized

    def _try_inline_condition(self, assign_stmt: HLILAssign, next_stmt: HLILStatement) -> Optional[HLILIf]:
        '''
        Try to inline: var = bool_expr; if (var != 0) {...} -> if (bool_expr) {...}
        Returns new HLILIf if successful, None otherwise.
        '''
        if not isinstance(next_stmt, HLILIf):
            return None

        cond = next_stmt.condition
        if not isinstance(cond, HLILBinaryOp):
            return None

        if cond.op not in (BinaryOp.EQ, BinaryOp.NE):
            return None

        if not isinstance(cond.rhs, HLILConst) or cond.rhs.value != 0:
            return None

        if not isinstance(cond.lhs, HLILVar):
            return None

        assigned_var = assign_stmt.dest.var
        if cond.lhs.var != assigned_var:
            return None

        # Globals are shared-state writes (matches _remove_redundant_else_assign's same
        # exclusion below) - the assignment is observable even with no in-function read of
        # its own, so it can never be treated as a dead store here
        if assigned_var.kind == VariableKind.GLOBAL:
            return None

        # Check var is not read in if body
        true_reads, _, _ = self._can_read_original_value(assigned_var, next_stmt.true_block)
        false_reads, _, _ = self._can_read_original_value(assigned_var, next_stmt.false_block)
        if true_reads or false_reads:
            return None

        # The assignment is about to be deleted, so var must not be read anywhere else in
        # the function either - it may be a VM register the bytecode reuses later, either
        # for this same condition again or for an unrelated value. assign_stmt and next_stmt
        # are excluded since their own reads of var are the pattern being folded away, not
        # an outside use (next_stmt's branches were just checked above; its condition is the
        # read this transform consumes).
        if self._var_read_elsewhere(assigned_var, exclude = (id(assign_stmt), id(next_stmt))):
            return None

        # Build new condition
        condition_expr = assign_stmt.src
        negate = (cond.op == BinaryOp.EQ)
        has_else = next_stmt.false_block and next_stmt.false_block.statements

        if negate and has_else:
            # if (var == 0) {A} else {B} -> if (expr) {B} else {A}
            new_condition = condition_expr
            new_true_block = next_stmt.false_block
            new_false_block = next_stmt.true_block

        elif negate:
            # if (var == 0) {A} -> if (!expr) {A}
            new_condition = self._negate_condition(condition_expr)
            new_true_block = next_stmt.true_block
            new_false_block = None

        else:
            # if (var != 0) {A} else {B} -> if (expr) {A} else {B}
            new_condition = condition_expr
            new_true_block = next_stmt.true_block
            new_false_block = next_stmt.false_block

        return HLILIf(new_condition, new_true_block, new_false_block)

    def _var_read_elsewhere(self, var: HLILVariable, exclude: tuple) -> bool:
        '''Check if var is read anywhere in the function, outside the excluded nodes.

        No kill/reachability tracking, unlike _can_read_original_value - any read anywhere
        counts, even one a real data-flow analysis could prove unreachable from the write
        being considered. That is deliberately conservative: it only ever blocks an
        optimization, never causes one, so it cannot turn a safe deletion into an unsafe one.
        '''
        return any(isinstance(n, HLILVar) and n.var == var for n in iter_tree(self._func_body, read_children, exclude))

    def _is_nop_stmt(self, stmt: HLILStatement) -> bool:
        '''Check if statement has no side effects (can be skipped)'''
        return isinstance(stmt, HLILComment)

    def _can_read_original_value(self, var: HLILVariable, node, killed: bool = False) -> tuple:
        '''
        Check if original value of var can be read anywhere in node.
        Uses data flow analysis to track write-before-read.

        Returns: (reads_original, fallthrough_killed, exit_paths)
            - reads_original: True if original value can be read on some path
            - fallthrough_killed: None when nothing falls through to whatever follows node;
              otherwise var's killed-state where it does. None is a structural proof (every
              path returns or jumps away); a bool is conservative, since conditions are
              never interpreted - `while (1)` still reports the zero-iteration fallthrough
              it can never really take. Over-reporting a fallthrough only keeps an
              assignment alive needlessly; it cannot hide a read.
            - exit_paths: every non-local exit reachable inside node that node does not
              itself own, each carrying the killed-state where it happens. Collected
              unconditionally - a break on one arm of an if survives even when the other
              arm falls through, because it rejoins at a real location further out.
              Multiplicity is irrelevant: whoever eventually owns a given exit contributes
              only its killed-state to a merge (_merge_fallthrough), same as any other
              path reaching that point - a return or a still-escaping labeled exit is
              never merged at all, just propagated unchanged until something owns it.
        '''
        if node is None:
            return (False, killed, ())

        # Expressions cannot contain a break/return/continue (those are statements) or kill
        # anything themselves, so killed is fixed across the whole subtree - walked with the
        # shared iter_tree, so a new expression node type can't drift from the other walkers.
        if isinstance(node, HLILExpression):
            reads = not killed and any(isinstance(n, HLILVar) and n.var == var for n in iter_tree(node, read_children))
            return (reads, killed, ())

        # Statements
        if isinstance(node, HLILExprStmt):
            reads, _, _ = self._can_read_original_value(var, node.expr, killed)
            return (reads, killed, ())

        if isinstance(node, HLILAssign):
            # RHS is evaluated first
            rhs_reads, _, _ = self._can_read_original_value(var, node.src, killed)

            # A store through a pointer (*dest = value) reads dest's own value too - unlike a
            # plain HLILVar dest, it does not kill var. Recursing on node.dest itself (not
            # node.dest.operand) reuses the HLILDeref branch above instead of re-deriving its
            # unwrap logic here.
            dest_reads = False
            if isinstance(node.dest, HLILDeref):
                dest_reads, _, _ = self._can_read_original_value(var, node.dest, killed)

            # Check if this kills var
            dest_kills = isinstance(node.dest, HLILVar) and node.dest.var == var
            return (rhs_reads or dest_reads, dest_kills or killed, ())

        if isinstance(node, HLILBlock):
            any_reads = False
            exit_paths = []
            current_killed = killed

            for stmt in node.statements:
                reads, fallthrough, stmt_exits = self._can_read_original_value(var, stmt, current_killed)
                if reads:
                    any_reads = True

                exit_paths.extend(stmt_exits)

                if fallthrough is None:
                    # Nothing after this statement is reachable
                    return (any_reads, None, tuple(exit_paths))

                current_killed = fallthrough

            return (any_reads, current_killed, tuple(exit_paths))

        if isinstance(node, HLILIf):
            # Check condition first
            cond_reads, _, _ = self._can_read_original_value(var, node.condition, killed)

            # A missing else is the None node case: condition-false falls through unchanged
            true_reads, true_fallthrough, true_exits = self._can_read_original_value(var, node.true_block, killed)
            false_reads, false_fallthrough, false_exits = self._can_read_original_value(var, node.false_block, killed)

            any_reads = cond_reads or true_reads or false_reads

            # An if owns no break/continue of its own, so both arms' exits pass straight
            # through - including an arm's exit whose sibling arm falls through instead
            exit_paths = true_exits + false_exits

            # Whichever arms continue rejoin right after the if - the same merge a loop's
            # condition-check or a switch's post-switch position uses for their own
            # multiple incoming states
            fallthrough = self._merge_fallthrough(
                [f for f in (true_fallthrough, false_fallthrough) if f is not None])

            return (any_reads, fallthrough, exit_paths)

        if isinstance(node, HLILWhile):
            return self._loop_result(var, node, killed, condition_checked_first = True)

        if isinstance(node, HLILDoWhile):
            return self._loop_result(var, node, killed, condition_checked_first = False)

        if isinstance(node, HLILSwitch):
            scrutinee_reads, _, _ = self._can_read_original_value(var, node.scrutinee, killed)

            any_reads = scrutinee_reads
            reaching_after = []
            exit_paths = []
            has_default = False

            for case in node.cases:
                if case.is_default():
                    has_default = True

                elif case.values:
                    # Case labels are expressions too (an OR-grouped chain of them, in
                    # general) - a read here is as real as one in the case body.
                    for value in case.values:
                        value_reads, _, _ = self._can_read_original_value(var, value, killed)
                        if value_reads:
                            any_reads = True

                case_reads, case_fallthrough, case_exits = self._can_read_original_value(var, case.body, killed)
                if case_reads:
                    any_reads = True

                if case_fallthrough is not None:
                    reaching_after.append(case_fallthrough)

                for exit_path in case_exits:
                    # A switch owns only a bare break. It carries no label of its own, so a
                    # labeled break can never name one, and continue belongs to a loop -
                    # both escape to be resolved further out, exactly like a return.
                    if exit_path.kind is ExitKind.BREAK and exit_path.label is None:
                        reaching_after.append(exit_path.killed)

                    else:
                        exit_paths.append(exit_path)

            # With no default, a scrutinee value matching none of the cases takes an
            # implicit path where nothing in the switch runs, reaching the code after it
            # with var untouched, no matter what the explicit cases do.
            if not has_default:
                reaching_after.append(killed)

            return (any_reads, self._merge_fallthrough(reaching_after), tuple(exit_paths))

        if isinstance(node, HLILReturn):
            # node.value is None for a bare return, which the None node case handles
            reads, _, _ = self._can_read_original_value(var, node.value, killed)
            return (reads, None, (ExitPath(ExitKind.RETURN, None, killed),))

        if isinstance(node, HLILBreak):
            return (False, None, (ExitPath(ExitKind.BREAK, node.label, killed),))

        if isinstance(node, HLILContinue):
            return (False, None, (ExitPath(ExitKind.CONTINUE, node.label, killed),))

        if isinstance(node, HLILUnstructured):
            # A jump HLIL could not express: whatever runs next may read var
            return (True, None, ())

        if isinstance(node, HLILComment):
            return (False, killed, ())

        return (False, killed, ())

    def _loop_result(self, var: HLILVariable, node, killed: bool, *,
                     condition_checked_first: bool) -> tuple:
        '''Shared while / do-while summary.

        The two differ only in whether the condition can be reached without the body
        running at all (while) or only after it (do-while). Everything else - which exits
        the loop owns, how a continue rejoins the next condition check, how the surviving
        states merge - is identical, so one walker serves both rather than two that have
        to be kept in step by hand.

        Iterates to a fixed point over the killed-states the body can be entered with.
        The worklist mechanically bounds this to at most two rounds, since killed only
        ever goes False -> True; monotonicity goes further and proves the second round is
        currently always redundant (a state reached with killed=True can never surface a
        new killed=False state). The worklist stays regardless, so correctness does not
        rest on that stronger argument continuing to hold as this file changes.
        '''
        reaching_condition = {killed} if condition_checked_first else set()
        pending = {killed}
        analyzed = set()

        body_reads = False
        breaks_out = []
        exit_paths = []

        while pending:
            state = pending.pop()
            analyzed.add(state)

            reads, fallthrough, exits = self._can_read_original_value(var, node.body, state)
            if reads:
                body_reads = True

            if fallthrough is not None:
                reaching_condition.add(fallthrough)

            for exit_path in exits:
                if not self._loop_absorbs(exit_path, node.label):
                    exit_paths.append(exit_path)

                elif exit_path.kind is ExitKind.CONTINUE:
                    # A continue rejoins the same next condition check the body falls into
                    reaching_condition.add(exit_path.killed)

                else:
                    # A break skips the check and lands after the loop
                    breaks_out.append(exit_path.killed)

            # Whatever reaches the check re-enters the body when it tests true
            pending |= reaching_condition - analyzed

        # The condition sees each state that reaches it - a killed=False arrival can expose
        # a read that a killed=True arrival would hide
        cond_reads = False
        for state in reaching_condition:
            reads, _, _ = self._can_read_original_value(var, node.condition, state)
            if reads:
                cond_reads = True

        # The loop is left either by the condition testing false or by a break
        after_loop = list(reaching_condition) + breaks_out
        return (body_reads or cond_reads, self._merge_fallthrough(after_loop), tuple(exit_paths))

    def _loop_absorbs(self, exit_path: ExitPath, loop_label: Optional[str]) -> bool:
        '''Whether a loop owns this exit: a bare break/continue always belongs to the
        nearest enclosing loop, a labeled one only to the loop carrying that label. A
        return belongs to no construct and is never absorbed.'''
        if exit_path.kind is ExitKind.RETURN:
            return False

        return exit_path.label is None or exit_path.label == loop_label

    def _merge_fallthrough(self, states: List[bool]) -> Optional[bool]:
        '''Killed-state where several paths rejoin. None when nothing arrives at all, so
        the construct structurally cannot fall through; otherwise killed only when every
        arriving path killed - one surviving path still holding the original value is
        enough to keep a later read of it visible.'''
        if not states:
            return None

        return all(states)

    def _remove_redundant_else_assign(self, if_stmt: HLILIf, preceding_stmts: List[HLILStatement]):
        '''Remove redundant var = source in else block for switch-case patterns.

        Pattern: if (var == A) { case_body } else { var = source; if (var == B) {...} }, where A
        and B are both literal constants (this function only recognizes literal switch-style
        discriminant tests). source must be a constant or a plain local/parameter variable - the
        only shapes provably stable across if_stmt's own condition evaluation and anything an
        intervening call could do: a global's value can change across a call while still
        rendering under the identical name at this layer; a register-kind variable still present
        here means SSA could not resolve it to a concrete tracked value (a successfully-tracked
        register becomes an ordinary LOCAL by this point); this codebase always represents an
        address-taken variable as an explicit *(&x) shape, never a bare HLILVar, so a bare HLILVar
        here is never address-taken.

        Requires proof that var already held source's value on entry to if_stmt: a reaching
        var = source assignment earlier in the same block (preceding_stmts), with nothing between
        it and if_stmt modifying var or source.
        '''
        if not if_stmt.false_block or not if_stmt.false_block.statements:
            return

        # Check outer condition is var == const (switch-case pattern)
        cond = if_stmt.condition
        if not isinstance(cond, HLILBinaryOp) or cond.op != BinaryOp.EQ:
            return

        if not isinstance(cond.lhs, HLILVar) or not isinstance(cond.rhs, HLILConst):
            return

        outer_var = cond.lhs.var

        if outer_var.kind not in (VariableKind.LOCAL, VariableKind.PARAM):
            return

        # Find first non-nop statement in else block
        false_stmts = if_stmt.false_block.statements
        assign_idx = 0
        while assign_idx < len(false_stmts) and self._is_nop_stmt(false_stmts[assign_idx]):
            assign_idx += 1

        if assign_idx >= len(false_stmts):
            return

        # Check it's var = source assignment
        assign_stmt = false_stmts[assign_idx]
        if not isinstance(assign_stmt, HLILAssign):
            return

        if not isinstance(assign_stmt.dest, HLILVar):
            return

        if assign_stmt.dest.var != outer_var:
            return

        source_expr = assign_stmt.src

        if isinstance(source_expr, HLILVar):
            if source_expr.var.kind not in (VariableKind.LOCAL, VariableKind.PARAM):
                return

            # Self-referential (x = x): a textual match against an earlier x = x does not mean
            # the same value was ever produced twice.
            if source_expr.var == outer_var:
                return

        elif not isinstance(source_expr, HLILConst):
            return

        # Check next statement is if (var == const)
        if assign_idx + 1 >= len(false_stmts):
            return

        inner_if = false_stmts[assign_idx + 1]
        if not isinstance(inner_if, HLILIf):
            return

        inner_cond = inner_if.condition
        if not isinstance(inner_cond, HLILBinaryOp) or inner_cond.op != BinaryOp.EQ:
            return

        if not isinstance(inner_cond.lhs, HLILVar) or inner_cond.lhs.var != outer_var:
            return

        if not isinstance(inner_cond.rhs, HLILConst):
            return

        if not self._reaching_assignment_exists(outer_var, source_expr, preceding_stmts):
            return

        # Remove redundant assignment
        false_stmts.pop(assign_idx)

    def _reaching_assignment_exists(self, var: HLILVariable, source: HLILExpression,
                                    preceding_stmts: List[HLILStatement]) -> bool:
        '''Walk preceding_stmts backward for a var = source-equivalent assignment, refusing if
        anything between it and here modifies var or (if source is itself a variable) source.
        source is already restricted to HLILConst or a plain local/param HLILVar by the caller.
        '''
        vars_to_guard = {var}
        if isinstance(source, HLILVar):
            vars_to_guard.add(source.var)

        for stmt in reversed(preceding_stmts):
            if (isinstance(stmt, HLILAssign) and isinstance(stmt.dest, HLILVar)
                    and stmt.dest.var == var and self._source_matches(stmt.src, source)):
                return True

            if self._stmt_modifies_any(stmt, vars_to_guard):
                return False

        return False

    def _source_matches(self, a: HLILExpression, b: HLILExpression) -> bool:
        '''True if a and b are the same constant value or the same plain variable - the only two
        shapes source_expr is ever allowed to be by the time this is called.
        '''
        if isinstance(a, HLILConst) and isinstance(b, HLILConst):
            return constant_values_equal(a.value, b.value)

        if isinstance(a, HLILVar) and isinstance(b, HLILVar):
            return a.var == b.var

        return False

    def _stmt_modifies_any(self, stmt: HLILStatement, vars_set: set) -> bool:
        '''Check if stmt modifies any variable in vars_set, anywhere in its tree.

        Note: a call (HLILExprStmt wrapping one, or nested inside an expression) is NOT
        considered to modify a named variable - REGS in this VM are only modified via direct
        assignment. Recognizes the address-taken *(&x) = v write shape too
        (ir/mlil/mlil_ssa.py's memory-form lowering), not just a plain HLILAssign(HLILVar, ...) -
        a call taking &x is still invisible here, a separate, larger gap this predicate does not
        attempt to close.
        '''
        def modifies(n) -> bool:
            if not isinstance(n, HLILAssign):
                return False

            if isinstance(n.dest, HLILVar):
                return n.dest.var in vars_set

            unwrapped = unwrap_address_taken_var(n.dest)
            return unwrapped is not None and unwrapped.var in vars_set

        return any(modifies(n) for n in iter_tree(stmt, read_children))

    def _equality_labels(self, cond) -> Optional[Tuple[HLILVar, List[int]]]:
        '''Values a test accepts, for `x == k` or any || chain of those

        The scrutinee must be a plain variable: a folded call would be evaluated
        once by the switch but once per test by the chain it replaces.
        '''
        if not isinstance(cond, HLILBinaryOp):
            return None

        if cond.op == BinaryOp.OR:
            left = self._equality_labels(cond.lhs)
            right = self._equality_labels(cond.rhs)

            if left is None or right is None:
                return None

            if left[0].var != right[0].var:
                return None

            return left[0], left[1] + right[1]

        if cond.op == BinaryOp.EQ:
            if isinstance(cond.lhs, HLILVar) and isinstance(cond.rhs, HLILConst):
                return cond.lhs, [cond.rhs.value]

        return None

    def _switch_link(self, if_stmt: HLILIf):
        '''One link of a dispatch chain as (scrutinee, values, case body, continuation)

        should_invert_condition can pick either orientation per link, so a chain may
        alternate between them; both are read here so one walk spans the whole chain.
        '''
        cond = if_stmt.condition

        match = self._equality_labels(cond)
        if match is not None:
            return match[0], match[1], if_stmt.true_block, if_stmt.false_block

        # Inverted: the case body is the else, the chain continues in the then
        if isinstance(cond, HLILUnaryOp) and cond.op == UnaryOp.NOT:
            match = self._equality_labels(cond.operand)
            if match is not None:
                return match[0], match[1], if_stmt.false_block, if_stmt.true_block

        if isinstance(cond, HLILBinaryOp) and cond.op == BinaryOp.NE:
            if isinstance(cond.lhs, HLILVar) and isinstance(cond.rhs, HLILConst):
                return cond.lhs, [cond.rhs.value], if_stmt.false_block, if_stmt.true_block

        return None

    def _try_convert_to_switch(self, if_stmt: HLILIf) -> Optional[HLILSwitch]:
        '''Convert a chain of equality tests on one variable into a switch

        Handles `==`, `!=` and ||-grouped links in any order, so a chain that
        alternates between them still becomes one switch.
        '''
        cases = []
        seen_case_values = set()
        scrutinee = None
        default_body = None
        pending_comments = []
        current_if = if_stmt

        while current_if is not None:
            link = self._switch_link(current_if)

            if link is None:
                return None

            var_expr, values, case_body, continuation = link

            if scrutinee is None:
                scrutinee = var_expr

            elif scrutinee.var != var_expr.var:
                return None

            if any(value in seen_case_values for value in values):
                return None

            case_body = case_body or HLILBlock()

            # Comments sat before the test that is about to disappear
            for comment in reversed(pending_comments):
                case_body.statements.insert(0, comment)

            pending_comments = []
            seen_case_values.update(values)
            cases.append((values, case_body))

            # Walk the continuation: another link, a switch already built from the
            # rest of the chain, or the default body
            current_if = None

            if continuation and continuation.statements:
                sole = sole_statement(continuation)

                if isinstance(sole, HLILIf):
                    current_if = sole
                    pending_comments = [s for s in continuation.statements if self._is_nop_stmt(s)]

                elif isinstance(sole, HLILSwitch):
                    nested = sole

                    if not isinstance(nested.scrutinee, HLILVar) or nested.scrutinee.var != scrutinee.var:
                        return None

                    for nested_case in nested.cases:
                        if nested_case.is_default():
                            default_body = nested_case.body
                            continue

                        if not all(isinstance(v, HLILConst) for v in nested_case.values):
                            return None

                        nested_values = [v.value for v in nested_case.values]

                        if any(value in seen_case_values for value in nested_values):
                            return None

                        seen_case_values.update(nested_values)
                        cases.append((nested_values, nested_case.body))

                else:
                    default_body = continuation

        if len(cases) < SWITCH_MIN_CASES or scrutinee is None:
            return None

        # A bare loop break inside a case would become a switch break after conversion
        if any(contains_bare_break(body) for _, body in cases) or contains_bare_break(default_body):
            return None

        switch_cases = [HLILSwitchCase([HLILConst(v) for v in values], body)
                        for values, body in cases]

        if default_body and default_body.statements:
            switch_cases.append(HLILSwitchCase(None, default_body))

        return HLILSwitch(scrutinee, switch_cases)

    def _negate_condition(self, condition: HLILExpression) -> HLILExpression:
        if isinstance(condition, HLILBinaryOp):
            if condition.op in NEGATED_COMPARISON_OP:
                return HLILBinaryOp(NEGATED_COMPARISON_OP[condition.op], condition.lhs, condition.rhs)

            elif condition.op in (BinaryOp.AND, BinaryOp.OR):
                return HLILBinaryOp(BinaryOp.EQ, condition, HLILConst(0))

        return HLILBinaryOp(BinaryOp.EQ, condition, HLILConst(0))
