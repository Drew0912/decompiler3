'''Control Flow Optimization Pass'''

import math
from typing import List, Optional, Tuple
from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILInstruction,
    HLILStatement,
    HLILExpression,
    HLILVar,
    HLILConst,
    HLILBinaryOp,
    HLILUnaryOp,
    HLILAddressOf,
    HLILDeref,
    HLILCall,
    HLILSyscall,
    HLILExternCall,
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
    HLILVariable,
    VariableKind,
    BinaryOp,
    UnaryOp,
    unwrap_address_taken_var,
)


# Below this a chain reads better as if/else-if than as a switch
SWITCH_MIN_CASES = 3


class ControlFlowOptimizationPass(Pass):
    '''Control flow optimizations: if-to-switch, empty-if inversion, else-if flattening, switch merging'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._func_body = func.body
        self._optimize_block(func.body)
        self._merge_nested_switches(func.body)
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
                if self._is_boolean_expr(stmt.src):
                    if i + 1 < len(block.statements):
                        next_stmt = block.statements[i + 1]
                        inlined = self._try_inline_condition(stmt, next_stmt)
                        if inlined:
                            # Recursively optimize the inlined if's sub-blocks
                            self._optimize_block(inlined.true_block)
                            self._optimize_block(inlined.false_block)
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
                        if self._is_boolean_expr(assign_stmt.src):
                            inlined = self._try_inline_condition(assign_stmt, if_stmt)
                            if inlined:
                                # Collect leading nops
                                for k in range(i, j):
                                    optimized.append(block.statements[k])

                                self._optimize_block(inlined.true_block)
                                self._optimize_block(inlined.false_block)
                                # Remove redundant assignments
                                self._remove_redundant_else_assign(inlined, optimized)
                                optimized.append(inlined)
                                i = j + 2
                                continue

            if isinstance(stmt, HLILIf):
                self._optimize_block(stmt.true_block)
                self._optimize_block(stmt.false_block)

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
                    non_nop_stmts = [s for s in stmt.false_block.statements if not self._is_nop_stmt(s)]
                    is_else_if_pattern = len(non_nop_stmts) == 1 and isinstance(non_nop_stmts[0], HLILIf)
                    if not is_else_if_pattern:
                        stmt.condition = self._negate_condition(stmt.condition)
                        stmt.true_block = stmt.false_block
                        stmt.false_block = None

            elif isinstance(stmt, HLILWhile):
                self._optimize_block(stmt.body)

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    self._optimize_block(case.body)

            optimized.append(stmt)
            i += 1

        block.statements = optimized

    # Operators that produce boolean results
    BOOLEAN_BINARY_OPS = {
        BinaryOp.EQ, BinaryOp.NE,
        BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE,
        BinaryOp.AND, BinaryOp.OR,
    }

    def _is_boolean_expr(self, expr: HLILExpression) -> bool:
        if isinstance(expr, HLILBinaryOp):
            return expr.op in self.BOOLEAN_BINARY_OPS

        elif isinstance(expr, HLILUnaryOp):
            return expr.op == UnaryOp.NOT

        return False

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

    def _expr_children(self, node) -> list:
        '''Immediate sub-expressions of an expression node, for a uniform "walk everything
        underneath" traversal. Leaves (HLILVar, HLILConst) and anything not an expression
        return no children.'''
        if isinstance(node, HLILBinaryOp):
            return [node.lhs, node.rhs]

        if isinstance(node, (HLILUnaryOp, HLILAddressOf, HLILDeref)):
            return [node.operand]

        if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
            return list(node.args)

        return []

    def _stmt_children(self, node) -> list:
        '''Immediate sub-statement/expression nodes of a statement-shaped node, falling
        through to _expr_children for anything that isn't a statement - lets _tree_any walk
        a mixed statement+expression tree with one recursive helper instead of every
        predicate hand-rolling its own dispatch list (the drift between hand-rolled lists is
        what let a switch case *label* go unscanned for variable reads - Codex Rule 2 review
        of Step 4's fix, finding 5).
        '''
        if isinstance(node, HLILAssign):
            # A plain-Var dest is a write, not a read - only a store through a pointer
            # (*dest = value) reads dest's own value too, so only that case is a child here
            # (matches _can_read_original_value's own dest handling below).
            if isinstance(node.dest, HLILDeref):
                return [node.dest, node.src]

            return [node.src]

        if isinstance(node, HLILExprStmt):
            return [node.expr]

        if isinstance(node, HLILReturn):
            return [node.value]

        if isinstance(node, HLILBlock):
            return list(node.statements)

        if isinstance(node, HLILIf):
            return [node.condition, node.true_block, node.false_block]

        if isinstance(node, HLILWhile):
            return [node.condition, node.body]

        if isinstance(node, HLILDoWhile):
            return [node.body, node.condition]

        if isinstance(node, HLILSwitch):
            children = [node.scrutinee]
            for case in node.cases:
                if case.values:
                    children.extend(case.values)
                children.append(case.body)
            return children

        return self._expr_children(node)

    def _tree_any(self, node, predicate, exclude: tuple = ()) -> bool:
        '''Whether predicate holds for node, or anywhere beneath it - statement or
        expression, via _stmt_children. The shared traversal behind every "does X occur
        anywhere in this tree" check in this file. A node whose id() is in exclude is
        skipped entirely (not recursed into), for callers that need to carve out a specific
        already-handled subtree rather than filter by node shape.'''
        if node is None or id(node) in exclude:
            return False

        if predicate(node):
            return True

        return any(self._tree_any(child, predicate, exclude) for child in self._stmt_children(node))

    def _var_read_elsewhere(self, var: HLILVariable, exclude: tuple) -> bool:
        '''Check if var is read anywhere in the function, outside the excluded nodes.

        No kill/reachability tracking, unlike _can_read_original_value - any read anywhere
        counts, even one a real data-flow analysis could prove unreachable from the write
        being considered. That is deliberately conservative: it only ever blocks an
        optimization, never causes one, so it cannot turn a safe deletion into an unsafe one.
        '''
        return self._tree_any(self._func_body, lambda n: isinstance(n, HLILVar) and n.var == var, exclude)

    def _is_nop_stmt(self, stmt: HLILStatement) -> bool:
        '''Check if statement has no side effects (can be skipped)'''
        return isinstance(stmt, HLILComment)

    def _can_read_original_value(self, var: HLILVariable, node, killed: bool = False) -> tuple:
        '''
        Check if original value of var can be read anywhere in node.
        Uses data flow analysis to track write-before-read.

        Returns: (reads_original, killed_after, always_exits)
            - reads_original: True if original value can be read on some path
            - killed_after: True if var is killed on all continuing paths
            - always_exits: True if all paths exit (return/break/continue)
        '''
        if node is None:
            return (False, killed, False)

        # Expressions - don't kill, may read
        if isinstance(node, HLILVar):
            reads = (node.var == var and not killed)
            return (reads, killed, False)

        if isinstance(node, HLILConst):
            return (False, killed, False)

        if isinstance(node, HLILBinaryOp):
            left_reads, _, _ = self._can_read_original_value(var, node.lhs, killed)
            right_reads, _, _ = self._can_read_original_value(var, node.rhs, killed)
            return (left_reads or right_reads, killed, False)

        if isinstance(node, (HLILUnaryOp, HLILAddressOf, HLILDeref)):
            reads, _, _ = self._can_read_original_value(var, node.operand, killed)
            return (reads, killed, False)

        if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
            for arg in node.args:
                reads, _, _ = self._can_read_original_value(var, arg, killed)
                if reads:
                    return (True, killed, False)
            return (False, killed, False)

        # Statements
        if isinstance(node, HLILExprStmt):
            reads, _, _ = self._can_read_original_value(var, node.expr, killed)
            return (reads, killed, False)

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
            return (rhs_reads or dest_reads, dest_kills or killed, False)

        if isinstance(node, HLILBlock):
            any_reads = False
            current_killed = killed

            for stmt in node.statements:
                reads, current_killed, exits = self._can_read_original_value(var, stmt, current_killed)
                if reads:
                    any_reads = True
                if exits:
                    # Path exits, subsequent code unreachable
                    return (any_reads, current_killed, True)

            return (any_reads, current_killed, False)

        if isinstance(node, HLILIf):
            # Check condition first
            cond_reads, _, _ = self._can_read_original_value(var, node.condition, killed)

            # Check both branches
            true_reads, true_killed, true_exits = self._can_read_original_value(var, node.true_block, killed)

            if node.false_block:
                false_reads, false_killed, false_exits = self._can_read_original_value(var, node.false_block, killed)

            else:
                false_reads, false_killed, false_exits = False, killed, False

            any_reads = cond_reads or true_reads or false_reads

            # Determine killed state after if
            if true_exits and false_exits:
                # Both exit - whole if exits
                return (any_reads, killed, True)

            elif true_exits:
                # Only false branch continues
                killed_after = false_killed

            elif false_exits:
                # Only true branch continues
                killed_after = true_killed

            else:
                # Both continue - killed only if both kill
                killed_after = true_killed and false_killed

            return (any_reads, killed_after, False)

        if isinstance(node, HLILWhile):
            # While may not execute at all, so can't guarantee kill
            cond_reads, _, _ = self._can_read_original_value(var, node.condition, killed)
            body_reads, _, _ = self._can_read_original_value(var, node.body, killed)
            return (cond_reads or body_reads, killed, False)

        if isinstance(node, HLILDoWhile):
            # Do-while executes body at least once
            body_reads, body_killed, body_exits = self._can_read_original_value(var, node.body, killed)

            if body_exits:
                return (body_reads, body_killed, True)

            cond_reads, _, _ = self._can_read_original_value(var, node.condition, body_killed)
            return (body_reads or cond_reads, body_killed, False)

        if isinstance(node, HLILSwitch):
            scrutinee_reads, _, _ = self._can_read_original_value(var, node.scrutinee, killed)

            any_reads = scrutinee_reads
            all_exit = True
            all_kill = True
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

                case_reads, case_killed, case_exits = self._can_read_original_value(var, case.body, killed)
                if case_reads:
                    any_reads = True
                if not case_exits:
                    all_exit = False
                    if not case_killed:
                        all_kill = False

            # With no default, a scrutinee value matching none of the cases takes an
            # implicit path where nothing in the switch runs - var reaches the code after
            # the switch unchanged, so the switch can neither be assumed to exit nor to
            # kill var on every path, no matter what the explicit cases do.
            if not has_default:
                all_exit = False
                all_kill = False

            if all_exit:
                return (any_reads, killed, True)

            return (any_reads, all_kill, False)

        if isinstance(node, HLILReturn):
            if node.value:
                reads, _, _ = self._can_read_original_value(var, node.value, killed)
                return (reads, killed, True)
            return (False, killed, True)

        if isinstance(node, (HLILBreak, HLILContinue)):
            return (False, killed, True)

        if isinstance(node, HLILComment):
            return (False, killed, False)

        return (False, killed, False)

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
        shapes source_expr is ever allowed to be by the time this is called. Constant comparison
        mirrors pass_reg_global_propagation.py's _expr_equal: int and float are distinct
        representations even at equal numeric value, and NaN compares equal to itself here
        (ED9 floats decode straight from binary data, so NaN is a real, reachable constant).
        '''
        if isinstance(a, HLILConst) and isinstance(b, HLILConst):
            if type(a.value) != type(b.value):
                return False

            if isinstance(a.value, float):
                return a.value == b.value or (math.isnan(a.value) and math.isnan(b.value))

            return a.value == b.value

        if isinstance(a, HLILVar) and isinstance(b, HLILVar):
            return a.var == b.var

        return False

    def _stmt_modifies_any(self, stmt: HLILStatement, vars_set: set) -> bool:
        '''Check if stmt modifies any variable in vars_set, anywhere in its tree.

        Note: a call (HLILExprStmt wrapping one, or nested inside an expression) is NOT
        considered to modify a named variable - REGS in this VM are only modified via direct
        assignment, unlike the conservative "any call may write anything" policy used
        elsewhere in this codebase (e.g. pass_copy_propagation.py) for a different hazard.
        Recognizes the address-taken *(&x) = v write shape too (ir/mlil/mlil_ssa.py's memory-
        form lowering), not just a plain HLILAssign(HLILVar, ...) - a call taking &x is still
        invisible here, a separate, larger gap this predicate does not attempt to close.
        '''
        def modifies(n) -> bool:
            if not isinstance(n, HLILAssign):
                return False

            if isinstance(n.dest, HLILVar):
                return n.dest.var in vars_set

            unwrapped = unwrap_address_taken_var(n.dest)
            return unwrapped is not None and unwrapped.var in vars_set

        return self._tree_any(stmt, modifies)

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
                real_stmts = [s for s in continuation.statements if not self._is_nop_stmt(s)]

                if len(real_stmts) == 1 and isinstance(real_stmts[0], HLILIf):
                    current_if = real_stmts[0]
                    pending_comments = [s for s in continuation.statements if self._is_nop_stmt(s)]

                elif len(real_stmts) == 1 and isinstance(real_stmts[0], HLILSwitch):
                    nested = real_stmts[0]

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
        for _, case_body in cases:
            if self._contains_bare_break(case_body):
                return None

        if default_body and self._contains_bare_break(default_body):
            return None

        switch_cases = [HLILSwitchCase([HLILConst(v) for v in values], body)
                        for values, body in cases]

        if default_body and default_body.statements:
            switch_cases.append(HLILSwitchCase(None, default_body))

        return HLILSwitch(scrutinee, switch_cases)

    def _contains_bare_break(self, block: Optional[HLILBlock]) -> bool:
        '''Check for an unlabeled break not owned by a nested loop or switch'''
        if not block or not block.statements:
            return False

        for stmt in block.statements:
            if isinstance(stmt, HLILBreak) and stmt.label is None:
                return True

            if isinstance(stmt, HLILIf):
                if self._contains_bare_break(stmt.true_block) or self._contains_bare_break(stmt.false_block):
                    return True

            # Breaks inside nested While/DoWhile/Switch belong to those constructs

        return False

    def _merge_nested_switches(self, block: HLILBlock):
        if not block or not block.statements:
            return

        for stmt in block.statements:
            if isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    self._merge_nested_switches(case.body)

                    comments = [s for s in case.body.statements if self._is_nop_stmt(s)]
                    rest = [s for s in case.body.statements if not self._is_nop_stmt(s)]

                    if len(rest) == 1:
                        nested_stmt = rest[0]
                        if isinstance(nested_stmt, HLILSwitch):
                            if isinstance(nested_stmt.scrutinee, HLILVar) and isinstance(stmt.scrutinee, HLILVar):
                                if nested_stmt.scrutinee.var == stmt.scrutinee.var:
                                    if case.is_default():
                                        # The merge drops this case, so its comments move to what replaces it
                                        if comments and nested_stmt.cases:
                                            nested_stmt.cases[0].body.statements[:0] = comments

                                        stmt.cases.remove(case)
                                        stmt.cases.extend(nested_stmt.cases)
                                        self._merge_nested_switches(block)
                                        return

            elif isinstance(stmt, HLILIf):
                self._merge_nested_switches(stmt.true_block)
                self._merge_nested_switches(stmt.false_block)

            elif isinstance(stmt, HLILWhile):
                self._merge_nested_switches(stmt.body)

    NEGATION_MAP = {
        BinaryOp.EQ: BinaryOp.NE,
        BinaryOp.NE: BinaryOp.EQ,
        BinaryOp.LT: BinaryOp.GE,
        BinaryOp.GE: BinaryOp.LT,
        BinaryOp.GT: BinaryOp.LE,
        BinaryOp.LE: BinaryOp.GT,
    }

    def _negate_condition(self, condition: HLILExpression) -> HLILExpression:
        if isinstance(condition, HLILBinaryOp):
            if condition.op in self.NEGATION_MAP:
                return HLILBinaryOp(self.NEGATION_MAP[condition.op], condition.lhs, condition.rhs)

            elif condition.op in (BinaryOp.AND, BinaryOp.OR):
                return HLILBinaryOp(BinaryOp.EQ, condition, HLILConst(0))

        return HLILBinaryOp(BinaryOp.EQ, condition, HLILConst(0))
