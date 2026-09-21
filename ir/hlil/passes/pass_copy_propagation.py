'''Copy Propagation Pass'''

from dataclasses import dataclass
from typing import Optional
from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILInstruction,
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
    HLILAssign,
    HLILExprStmt,
    HLILReturn,
    HLILBreak,
    HLILContinue,
    HLILVariable,
    BinaryOp,
    UnaryOp,
)


@dataclass
class UseInfo:
    '''Information about a variable use location'''
    in_entered_loop: bool = False
    containing_loop: Optional[HLILInstruction] = None
    in_conditional_branch: bool = False


class CopyPropagationPass(Pass):
    '''Propagate single-use variable copies: var = expr; use(var) -> use(expr)'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        # Every local whose address is taken anywhere in the function - only such a variable
        # could ever be aliased by a pointer (nothing else ever computed a pointer to it), so
        # _may_clobber_impure_read scopes its named-variable hazard to this set rather than
        # treating every assignment in the function as a potential alias (Codex Rule 2 round 9
        # finding #4 fix, corrected after the unscoped version regressed 3 existing tests by
        # blocking essentially all impure-read propagation).
        self._address_taken_vars = set()
        self._collect_address_taken_vars(func.body, self._address_taken_vars)

        self._propagate_copies(func.body)
        return func

    def _collect_address_taken_vars(self, node, result: set):
        '''Recursively find every AddressOf(var) in node's tree and add var to result.'''
        if node is None:
            return

        if isinstance(node, HLILAddressOf) and isinstance(node.operand, HLILVar):
            result.add(node.operand.var)

        for child in self._stmt_children(node):
            self._collect_address_taken_vars(child, result)

    def _propagate_copies(self, block: HLILBlock):
        if not block or not block.statements:
            return

        # Recurse into nested blocks first
        for stmt in block.statements:
            if isinstance(stmt, HLILIf):
                self._propagate_copies(stmt.true_block)
                self._propagate_copies(stmt.false_block)

            elif isinstance(stmt, HLILWhile):
                self._propagate_copies(stmt.body)

            elif isinstance(stmt, HLILDoWhile):
                self._propagate_copies(stmt.body)

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    self._propagate_copies(case.body)

        # Find and propagate single-use copies
        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]

            if not isinstance(stmt, HLILAssign) or not isinstance(stmt.dest, HLILVar):
                i += 1
                continue

            var = stmt.dest.var
            expr = stmt.src

            # Skip boolean expressions (handled by ControlFlowOptimizationPass)
            if self._is_boolean_expr(expr):
                i += 1
                continue

            # Find reachable uses in remaining statements
            remaining = block.statements[i + 1:]
            if not remaining:
                i += 1
                continue

            uses, any_kill = self._find_reachable_uses_in_list(remaining, var, in_entered_loop = False)

            # any_kill means the scan stopped early because some path through a reassigns var
            # - e.g. `switch (var) { case 0: var = x; default: }`, where the scrutinee counts
            # as the one use found so far, but a non-killing case (the default here) may still
            # reach code further down that never got examined. len(uses) == 1 alone can't be
            # trusted once the scan was cut short this way: propagating and deleting the
            # original def would leave that later, unexamined path reading an undefined
            # variable (Codex Rule 2 round 9 finding #2).
            if len(uses) != 1 or any_kill:
                i += 1
                continue

            use = uses[0]
            source_vars = self._collect_vars(expr)
            effectful_or_impure = self._is_effectful_or_impure(expr)

            # Check loop constraints
            if use.in_entered_loop:
                if effectful_or_impure:
                    i += 1
                    continue

                if use.containing_loop and self._modifies_vars(use.containing_loop, source_vars):
                    i += 1
                    continue

            # Check conditional-branch constraint: the definition runs unconditionally (it's
            # a statement in this same straight-line block), so propagating an effectful/
            # impure expression into a use nested inside an if/switch branch would change it
            # from "always runs" to "only runs when that branch is taken" - the same hazard
            # class as CallResultFolder's short-circuit problem, just via propagation here
            # instead of call-result folding.
            if use.in_conditional_branch and effectful_or_impure:
                i += 1
                continue

            # Check source not modified between assignment and use
            source_modified = False
            for stmt_between in remaining:
                if self._modifies_vars(stmt_between, source_vars):
                    source_modified = True
                    break

            # _modifies_vars only tracks named variables, and short-circuits to False when
            # source_vars is empty (e.g. a deref of a constant address) - so a call between
            # assignment and use is missed there for such expressions. An impure read can
            # also change value via a store through ANY pointer, not just a reassignment of
            # a variable appearing in the expression. Check both hazards directly against
            # the expression's own impurity instead of relying on named-variable tracking.
            #
            # _may_clobber_impure_read only catches a clobber in a DIFFERENT statement - it
            # does not catch an impure read (*p) sitting as a sibling to var's own use,
            # evaluated earlier in the SAME statement (e.g. `x = *p + var`): propagating an
            # effectful source there would move it to run after *p instead of before, which
            # is exactly the hazard _reads_before_impure checks for.
            #
            # _contains_impure_read(stmt_between) catches the remaining gap: an impure read
            # sitting in an EARLIER, SEPARATE statement (not a sibling within the use's own
            # statement) - moving the effectful expr past it the same way _may_clobber_impure_
            # read's clobber check does, just for reads instead of writes (Codex Rule 2 round
            # 8 finding #1).
            #
            # also_named_vars (passed to _reads_before_impure) additionally treats a sibling
            # read of any OTHER named variable as a hazard, but only when expr itself is a
            # call: a call is conservatively assumed able to write any named variable
            # (_modifies_vars's own policy), so it must not move past an earlier sibling read
            # of one either (Codex Rule 2 round 8 finding #3). _reads_before_impure only
            # covers that hazard WITHIN the use's own statement, though (`out = x + var`) - a
            # read of some other named variable in an EARLIER, SEPARATE statement
            # (`var = call(&x); p = x; ... = var`) needs the same protection
            # _contains_impure_read above already gets for derefs, via _reads_any_var below
            # (Codex Rule 2 round 9 finding #1). Guarded to skip the statement containing the
            # use itself - that one's internal ordering is what _reads_before_impure exists
            # for, and it would otherwise always "contain a var read" (var's own). Uses
            # _tree_any directly rather than _contains_var, which only ever handles expression
            # node types (its callers always pass it an expression, never a full statement) -
            # passing it a statement like stmt_between here would silently always return
            # False, making the guard a no-op (caught by 2 regressed tests before this fix).
            if not source_modified and effectful_or_impure:
                also_named_vars = self._contains_call(expr)
                for stmt_between in remaining:
                    stmt_contains_var = self._tree_any(stmt_between, lambda n: isinstance(n, HLILVar) and n.var == var)
                    if (self._may_clobber_impure_read(stmt_between) or
                            self._contains_impure_read(stmt_between) or
                            self._reads_before_impure(stmt_between, var, also_named_vars) or
                            (also_named_vars and not stmt_contains_var and
                             self._reads_any_var(stmt_between))):
                        source_modified = True
                        break

            if source_modified:
                i += 1
                continue

            # Safe to propagate: replace and delete
            if self._replace_var(remaining, var, expr):
                block.statements.pop(i)
                # Don't increment i
            else:
                i += 1

    BOOLEAN_BINARY_OPS = {
        BinaryOp.EQ, BinaryOp.NE,
        BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE,
        BinaryOp.AND, BinaryOp.OR,
    }

    def _is_boolean_expr(self, expr: HLILExpression) -> bool:
        if isinstance(expr, HLILBinaryOp):
            return expr.op in self.BOOLEAN_BINARY_OPS

        if isinstance(expr, HLILUnaryOp):
            return expr.op == UnaryOp.NOT

        return False

    def _find_reachable_uses_in_list(self, stmts: list, var: HLILVariable, in_entered_loop: bool,
                                      containing_loop = None, in_conditional_branch: bool = False) -> tuple[list[UseInfo], bool]:
        '''Find reachable uses in a list of statements. Returns (uses, any_kill).

        Mirrors the HLILBlock case in _find_reachable_uses below (both walk a flat statement
        list the same way) - kept separate because callers here start from a plain list slice
        (block.statements[i + 1:]), not an HLILBlock node.
        '''
        uses = []
        any_kill = False
        conditional = in_conditional_branch
        for stmt in stmts:
            stmt_uses, killed = self._find_reachable_uses(stmt, var, in_entered_loop, containing_loop, conditional)
            uses.extend(stmt_uses)
            if killed:
                any_kill = True
                break

            # A bare return/break/continue statement itself makes everything positioned after
            # it, in this same statement list, unreachable - stop scanning (stmt's own uses,
            # e.g. `return var`, were already collected above; this only stops looking BEYOND
            # it). Without this, trailing dead code after a terminator could be found as the
            # sole "use," letting an effectful def get moved into code that never runs
            # (Codex Rule 2 round 9 finding #5).
            if isinstance(stmt, (HLILReturn, HLILBreak, HLILContinue)):
                break

            if self._may_skip_later_code(stmt):
                conditional = True

        return (uses, any_kill)

    def _find_reachable_uses(self, node, var: HLILVariable, in_entered_loop: bool, containing_loop = None,
                              in_conditional_branch: bool = False) -> tuple[list[UseInfo], bool]:
        '''Find reachable uses of var in node. Returns (list of UseInfo, any_kill).'''
        if node is None:
            return ([], False)

        # Leaf nodes
        if isinstance(node, HLILVar):
            if node.var == var:
                return ([UseInfo(in_entered_loop = in_entered_loop, containing_loop = containing_loop,
                                  in_conditional_branch = in_conditional_branch)], False)
            return ([], False)

        if isinstance(node, HLILConst):
            return ([], False)

        # Expression nodes
        if isinstance(node, HLILBinaryOp):
            left_uses, _ = self._find_reachable_uses(node.lhs, var, in_entered_loop, containing_loop, in_conditional_branch)

            # Logical AND/OR short-circuit: the rhs only evaluates when the lhs doesn't already
            # decide the result, so a use there is reached on fewer paths than the lhs (or a
            # non-short-circuiting operator's operands) is.
            rhs_conditional = in_conditional_branch or node.op in (BinaryOp.AND, BinaryOp.OR)
            right_uses, _ = self._find_reachable_uses(node.rhs, var, in_entered_loop, containing_loop, rhs_conditional)
            return (left_uses + right_uses, False)

        if isinstance(node, (HLILUnaryOp, HLILAddressOf, HLILDeref)):
            return self._find_reachable_uses(node.operand, var, in_entered_loop, containing_loop, in_conditional_branch)

        if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
            all_uses = []
            for arg in node.args:
                arg_uses, _ = self._find_reachable_uses(arg, var, in_entered_loop, containing_loop, in_conditional_branch)
                all_uses.extend(arg_uses)
            return (all_uses, False)

        # Statement nodes
        if isinstance(node, HLILAssign):
            src_uses, _ = self._find_reachable_uses(node.src, var, in_entered_loop, containing_loop, in_conditional_branch)

            # A store through a pointer (*dest = value) reads dest's own value too, unlike a
            # plain HLILVar dest which kills rather than reads. Recursing on node.dest itself
            # (not node.dest.operand) reuses the HLILDeref branch above instead of re-deriving
            # its unwrap logic here.
            dest_uses = []
            if isinstance(node.dest, HLILDeref):
                dest_uses, _ = self._find_reachable_uses(node.dest, var, in_entered_loop, containing_loop, in_conditional_branch)

            kills = isinstance(node.dest, HLILVar) and node.dest.var == var
            return (src_uses + dest_uses, kills)

        if isinstance(node, HLILExprStmt):
            return self._find_reachable_uses(node.expr, var, in_entered_loop, containing_loop, in_conditional_branch)

        if isinstance(node, HLILBlock):
            all_uses = []
            conditional = in_conditional_branch
            for stmt in node.statements:
                stmt_uses, any_kill = self._find_reachable_uses(stmt, var, in_entered_loop, containing_loop, conditional)
                all_uses.extend(stmt_uses)
                if any_kill:
                    return (all_uses, True)

                # A bare return/break/continue makes everything after it, in this same block,
                # unreachable - stop here (mirrors the identical check in
                # _find_reachable_uses_in_list below; Codex Rule 2 round 9 finding #5).
                if isinstance(stmt, (HLILReturn, HLILBreak, HLILContinue)):
                    return (all_uses, False)

                # If this statement might return/break/continue on some path (an if-branch,
                # or a switch case), everything after it in this block is only reached via
                # the paths that don't - conditional from here on, even though it isn't
                # lexically nested inside that branch/case.
                if self._may_skip_later_code(stmt):
                    conditional = True

            return (all_uses, False)

        if isinstance(node, HLILIf):
            cond_uses, _ = self._find_reachable_uses(node.condition, var, in_entered_loop, containing_loop, in_conditional_branch)

            # A use nested inside either branch is reached on fewer paths than the
            # definition (which runs unconditionally, as a statement in the same
            # straight-line block) - mark it, regardless of which branch it's in.
            true_uses, true_kill = self._find_reachable_uses(node.true_block, var, in_entered_loop, containing_loop, True)

            if node.false_block:
                false_uses, false_kill = self._find_reachable_uses(node.false_block, var, in_entered_loop, containing_loop, True)

            else:
                false_uses, false_kill = [], False

            any_kill = true_kill or false_kill
            return (cond_uses + true_uses + false_uses, any_kill)

        if isinstance(node, HLILWhile):
            cond_uses, _ = self._find_reachable_uses(node.condition, var, True, node, in_conditional_branch)
            body_uses, body_kill = self._find_reachable_uses(node.body, var, True, node, in_conditional_branch)
            return (cond_uses + body_uses, body_kill)

        if isinstance(node, HLILDoWhile):
            body_uses, body_kill = self._find_reachable_uses(node.body, var, True, node, in_conditional_branch)
            if body_kill:
                return (body_uses, True)

            cond_uses, _ = self._find_reachable_uses(node.condition, var, True, node, in_conditional_branch)
            return (body_uses + cond_uses, False)

        if isinstance(node, HLILSwitch):
            scrut_uses, _ = self._find_reachable_uses(node.scrutinee, var, in_entered_loop, containing_loop, in_conditional_branch)
            all_uses = scrut_uses
            any_kill = False
            for case in node.cases:
                # A case body only runs when that case matches - same "fewer paths than the
                # definition" reasoning as an if's branches above.
                case_uses, case_kill = self._find_reachable_uses(case.body, var, in_entered_loop, containing_loop, True)
                all_uses.extend(case_uses)
                if case_kill:
                    any_kill = True

            return (all_uses, any_kill)

        if isinstance(node, HLILReturn):
            if node.value:
                return self._find_reachable_uses(node.value, var, in_entered_loop, containing_loop, in_conditional_branch)
            return ([], False)

        return ([], False)

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
        through to _expr_children for anything that isn't a statement - lets _tree_any walk a
        mixed statement+expression tree with a single recursive helper instead of every
        predicate hand-rolling its own dispatch list (the drift between those hand-rolled
        lists - e.g. _modifies_vars never recursing into HLILBinaryOp - is what let a call
        buried inside a binary expression go undetected as a clobber; Codex Rule 2 round 8).
        '''
        if isinstance(node, HLILAssign):
            return [node.dest, node.src]

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
            return [node.scrutinee] + [case.body for case in node.cases]

        return self._expr_children(node)

    def _tree_any(self, node, predicate) -> bool:
        '''Whether predicate holds for node, or anywhere beneath it - statement or
        expression, via _stmt_children. The shared traversal behind every "does X occur
        anywhere in this tree" check in this file.'''
        if node is None:
            return False

        if predicate(node):
            return True

        return any(self._tree_any(child, predicate) for child in self._stmt_children(node))

    def _collect_vars(self, expr: HLILExpression) -> set:
        '''Collect all variables referenced in expression.'''
        if isinstance(expr, HLILVar):
            return {expr.var}

        result = set()
        for child in self._expr_children(expr):
            result.update(self._collect_vars(child))
        return result

    def _is_effectful_or_impure(self, expr: HLILExpression) -> bool:
        '''Check if expression has side effects (calls), or, for HLILDeref, is an impure read
        that could change value between loop iterations - unsafe to duplicate into a loop
        either way, even though a deref itself is a read, not a side effect.'''
        return self._tree_any(expr, lambda n: isinstance(n, (HLILCall, HLILSyscall, HLILExternCall, HLILDeref)))

    def _contains_call(self, node) -> bool:
        '''Whether node contains a call anywhere in its tree - the only construct this file
        conservatively treats as capable of writing a named variable it doesn't mention by
        name (matching _modifies_vars's "any call may modify any variable" policy). Unlike
        _is_effectful_or_impure, a plain HLILDeref doesn't count here: reading through a
        pointer doesn't write anything.'''
        return self._tree_any(node, lambda n: isinstance(n, (HLILCall, HLILSyscall, HLILExternCall)))

    def _modifies_vars(self, node, vars_to_check: set) -> bool:
        '''Check if node modifies any variable in vars_to_check, anywhere in its tree.'''
        if not vars_to_check:
            return False

        def is_clobber(n) -> bool:
            if isinstance(n, HLILAssign):
                if isinstance(n.dest, HLILVar) and n.dest.var in vars_to_check:
                    return True

                # A store through a pointer could alias any named variable - no alias
                # analysis to rule it out, same conservative treatment calls get below. This
                # is what makes source_modified's scan below catch a deref-store clobbering a
                # PURE named-variable source, not just an effectful/impure one (the latter
                # has its own separate _may_clobber_impure_read/_reads_before_impure checks).
                if isinstance(n.dest, HLILDeref):
                    return True

            # Conservative: calls may modify any variable
            return isinstance(n, (HLILCall, HLILSyscall, HLILExternCall))

        return self._tree_any(node, is_clobber)

    def _may_clobber_impure_read(self, node) -> bool:
        '''Check if node could invalidate an impure read (e.g. *p) anywhere in its tree: an
        explicit store through a pointer (*dest = value), a store to a named variable whose
        address is taken somewhere in the function (self._address_taken_vars - such a
        variable is the only kind a pointer could plausibly be aliasing, the same "no alias
        analysis" reasoning _modifies_vars already applies in the opposite direction for
        deref-stores; Codex Rule 2 round 9 finding #4), or a call.

        Scoped to address_taken_vars rather than every named variable: an unscoped version
        was tried first and regressed 3 existing tests by treating the use statement's own
        (entirely unrelated) destination variable as a hazard, blocking nearly all impure-read
        propagation - a variable whose address is never taken cannot be aliased by any
        pointer, so it is not a hazard at all.
        '''
        def is_hazard(n) -> bool:
            if isinstance(n, HLILAssign):
                if isinstance(n.dest, HLILDeref):
                    return True
                if isinstance(n.dest, HLILVar) and n.dest.var in self._address_taken_vars:
                    return True
            return isinstance(n, (HLILCall, HLILSyscall, HLILExternCall))

        return self._tree_any(node, is_hazard)

    def _contains_impure_read(self, node) -> bool:
        '''Whether node reads through a pointer (HLILDeref) anywhere in its tree - statement
        or expression.

        Only derefs count here, not calls - a call sitting between the definition and use
        (in a different statement, or as a sibling within the same one) is already caught by
        _may_clobber_impure_read's unconditional "a call may clobber anything" rule. This
        helper exists for the narrower gap that check doesn't cover: a deref is a READ, not a
        clobber, so it needs its own evaluation-order check (_reads_before_impure below), and
        an evaluation-order check against an EARLIER, separate statement (not just a sibling
        within the same one - Codex Rule 2 round 8 finding #1).
        '''
        return self._tree_any(node, lambda n: isinstance(n, HLILDeref))

    def _reads_any_var(self, node) -> bool:
        '''Whether node mentions any named variable anywhere in its tree - used only for the
        also_named_vars hazard in _propagate_copies's scan loop, where a call about to move
        LATER (past this earlier, separate statement) is conservatively assumed able to write
        any named variable, so any variable mention here is a potential hazard (Codex Rule 2
        round 9 finding #1 - the cross-statement counterpart to _reads_before_impure's
        also_named_vars, which only covers a sibling read within the use's own statement).
        Slightly imprecise - a plain assignment's HLILVar dest counts too, even though it's a
        write, not a read - in favor of staying conservative rather than distinguishing every
        read/write position precisely.'''
        return self._tree_any(node, lambda n: isinstance(n, HLILVar))

    def _reads_before_impure(self, node, var: HLILVariable, also_named_vars: bool = False) -> bool:
        '''Whether a read of var inside node is preceded, in evaluation order, by an impure
        read (dereference) elsewhere in node - or, when also_named_vars is set, by a read of
        ANY other named variable.

        Propagating an effectful/impure source into var's position must not let something
        that evaluates before var's own read - in the original code - end up running after
        it once var is replaced. Mirrors mlil_to_hlil.py's
        CallResultFolder._reads_before_impure for the same reason, at the HLIL level; this
        file's own convention (see _find_reachable_uses) is that an HLILAssign's src is
        evaluated before its dest.

        also_named_vars widens "impure" to any named-variable read, for when the replacement
        about to occupy var's position is itself a call: _modifies_vars already treats any
        call as conservatively able to write any named variable, so a call replacing var must
        not be allowed to move past an earlier sibling read of some OTHER variable either
        (Codex Rule 2 round 8 finding #3) - not just past a deref. Only the caller
        (_propagate_copies) knows whether that's the case, so it threads the flag in.
        '''
        def is_impure(n) -> bool:
            if isinstance(n, HLILDeref):
                return True
            return also_named_vars and isinstance(n, HLILVar)

        if isinstance(node, HLILBinaryOp):
            if self._contains_var(node.rhs, var) and self._tree_any(node.lhs, is_impure):
                return True

            return (self._reads_before_impure(node.lhs, var, also_named_vars) or
                    self._reads_before_impure(node.rhs, var, also_named_vars))

        if isinstance(node, (HLILUnaryOp, HLILAddressOf, HLILDeref)):
            return self._reads_before_impure(node.operand, var, also_named_vars)

        if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
            seen_impure = False
            for arg in node.args:
                if seen_impure and self._contains_var(arg, var):
                    return True

                if self._reads_before_impure(arg, var, also_named_vars):
                    return True

                seen_impure = seen_impure or self._tree_any(arg, is_impure)

            return False

        if isinstance(node, HLILAssign):
            if self._reads_before_impure(node.src, var, also_named_vars):
                return True

            if isinstance(node.dest, HLILDeref):
                if self._contains_var(node.dest, var) and self._tree_any(node.src, is_impure):
                    return True

                return self._reads_before_impure(node.dest, var, also_named_vars)

            return False

        if isinstance(node, HLILExprStmt):
            return self._reads_before_impure(node.expr, var, also_named_vars)

        if isinstance(node, HLILIf):
            return self._reads_before_impure(node.condition, var, also_named_vars)

        if isinstance(node, HLILWhile):
            return self._reads_before_impure(node.condition, var, also_named_vars)

        if isinstance(node, HLILSwitch):
            return self._reads_before_impure(node.scrutinee, var, also_named_vars)

        if isinstance(node, HLILReturn):
            return self._reads_before_impure(node.value, var, also_named_vars) if node.value is not None else False

        return False

    def _may_exit(self, node) -> bool:
        '''Whether node contains a return, break, or continue anywhere in its tree, on SOME
        path - not necessarily every path (unlike the old _always_exits, this also catches a
        nested/partial early exit, e.g. `if (a) { if (b) return; }` - Codex Rule 2 round 8
        finding #5).

        A return always exits the function, at any nesting depth; break/continue only
        exit/restart the nearest loop or switch. This doesn't distinguish that: a break
        nested inside a loop that's itself inside node is, strictly, absorbed by that inner
        loop rather than affecting what comes after node - not tracked here, so this can flag
        a statement as conditional a little more often than strictly necessary, never less
        (finding #4/#4b only needed the direct, unnested case).
        '''
        return self._tree_any(node, lambda n: isinstance(n, (HLILReturn, HLILBreak, HLILContinue)))

    def _contains_return(self, node) -> bool:
        '''Whether node contains a return anywhere in its tree. Unlike _may_exit, this does
        NOT also match break/continue: used for HLILWhile/HLILDoWhile in _may_skip_later_code
        below, where a break/continue found directly in the loop's OWN body is not a hazard
        (break lands exactly where normal loop exit does - the position being asked about;
        continue never leaves the loop at all) - only a return, which escapes the function
        regardless of loop nesting, actually skips what comes after the loop (Codex Rule 2
        round 9 finding #3).'''
        return self._tree_any(node, lambda n: isinstance(n, HLILReturn))

    def _may_skip_later_code(self, stmt) -> bool:
        '''Whether taking stmt might skip code that follows it in the same block - true when
        either branch of an if, or any case of a switch (Codex Rule 2 round 8 finding #6),
        might return/break/continue on some path through it, even if not on every path (a
        nested/partial early exit still skips the rest of this block on whichever paths
        reach it) - or when a while/do-while loop's body might return (Codex Rule 2 round 9
        finding #3; break/continue excluded there, see _contains_return).'''
        if isinstance(stmt, HLILIf):
            return self._may_exit(stmt.true_block) or self._may_exit(stmt.false_block)

        if isinstance(stmt, HLILSwitch):
            return any(self._may_exit(case.body) for case in stmt.cases)

        if isinstance(stmt, (HLILWhile, HLILDoWhile)):
            return self._contains_return(stmt.body)

        return False

    def _is_use_at_entry(self, stmt, var: HLILVariable) -> bool:
        '''Check if var's use is at the entry point of stmt (evaluated first).'''
        if isinstance(stmt, HLILIf):
            return self._contains_var(stmt.condition, var)

        if isinstance(stmt, HLILWhile):
            return self._contains_var(stmt.condition, var)

        if isinstance(stmt, HLILAssign):
            return self._contains_var(stmt.src, var)

        if isinstance(stmt, HLILExprStmt):
            return self._contains_var(stmt.expr, var)

        if isinstance(stmt, HLILReturn):
            return self._contains_var(stmt.value, var)

        return False

    def _contains_var(self, expr, var: HLILVariable) -> bool:
        '''Check if expression contains var.'''
        if expr is None:
            return False

        if isinstance(expr, HLILVar):
            return expr.var == var

        if isinstance(expr, HLILBinaryOp):
            return self._contains_var(expr.lhs, var) or self._contains_var(expr.rhs, var)

        if isinstance(expr, (HLILUnaryOp, HLILAddressOf, HLILDeref)):
            return self._contains_var(expr.operand, var)

        if isinstance(expr, (HLILCall, HLILSyscall, HLILExternCall)):
            return any(self._contains_var(arg, var) for arg in expr.args)

        return False

    def _replace_var(self, stmts: list, var: HLILVariable, replacement: HLILExpression) -> bool:
        '''Replace first occurrence of var with replacement. Returns True if replaced.'''
        for stmt in stmts:
            if self._replace_var_in_node(stmt, var, replacement):
                return True
        return False

    def _replace_var_in_node(self, node, var: HLILVariable, replacement: HLILExpression) -> bool:
        '''Replace var in node. Returns True if replaced.'''
        if node is None:
            return False

        if isinstance(node, HLILBinaryOp):
            if isinstance(node.lhs, HLILVar) and node.lhs.var == var:
                node.lhs = replacement
                return True

            if self._replace_var_in_node(node.lhs, var, replacement):
                return True

            if isinstance(node.rhs, HLILVar) and node.rhs.var == var:
                node.rhs = replacement
                return True

            return self._replace_var_in_node(node.rhs, var, replacement)

        if isinstance(node, HLILUnaryOp):
            if isinstance(node.operand, HLILVar) and node.operand.var == var:
                node.operand = replacement
                return True

            return self._replace_var_in_node(node.operand, var, replacement)

        if isinstance(node, HLILAddressOf):
            # Cannot replace variable with constant in address-of (need lvalue)
            return False

        if isinstance(node, HLILDeref):
            # Unlike AddressOf, a pointer's VALUE is an ordinary operand - safe to substitute
            if isinstance(node.operand, HLILVar) and node.operand.var == var:
                node.operand = replacement
                return True

            return self._replace_var_in_node(node.operand, var, replacement)

        if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
            for i, arg in enumerate(node.args):
                if isinstance(arg, HLILVar) and arg.var == var:
                    node.args[i] = replacement
                    return True

                if self._replace_var_in_node(arg, var, replacement):
                    return True

            return False

        if isinstance(node, HLILAssign):
            if isinstance(node.src, HLILVar) and node.src.var == var:
                node.src = replacement
                return True

            if self._replace_var_in_node(node.src, var, replacement):
                return True

            # A store through a pointer (*dest = value) reads dest's own value too, unlike a
            # plain HLILVar dest. Recursing on node.dest itself reuses the HLILDeref branch
            # above instead of re-deriving its unwrap logic here.
            if isinstance(node.dest, HLILDeref):
                return self._replace_var_in_node(node.dest, var, replacement)

            return False

        if isinstance(node, HLILExprStmt):
            if isinstance(node.expr, HLILVar) and node.expr.var == var:
                node.expr = replacement
                return True

            return self._replace_var_in_node(node.expr, var, replacement)

        if isinstance(node, HLILIf):
            if isinstance(node.condition, HLILVar) and node.condition.var == var:
                node.condition = replacement
                return True

            if self._replace_var_in_node(node.condition, var, replacement):
                return True

            if node.true_block:
                if self._replace_var(node.true_block.statements, var, replacement):
                    return True

            if node.false_block:
                return self._replace_var(node.false_block.statements, var, replacement)

            return False

        if isinstance(node, HLILWhile):
            if isinstance(node.condition, HLILVar) and node.condition.var == var:
                node.condition = replacement
                return True

            if self._replace_var_in_node(node.condition, var, replacement):
                return True

            if node.body:
                return self._replace_var(node.body.statements, var, replacement)

            return False

        if isinstance(node, HLILDoWhile):
            if node.body:
                if self._replace_var(node.body.statements, var, replacement):
                    return True

            if isinstance(node.condition, HLILVar) and node.condition.var == var:
                node.condition = replacement
                return True

            return self._replace_var_in_node(node.condition, var, replacement)

        if isinstance(node, HLILSwitch):
            if isinstance(node.scrutinee, HLILVar) and node.scrutinee.var == var:
                node.scrutinee = replacement
                return True

            if self._replace_var_in_node(node.scrutinee, var, replacement):
                return True

            for case in node.cases:
                if self._replace_var(case.body.statements, var, replacement):
                    return True

            return False

        if isinstance(node, HLILReturn):
            if node.value:
                if isinstance(node.value, HLILVar) and node.value.var == var:
                    node.value = replacement
                    return True

                return self._replace_var_in_node(node.value, var, replacement)

            return False

        return False
