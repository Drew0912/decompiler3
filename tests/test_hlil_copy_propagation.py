#!/usr/bin/env python3
'''Unit tests for HLIL copy propagation (disabled pass, kept correct for its documented API).'''

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.hlil import (
    BinaryOp,
    CopyPropagationPass,
    HighLevelILFunction,
    HLILAddressOf,
    HLILAssign,
    HLILBinaryOp,
    HLILBlock,
    HLILBreak,
    HLILCall,
    HLILConst,
    HLILContinue,
    HLILDeref,
    HLILExprStmt,
    HLILIf,
    HLILReturn,
    HLILSwitch,
    HLILSwitchCase,
    HLILVar,
    HLILVariable,
    HLILWhile,
)


TEST_FUNCTION_NAME = 'test_copy_propagation'
POINTER_ARG_VALUE = 0x1000
FLAG_TRUE_VALUE = 1


def run_pass(func: HighLevelILFunction) -> HighLevelILFunction:
    return CopyPropagationPass().run(func)


class TestReadsBeforeImpure(unittest.TestCase):
    '''Codex Rule 2 round 6, finding #1: propagating a call result across a sibling deref
    read within the same statement must not reorder the deref before the call.'''

    def test_effectful_source_not_propagated_across_earlier_sibling_deref(self):
        # r = f(); x = *p + r  ->  must NOT become x = *p + f() (reorders *p before f())
        r = HLILVariable('r')
        x = HLILVariable('x')
        p = HLILVariable('p')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        func.add_statement(HLILAssign(
            HLILVar(x),
            HLILBinaryOp(BinaryOp.ADD, HLILDeref(HLILVar(p)), HLILVar(r))
        ))

        result = run_pass(func)

        # The call must still be its own statement - not folded into the second assign's src
        self.assertEqual(len(result.body.statements), 2)
        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_effectful_source_still_propagated_without_a_sibling_deref(self):
        # r = f(); x = r + 1 -> becomes x = f() + 1 (no deref hazard, still an optimization)
        r = HLILVariable('r')
        x = HLILVariable('x')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        func.add_statement(HLILAssign(HLILVar(x), HLILBinaryOp(BinaryOp.ADD, HLILVar(r), HLILConst(1))))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 1)
        stmt = result.body.statements[0]
        self.assertIsInstance(stmt, HLILAssign)
        self.assertIsInstance(stmt.src, HLILBinaryOp)
        self.assertIsInstance(stmt.src.lhs, HLILCall)


class TestConditionalBranchPropagation(unittest.TestCase):
    '''Codex Rule 2 round 6, finding #3: propagating an effectful/impure expression into a
    use nested inside only one if-branch must not turn an unconditional call into a
    conditionally-executed one.'''

    def test_effectful_source_not_propagated_into_if_branch(self):
        # r = f(); if (flag) { x = r; }  ->  must NOT become if (flag) { x = f(); }
        r = HLILVariable('r')
        x = HLILVariable('x')
        flag = HLILVariable('flag')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        func.add_statement(HLILIf(
            HLILVar(flag),
            HLILBlock([HLILAssign(HLILVar(x), HLILVar(r))]),
            None
        ))

        result = run_pass(func)

        # The call must still run unconditionally as its own statement before the if
        self.assertEqual(len(result.body.statements), 2)
        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_pure_source_still_propagated_into_if_branch(self):
        # a = 1; if (flag) { x = a; } -> becomes if (flag) { x = 1; } (no effect to preserve)
        a = HLILVariable('a')
        x = HLILVariable('x')
        flag = HLILVariable('flag')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(a), HLILConst(1)))
        func.add_statement(HLILIf(
            HLILVar(flag),
            HLILBlock([HLILAssign(HLILVar(x), HLILVar(a))]),
            None
        ))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 1)
        if_stmt = result.body.statements[0]
        self.assertIsInstance(if_stmt, HLILIf)
        inner_assign = if_stmt.true_block.statements[0]
        self.assertIsInstance(inner_assign.src, HLILConst)
        self.assertEqual(inner_assign.src.value, 1)

    def test_effectful_source_not_propagated_across_logical_and_rhs(self):
        # r = f(); x = flag && r  ->  must NOT become x = flag && f() (rhs is conditional)
        r = HLILVariable('r')
        x = HLILVariable('x')
        flag = HLILVariable('flag')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        func.add_statement(HLILAssign(HLILVar(x), HLILBinaryOp(BinaryOp.AND, HLILVar(flag), HLILVar(r))))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 2)
        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_effectful_source_not_propagated_across_logical_or_rhs(self):
        # r = f(); x = flag || r  ->  must NOT become x = flag || f()
        r = HLILVariable('r')
        x = HLILVariable('x')
        flag = HLILVariable('flag')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        func.add_statement(HLILAssign(HLILVar(x), HLILBinaryOp(BinaryOp.OR, HLILVar(flag), HLILVar(r))))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 2)
        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_effectful_source_not_propagated_past_a_one_sided_return(self):
        # r = f(); if (flag) { return; } x = r  ->  must NOT become
        # if (flag) { return; } x = f() (x = r is only reached when flag is false)
        r = HLILVariable('r')
        x = HLILVariable('x')
        flag = HLILVariable('flag')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        func.add_statement(HLILIf(HLILVar(flag), HLILBlock([HLILReturn(None)]), None))
        func.add_statement(HLILAssign(HLILVar(x), HLILVar(r)))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 3)
        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_pure_source_still_propagated_past_a_one_sided_return(self):
        # a = 1; if (flag) { return; } x = a -> becomes if (flag) { return; } x = 1
        a = HLILVariable('a')
        x = HLILVariable('x')
        flag = HLILVariable('flag')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(a), HLILConst(1)))
        func.add_statement(HLILIf(HLILVar(flag), HLILBlock([HLILReturn(None)]), None))
        func.add_statement(HLILAssign(HLILVar(x), HLILVar(a)))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 2)
        final_assign = result.body.statements[1]
        self.assertIsInstance(final_assign.src, HLILConst)
        self.assertEqual(final_assign.src.value, 1)


class TestPointerAliasingOfPureSource(unittest.TestCase):
    '''Codex Rule 2 round 7, finding #3: a deref-store must be treated as a conservative
    clobber of any named variable (matching how a call already is), not just gated behind
    the source expression's own impurity - a PURE named-variable read can be aliased too.'''

    def test_pure_var_not_propagated_across_an_intervening_deref_store(self):
        # p = &local; r = local; *p = value; x = r
        # must NOT become: p = &local; *p = value; x = local (reads post-store value)
        p = HLILVariable('p')
        local = HLILVariable('local')
        r = HLILVariable('r')
        x = HLILVariable('x')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(p), HLILAddressOf(HLILVar(local))))
        func.add_statement(HLILAssign(HLILVar(r), HLILVar(local)))
        func.add_statement(HLILAssign(HLILDeref(HLILVar(p)), HLILConst(POINTER_ARG_VALUE)))
        func.add_statement(HLILAssign(HLILVar(x), HLILVar(r)))

        result = run_pass(func)

        # r = local must survive as its own statement, not be folded into x = local
        assigns = [s for s in result.body.statements if isinstance(s, HLILAssign)]
        r_assigns = [s for s in assigns if isinstance(s.dest, HLILVar) and s.dest.var == r]
        self.assertEqual(len(r_assigns), 1)


class TestReadsBeforeImpureSwitch(unittest.TestCase):
    '''Codex Rule 2 round 7, finding #5: _reads_before_impure had no HLILSwitch case, even
    though _find_reachable_uses searches the switch scrutinee - the same reordering hazard
    as the binary-op case, just in a scrutinee position.'''

    def test_effectful_source_not_propagated_into_switch_scrutinee_across_a_deref(self):
        # r = f(); switch (*p + r) { case 1: a(); }
        # must NOT become: switch (*p + f()) { ... } (reorders *p before f())
        r = HLILVariable('r')
        p = HLILVariable('p')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(r), HLILCall('f', [])))
        scrutinee = HLILBinaryOp(BinaryOp.ADD, HLILDeref(HLILVar(p)), HLILVar(r))
        case = HLILSwitchCase([HLILConst(1)], HLILBlock([HLILExprStmt(HLILCall('a', []))]))
        func.add_statement(HLILSwitch(scrutinee, [case]))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 2)
        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)


class TestReadsBeforeImpureAcrossStatements(unittest.TestCase):
    '''Codex Rule 2 round 8, finding #1: an effectful source must not be propagated past an
    impure read sitting in an EARLIER, SEPARATE statement (not just a sibling within the use's
    own statement, which TestReadsBeforeImpure above already covers).'''

    def test_effectful_source_not_propagated_across_an_earlier_statements_deref(self):
        # tmp = f(); snapshot = *p; return tmp + snapshot
        # must NOT become: snapshot = *p; return f() + snapshot (reorders *p before f())
        tmp = HLILVariable('tmp')
        snapshot = HLILVariable('snapshot')
        p = HLILVariable('p')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(tmp), HLILCall('f', [])))
        func.add_statement(HLILAssign(HLILVar(snapshot), HLILDeref(HLILVar(p))))
        func.add_statement(HLILReturn(HLILBinaryOp(BinaryOp.ADD, HLILVar(tmp), HLILVar(snapshot))))

        result = run_pass(func)

        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_pure_deref_source_still_propagated_across_an_earlier_unrelated_assign(self):
        # snapshot = *p; other = 1; return snapshot -> the *p read has no effectful source
        # ahead of it, so this is still a safe, expected optimization
        snapshot = HLILVariable('snapshot')
        p = HLILVariable('p')
        other = HLILVariable('other')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(snapshot), HLILDeref(HLILVar(p))))
        func.add_statement(HLILAssign(HLILVar(other), HLILConst(1)))
        func.add_statement(HLILReturn(HLILVar(snapshot)))

        result = run_pass(func)

        final = result.body.statements[-1]
        self.assertIsInstance(final, HLILReturn)
        self.assertIsInstance(final.value, HLILDeref)


class TestModifiesVarsNestedCall(unittest.TestCase):
    '''Codex Rule 2 round 8, finding #2: _modifies_vars must recurse into a call nested inside
    a binary expression, not just a call that is the entire statement/source by itself.'''

    def test_pure_var_not_propagated_across_a_call_nested_in_a_binary_op(self):
        # tmp = x; out = call(&x) + tmp -> must NOT become out = call(&x) + x
        # (call(&x) writes x between the snapshot and its use)
        tmp = HLILVariable('tmp')
        x = HLILVariable('x')
        out = HLILVariable('out')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(tmp), HLILVar(x)))
        func.add_statement(HLILAssign(
            HLILVar(out),
            HLILBinaryOp(BinaryOp.ADD, HLILCall('call', [HLILAddressOf(HLILVar(x))]), HLILVar(tmp))
        ))

        result = run_pass(func)

        tmp_assigns = [s for s in result.body.statements
                       if isinstance(s, HLILAssign) and isinstance(s.dest, HLILVar) and s.dest.var == tmp]
        self.assertEqual(len(tmp_assigns), 1)


class TestReadsBeforeImpureCallWritesNamedVar(unittest.TestCase):
    '''Codex Rule 2 round 8, finding #3: a call about to replace var must not move past an
    earlier sibling read of some OTHER named variable, since a call is conservatively assumed
    able to write any named variable (matching _modifies_vars's own policy) - not just past a
    deref, which TestReadsBeforeImpure above already covers.'''

    def test_call_with_addr_taken_arg_not_propagated_across_an_earlier_sibling_read(self):
        # tmp = call(&x); out = x + tmp -> must NOT become out = x + call(&x)
        # (reorders x's read to before the call that may write through &x)
        tmp = HLILVariable('tmp')
        x = HLILVariable('x')
        out = HLILVariable('out')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(tmp), HLILCall('call', [HLILAddressOf(HLILVar(x))])))
        func.add_statement(HLILAssign(HLILVar(out), HLILBinaryOp(BinaryOp.ADD, HLILVar(x), HLILVar(tmp))))

        result = run_pass(func)

        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_call_still_propagated_when_no_other_named_var_is_read_first(self):
        # tmp = call(&x); out = tmp + 1 -> becomes out = call(&x) + 1 (no sibling var to reorder)
        tmp = HLILVariable('tmp')
        x = HLILVariable('x')
        out = HLILVariable('out')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(tmp), HLILCall('call', [HLILAddressOf(HLILVar(x))])))
        func.add_statement(HLILAssign(HLILVar(out), HLILBinaryOp(BinaryOp.ADD, HLILVar(tmp), HLILConst(1))))

        result = run_pass(func)

        self.assertEqual(len(result.body.statements), 1)
        stmt = result.body.statements[0]
        self.assertIsInstance(stmt.src, HLILBinaryOp)
        self.assertIsInstance(stmt.src.lhs, HLILCall)


class TestBreakContinueMakeLaterCodeConditional(unittest.TestCase):
    '''Codex Rule 2 round 8, findings #4/#4b: break/continue skip the rest of their enclosing
    block on the paths that take them, the same way a one-sided return does - an effectful
    source defined before them must not be propagated to a use positioned after.'''

    def test_effectful_source_not_propagated_past_a_conditional_continue(self):
        # while (1) { tmp = f(); if (cond) continue; x = tmp; }
        # must NOT become: while (1) { if (cond) continue; x = f(); }
        tmp = HLILVariable('tmp')
        cond = HLILVariable('cond')
        x = HLILVariable('x')

        body = HLILBlock([
            HLILAssign(HLILVar(tmp), HLILCall('f', [])),
            HLILIf(HLILVar(cond), HLILBlock([HLILContinue()]), None),
            HLILAssign(HLILVar(x), HLILVar(tmp)),
        ])
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILWhile(HLILConst(1), body))

        result = run_pass(func)

        loop_body = result.body.statements[0].body.statements
        first = loop_body[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_effectful_source_not_propagated_past_a_conditional_break(self):
        # while (1) { tmp = f(); if (cond) break; x = tmp; }
        # must NOT become: while (1) { if (cond) break; x = f(); }
        tmp = HLILVariable('tmp')
        cond = HLILVariable('cond')
        x = HLILVariable('x')

        body = HLILBlock([
            HLILAssign(HLILVar(tmp), HLILCall('f', [])),
            HLILIf(HLILVar(cond), HLILBlock([HLILBreak()]), None),
            HLILAssign(HLILVar(x), HLILVar(tmp)),
        ])
        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILWhile(HLILConst(1), body))

        result = run_pass(func)

        loop_body = result.body.statements[0].body.statements
        first = loop_body[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)


class TestNestedOneSidedReturnMakesLaterCodeConditional(unittest.TestCase):
    '''Codex Rule 2 round 8, finding #5: a return nested two levels deep in a lone if (no
    else) still makes code after the OUTER if conditionally reached, even though neither the
    outer if's true_block, nor the inner if alone, "always" returns.'''

    def test_effectful_source_not_propagated_past_a_nested_conditional_return(self):
        # tmp = f(); if (a) { if (b) return; } x = tmp
        # must NOT become: if (a) { if (b) return; } x = f()
        # (the a && b path skips x = tmp entirely in the original, so f() must still run there)
        tmp = HLILVariable('tmp')
        a = HLILVariable('a')
        b = HLILVariable('b')
        x = HLILVariable('x')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(tmp), HLILCall('f', [])))
        inner_if = HLILIf(HLILVar(b), HLILBlock([HLILReturn(None)]), None)
        outer_if = HLILIf(HLILVar(a), HLILBlock([inner_if]), None)
        func.add_statement(outer_if)
        func.add_statement(HLILAssign(HLILVar(x), HLILVar(tmp)))

        result = run_pass(func)

        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)


class TestSwitchWithReturningCaseMakesLaterCodeConditional(unittest.TestCase):
    '''Codex Rule 2 round 8, finding #6: a switch where some case always returns makes code
    after the switch conditionally reached (only via the non-returning cases), the same way a
    one-sided if/return does.'''

    def test_effectful_source_not_propagated_past_a_switch_with_a_returning_case(self):
        # tmp = f(); switch (s) { case 0: return; default: y = 1; } x = tmp
        # must NOT become: switch (s) { case 0: return; default: y = 1; } x = f()
        tmp = HLILVariable('tmp')
        s = HLILVariable('s')
        y = HLILVariable('y')
        x = HLILVariable('x')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(tmp), HLILCall('f', [])))
        case0 = HLILSwitchCase([HLILConst(0)], HLILBlock([HLILReturn(None)]))
        case_default = HLILSwitchCase(None, HLILBlock([HLILAssign(HLILVar(y), HLILConst(1))]))
        func.add_statement(HLILSwitch(HLILVar(s), [case0, case_default]))
        func.add_statement(HLILAssign(HLILVar(x), HLILVar(tmp)))

        result = run_pass(func)

        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)


class TestReadsAnyVarAcrossStatements(unittest.TestCase):
    '''Codex Rule 2 round 9, finding #1: a call about to replace var must not move past an
    earlier, SEPARATE statement that reads some other named variable (the cross-statement
    counterpart to TestReadsBeforeImpureCallWritesNamedVar above, which only covers a sibling
    read within the use's own statement).'''

    def test_call_not_propagated_across_an_earlier_statements_read_of_another_var(self):
        # var = call(&x); p = x; value = var; return p
        # must NOT become: p = x; value = call(&x); return p (reorders x's read before the call)
        var = HLILVariable('var')
        x = HLILVariable('x')
        p = HLILVariable('p')
        value = HLILVariable('value')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(var), HLILCall('call', [HLILAddressOf(HLILVar(x))])))
        func.add_statement(HLILAssign(HLILVar(p), HLILVar(x)))
        func.add_statement(HLILAssign(HLILVar(value), HLILVar(var)))
        func.add_statement(HLILReturn(HLILVar(p)))

        result = run_pass(func)

        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILCall)

    def test_pure_var_still_propagated_across_an_earlier_unrelated_statement(self):
        # a = 1; p = x; return a -> becomes p = x; return 1 (no call involved, nothing to guard)
        a = HLILVariable('a')
        x = HLILVariable('x')
        p = HLILVariable('p')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(a), HLILConst(1)))
        func.add_statement(HLILAssign(HLILVar(p), HLILVar(x)))
        func.add_statement(HLILReturn(HLILVar(a)))

        result = run_pass(func)

        final = result.body.statements[-1]
        self.assertIsInstance(final, HLILReturn)
        self.assertIsInstance(final.value, HLILConst)
        self.assertEqual(final.value.value, 1)


class TestSwitchPartialKillDoesNotTruncateUseScan(unittest.TestCase):
    '''Codex Rule 2 round 9, finding #2: a kill (reassignment) in only SOME cases of a switch
    must not cause the pass to conclude the scrutinee is the sole use and delete the original
    definition - a non-killing case can still reach code after the switch that reads the
    original value.'''

    def test_definition_survives_when_only_one_case_kills_the_scrutinee_var(self):
        # var = value; switch (var) { case 0: var = x; default: } return var
        # must NOT delete `var = value` - the default case reaches `return var` with no
        # reassignment, so it still needs the original definition
        var = HLILVariable('var')
        value = HLILVariable('value')
        x = HLILVariable('x')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(var), HLILVar(value)))
        case0 = HLILSwitchCase([HLILConst(0)], HLILBlock([HLILAssign(HLILVar(var), HLILVar(x))]))
        case_default = HLILSwitchCase(None, HLILBlock([]))
        func.add_statement(HLILSwitch(HLILVar(var), [case0, case_default]))
        func.add_statement(HLILReturn(HLILVar(var)))

        result = run_pass(func)

        def_survives = any(isinstance(s, HLILAssign) and isinstance(s.dest, HLILVar) and s.dest.var == var
                            and isinstance(s.src, HLILVar) and s.src.var == value
                            for s in result.body.statements)
        self.assertTrue(def_survives)


class TestReturnInsideLoopMakesLaterCodeConditional(unittest.TestCase):
    '''Codex Rule 2 round 9, finding #3: a return reachable inside a while/do-while loop's
    body makes code positioned after the loop conditionally reached (skipped on the
    early-return path), the same way a one-sided if/return does outside a loop.'''

    def test_effectful_source_not_propagated_past_a_loop_with_an_internal_return(self):
        # var = *p; while (cond) { if (x) return value; } result = var
        # must NOT become: while (cond) { if (x) return value; } result = *p
        # (the early-return path in the original still ran *p before the loop)
        var = HLILVariable('var')
        p = HLILVariable('p')
        cond = HLILVariable('cond')
        x = HLILVariable('x')
        result_v = HLILVariable('result')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(var), HLILDeref(HLILVar(p))))
        inner_if = HLILIf(HLILVar(x), HLILBlock([HLILReturn(HLILConst(1))]), None)
        func.add_statement(HLILWhile(HLILVar(cond), HLILBlock([inner_if])))
        func.add_statement(HLILAssign(HLILVar(result_v), HLILVar(var)))

        result = run_pass(func)

        first = result.body.statements[0]
        self.assertIsInstance(first, HLILAssign)
        self.assertIsInstance(first.src, HLILDeref)


class TestMayClobberImpureReadNamedVarStore(unittest.TestCase):
    '''Codex Rule 2 round 9, finding #4: a store to a named variable whose address is taken
    somewhere in the function must be treated as a possible clobber of a pending impure read,
    the same "no alias analysis" reasoning _modifies_vars already applies in the opposite
    direction for deref-stores. Scoped to address-taken variables specifically (not every
    named variable) - see the docstring on _may_clobber_impure_read for why the unscoped
    version regressed other propagation.'''

    def test_deref_source_not_propagated_across_a_store_to_an_address_taken_var(self):
        # p = &x; var = *p; x = value; return var
        # must NOT become: p = &x; x = value; return *p (reads *p AFTER x is overwritten)
        p = HLILVariable('p')
        x = HLILVariable('x')
        var = HLILVariable('var')
        value = HLILVariable('value')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(p), HLILAddressOf(HLILVar(x))))
        func.add_statement(HLILAssign(HLILVar(var), HLILDeref(HLILVar(p))))
        func.add_statement(HLILAssign(HLILVar(x), HLILVar(value)))
        func.add_statement(HLILReturn(HLILVar(var)))

        result = run_pass(func)

        def_survives = any(isinstance(s, HLILAssign) and isinstance(s.dest, HLILVar) and s.dest.var == var
                            and isinstance(s.src, HLILDeref) for s in result.body.statements)
        self.assertTrue(def_survives)

    def test_deref_source_still_propagated_across_a_store_to_a_non_address_taken_var(self):
        # var = *p; y = value; return var -> still becomes return *p (y's address is never
        # taken anywhere, so it cannot be what p points at)
        var = HLILVariable('var')
        p = HLILVariable('p')
        y = HLILVariable('y')
        value = HLILVariable('value')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(var), HLILDeref(HLILVar(p))))
        func.add_statement(HLILAssign(HLILVar(y), HLILVar(value)))
        func.add_statement(HLILReturn(HLILVar(var)))

        result = run_pass(func)

        final = result.body.statements[-1]
        self.assertIsInstance(final, HLILReturn)
        self.assertIsInstance(final.value, HLILDeref)


class TestUnreachableCodeAfterTerminatorIsNotScannedForUses(unittest.TestCase):
    '''Codex Rule 2 round 9, finding #5: a statement positioned after an unconditional
    return/break/continue, in the same statement list, is unreachable and must not be treated
    as a real use - otherwise an effectful definition can be deleted from its live position and
    moved into code that never runs.'''

    def test_effectful_def_not_moved_into_dead_code_after_a_return(self):
        # var = call(); return value; p = var  (p = var is unreachable)
        # must NOT become: return value; p = call() (the call no longer ever runs)
        var = HLILVariable('var')
        value = HLILVariable('value')
        p = HLILVariable('p')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        func.add_statement(HLILAssign(HLILVar(var), HLILCall('call', [])))
        func.add_statement(HLILReturn(HLILVar(value)))
        func.add_statement(HLILAssign(HLILVar(p), HLILVar(var)))

        result = run_pass(func)

        call_before_return = False
        for stmt in result.body.statements:
            if isinstance(stmt, HLILReturn):
                break
            if isinstance(stmt, HLILAssign) and isinstance(stmt.dest, HLILVar) and stmt.dest.var == var \
                    and isinstance(stmt.src, HLILCall):
                call_before_return = True
        self.assertTrue(call_before_return)

    def test_effectful_def_not_moved_into_dead_code_after_a_break(self):
        # while (1) { var = call(); break; p = var; } (p = var is unreachable)
        # must NOT delete `var = call()` - it has no reachable use, so it just stays put
        var = HLILVariable('var')
        p = HLILVariable('p')

        func = HighLevelILFunction(TEST_FUNCTION_NAME)
        body = HLILBlock([
            HLILAssign(HLILVar(var), HLILCall('call', [])),
            HLILBreak(),
            HLILAssign(HLILVar(p), HLILVar(var)),
        ])
        func.add_statement(HLILWhile(HLILConst(1), body))

        result = run_pass(func)

        loop_body = result.body.statements[0].body.statements
        call_survives = any(isinstance(s, HLILAssign) and isinstance(s.dest, HLILVar) and s.dest.var == var
                             and isinstance(s.src, HLILCall) for s in loop_body)
        self.assertTrue(call_survives)


if __name__ == '__main__':
    unittest.main()
