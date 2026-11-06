"""Switch Recovery Pass"""

from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILVar,
    HLILConst,
    HLILBinaryOp,
    HLILIf,
    HLILSwitch,
    HLILSwitchCase,
    BinaryOp,
    OR_OPS,
    contains_bare_break,
    sole_statement,
    strip_truth_test,
    sub_blocks,
)


# Below this a chain reads better as if/else-if than as a switch
SWITCH_MIN_CASES = 3


class SwitchRecoveryPass(Pass):
    """Chains of equality tests on one variable become a switch, absorbing a switch already built from the rest of
    the chain"""

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._recover_switches(func.body)
        return func

    def _recover_switches(self, block: HLILBlock):
        for index, stmt in enumerate(block.statements):
            for child in sub_blocks(stmt):
                self._recover_switches(child)

            if isinstance(stmt, HLILIf):
                block.statements[index] = self._try_convert_to_switch(stmt) or stmt

    def _equality_labels(self, cond) -> tuple[HLILVar, list[int], bool] | None:
        """(scrutinee, values, negated) of a test `x == k`, `x != k` or an || of `x == k`s, each read through its truth
        tests (the stack translator keeps the LLIL's `(x == k) == 0`)

        The scrutinee must be a plain variable: a folded call would be evaluated
        once by the switch but once per test by the chain it replaces
        """
        test, negated = strip_truth_test(cond)
        if not isinstance(test, HLILBinaryOp):
            return None

        if test.op in OR_OPS:
            left = self._equality_labels(test.lhs)
            right = self._equality_labels(test.rhs)

            if left is None or right is None or left[2] or right[2]:
                return None

            if left[0].var != right[0].var:
                return None

            return left[0], left[1] + right[1], negated

        if test.op in (BinaryOp.EQ, BinaryOp.NE) and isinstance(test.lhs, HLILVar) and isinstance(test.rhs, HLILConst):
            return test.lhs, [test.rhs.value], negated ^ (test.op == BinaryOp.NE)

        return None

    def _switch_link(self, if_stmt: HLILIf):
        """One link of a dispatch chain as (scrutinee, values, case body, continuation)

        should_invert_condition can pick either orientation per link, so a chain may
        alternate between them; a negated test's case body is the else
        """
        match = self._equality_labels(if_stmt.condition)
        if match is None:
            return None

        scrutinee, values, negated = match
        if negated:
            return scrutinee, values, if_stmt.false_block, if_stmt.true_block

        return scrutinee, values, if_stmt.true_block, if_stmt.false_block

    def _try_convert_to_switch(self, if_stmt: HLILIf) -> HLILSwitch | None:
        """Convert a chain of equality tests on one variable into a switch

        Handles `==`, `!=` and ||-grouped links in any order, each also under a
        truth test, so a chain that alternates between them still becomes one
        switch. The chain is only read until the conversion is certain, so one
        that stays an if keeps its comments.
        """
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

            seen_case_values.update(values)
            # Comments sat before the test that is about to disappear
            cases.append((values, pending_comments, case_body))
            pending_comments = []

            # Walk the continuation: another link, a switch already built from the
            # rest of the chain, or the default body
            current_if = None

            if continuation and continuation.statements:
                sole = sole_statement(continuation)

                if isinstance(sole, (HLILIf, HLILSwitch)):
                    # A comment after the rest of the chain marks a source statement there: the chain isn't flat
                    if continuation.statements[-1] is not sole:
                        return None

                    pending_comments = continuation.statements[:-1]

                if isinstance(sole, HLILIf):
                    current_if = sole
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
                        # The nested switch's first case is the test they sat before
                        cases.append((nested_values, pending_comments, nested_case.body))
                        pending_comments = []
                else:
                    default_body = continuation

        if len(cases) < SWITCH_MIN_CASES or scrutinee is None:
            return None

        # A bare loop break inside a case would become a switch break after conversion
        if any(contains_bare_break(body) for _, _, body in cases) or contains_bare_break(default_body):
            return None

        switch_cases = []
        for values, comments, body in cases:
            body = body or HLILBlock()
            body.statements[:0] = comments
            switch_cases.append(HLILSwitchCase([HLILConst(v) for v in values], body))

        if default_body and default_body.statements:
            switch_cases.append(HLILSwitchCase(None, default_body))

        return HLILSwitch(scrutinee, switch_cases)
