"""Loop Recovery Pass

Turn the while(1) shape that structuring produces back into a tested loop:

    while (1) { if (c) break; body }    ->  while (!c) { body }
    while (1) { body; if (c) break; }   ->  do { body } while (!c)
    while (1) { body; if (c) continue; else break; }   ->  do { body } while (c)
    while (1) { if (c) return x; body } ->  while (!c) { body } return x

Also folds constant loop conditions and drops a trailing continue, which says
nothing at the end of a loop body
"""

from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILStatement,
    HLILExpression,
    HLILConst,
    HLILBinaryOp,
    HLILIf,
    HLILWhile,
    HLILDoWhile,
    HLILBreak,
    HLILContinue,
    HLILReturn,
    HLILComment,
    HLILUnstructured,
    BinaryOp,
    COMPARISON_FUNCTIONS,
    comment_statements,
    contains_escaping_exit,
    drop_trailing_continue,
    iter_tree,
    negate_condition,
    sole_statement,
    sub_blocks,
)


class LoopRecoveryPass(Pass):
    """Recover loop conditions from while(1) bodies"""

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._process_block(func.body)
        return func

    def _process_block(self, block: HLILBlock):
        # Rebuilt rather than assigned in place: recovery can turn one loop into a
        # loop plus the statements hoisted out after it
        recovered: list[HLILStatement] = []

        for stmt in block.statements:
            for child in sub_blocks(stmt):
                self._process_block(child)

            if isinstance(stmt, HLILWhile):
                recovered.extend(self._recover_loop(stmt))
            else:
                recovered.append(stmt)

        block.statements = recovered

    def _recover_loop(self, loop: HLILWhile) -> list[HLILStatement]:
        """Rewrite an unconditional loop whose body only guards its own exit"""
        # A jump HLIL could not express may leave or re-enter the loop: keep the loop as built
        if any(isinstance(node, HLILUnstructured) for node in iter_tree(loop.body)):
            return [loop]

        drop_trailing_continue(loop.body)
        loop.condition = self._fold_constant_condition(loop.condition)

        if not self._is_always_true(loop.condition):
            return [loop]

        guarded = self._guarded_body(loop.body)
        if guarded is not None:
            loop.condition, loop.body = guarded
            drop_trailing_continue(loop.body)
            return [loop]

        leading_exit = self._leading_exit_condition(loop.body)
        if leading_exit is not None:
            loop.condition = leading_exit
            return [loop]

        leading_return = self._leading_exit_return(loop.body)
        if leading_return is not None:
            loop.condition, trailing = leading_return
            return [loop] + trailing

        # Before the continue check below: this test's continue arm is one, and it goes
        trailing_test = self._trailing_continue_test(loop.body)
        if trailing_test is not None:
            return [self._do_while(trailing_test, loop)]

        # Checked before _trailing_exit_condition, which mutates loop.body - refusing after
        # that mutation would return a "left unchanged" while(1) loop that had already lost
        # its own trailing break
        if contains_escaping_exit(loop.body, HLILContinue, include_labeled=True):
            return [loop]

        trailing_exit = self._trailing_exit_condition(loop.body)
        if trailing_exit is not None:
            return [self._do_while(trailing_exit, loop)]

        return [loop]

    def _do_while(self, condition: HLILExpression, loop: HLILWhile) -> HLILDoWhile:
        """loop's body tested at its end by condition, the loop's label and provenance kept"""
        new_loop = HLILDoWhile(condition, loop.body, label=loop.label)
        new_loop.address = loop.address
        new_loop.mlil_index = loop.mlil_index
        return new_loop

    def _trailing_continue_test(self, body: HLILBlock) -> HLILExpression | None:
        """Condition of a trailing `if (c) continue; else break;` (c; its mirror's negated), taken off the body: the
        continue does what the body's end does. Each arm the unlabeled statement alone, so no comment is lost; and
        nothing else in the body continues, since a continue in a do-while runs the test"""
        if not body.statements or not isinstance(body.statements[-1], HLILIf):
            return None

        stmt = body.statements[-1]
        arms = (self._bare_jump(stmt.true_block), self._bare_jump(stmt.false_block))
        if arms == (HLILContinue, HLILBreak):
            condition = stmt.condition
        elif arms == (HLILBreak, HLILContinue):
            condition = negate_condition(stmt.condition)
        else:
            return None

        if contains_escaping_exit(HLILBlock(body.statements[:-1]), HLILContinue, include_labeled=True):
            return None

        del body.statements[-1]
        return condition

    def _bare_jump(self, block: HLILBlock | None) -> type | None:
        """HLILBreak or HLILContinue, when block holds that unlabeled statement and nothing else"""
        if block is None or len(block.statements) != 1:
            return None

        stmt = block.statements[0]
        if isinstance(stmt, (HLILBreak, HLILContinue)) and stmt.label is None:
            return type(stmt)
        return None

    def _guarded_body(self, body: HLILBlock) -> tuple | None:
        """while (1) { if (c) {...} else { break } } -> while (c) { ... }"""
        index = self._first_real_statement(body)
        if index is None or index != len(body.statements) - 1:
            return None

        stmt = body.statements[index]
        if not isinstance(stmt, HLILIf):
            return None

        if self._is_only_break(stmt.false_block):
            condition = stmt.condition
            new_body = stmt.true_block or HLILBlock()
        elif self._is_only_break(stmt.true_block) and stmt.false_block:
            condition = negate_condition(stmt.condition)
            new_body = stmt.false_block
        else:
            return None

        # Comments above the test are re-read on every iteration with it
        new_body.statements[:0] = body.statements[:index]
        return (condition, new_body)

    def _is_only_break(self, block: HLILBlock | None) -> bool:
        """Check that a block does nothing but leave the loop"""
        inner = sole_statement(block)
        return isinstance(inner, HLILBreak) and inner.label is None

    def _leading_exit_condition(self, body: HLILBlock) -> HLILExpression | None:
        """Condition of a leading `if (c) break;`, negated to become the loop test"""
        index = self._first_real_statement(body)
        if index is None:
            return None

        stmt = body.statements[index]
        if not self._is_lone_break(stmt):
            return None

        # Comments above the test stay at the top of the body, with the test - and the
        # break's own comments stay where the test was, since the break becomes that test
        body.statements[index : index + 1] = comment_statements(stmt.true_block)
        return negate_condition(stmt.condition)

    def _leading_exit_return(self, body: HLILBlock) -> tuple | None:
        """Leading `if (c) { return x; }` becomes the test, with the return after the loop

        Only sound while nothing in the body breaks out of this loop: a break leaves
        it without returning, and the hoisted return would then swallow that path
        """
        index = self._first_real_statement(body)
        if index is None:
            return None

        stmt = body.statements[index]
        if not self._is_lone_return(stmt):
            return None

        if contains_escaping_exit(body, HLILBreak, include_labeled=True):
            return None

        # The guard's whole body moves out, comments included, so a line comment
        # stays with the return it belongs to
        trailing = list(stmt.true_block.statements)
        del body.statements[index]

        return (negate_condition(stmt.condition), trailing)

    def _is_lone_return(self, stmt: HLILStatement) -> bool:
        """Check for `if (c) { return x; }` with no else branch"""
        if not isinstance(stmt, HLILIf):
            return False

        if stmt.false_block and stmt.false_block.statements:
            return False

        return isinstance(sole_statement(stmt.true_block), HLILReturn)

    def _trailing_exit_condition(self, body: HLILBlock) -> HLILExpression | None:
        """Condition of a trailing `if (c) break;`, negated to become the loop test"""
        if not body.statements:
            return None

        stmt = body.statements[-1]
        if not self._is_lone_break(stmt):
            return None

        # A body that is only its own exit test is not a do-while
        if self._first_real_statement(body) == len(body.statements) - 1:
            return None

        # The break becomes the loop test, so its comments stay where the test was
        body.statements[-1:] = comment_statements(stmt.true_block)
        return negate_condition(stmt.condition)

    def _is_lone_break(self, stmt: HLILStatement) -> bool:
        """Check for `if (c) break;` with no else branch"""
        if not isinstance(stmt, HLILIf):
            return False

        if stmt.false_block and stmt.false_block.statements:
            return False

        return self._is_only_break(stmt.true_block)

    def _first_real_statement(self, body: HLILBlock) -> int | None:
        """Index of the first statement that is not a comment"""
        for index, stmt in enumerate(body.statements):
            if not isinstance(stmt, HLILComment):
                return index

        return None

    def _fold_constant_condition(self, condition: HLILExpression) -> HLILExpression:
        """Reduce an == or != between two constants to a single constant"""
        if not isinstance(condition, HLILBinaryOp) or condition.op not in (BinaryOp.EQ, BinaryOp.NE):
            return condition

        if not isinstance(condition.lhs, HLILConst) or not isinstance(condition.rhs, HLILConst):
            return condition

        # Float comparisons stay as written: the VM's float32 compare is known statically, not traced
        # (docs/falcom/ed9/ED9_VM.md, Comparisons)
        if isinstance(condition.lhs.value, float) or isinstance(condition.rhs.value, float):
            return condition

        return HLILConst(int(COMPARISON_FUNCTIONS[condition.op](condition.lhs.value, condition.rhs.value)))

    def _is_always_true(self, condition: HLILExpression) -> bool:
        # A float constant's truth depends on what tests it (docs/falcom/ed9/ED9_VM.md, Truth)
        if not isinstance(condition, HLILConst) or isinstance(condition.value, float):
            return False

        return condition.value not in (0, False)
