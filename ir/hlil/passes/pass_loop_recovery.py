'''Loop Recovery Pass

Turn the while(1) shape that structuring produces back into a tested loop:

    while (1) { if (c) break; body }    ->  while (!c) { body }
    while (1) { body; if (c) break; }   ->  do { body } while (!c)
    while (1) { if (c) return x; body } ->  while (!c) { body } return x

Also folds constant loop conditions and drops a trailing continue, which says
nothing at the end of a loop body.
'''

from typing import List, Optional
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
    contains_escaping_exit,
    iter_tree,
    negate_condition,
    sole_statement,
    sub_blocks,
)


class LoopRecoveryPass(Pass):
    '''Recover loop conditions from while(1) bodies'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._process_block(func.body)
        return func

    def _process_block(self, block: Optional[HLILBlock]):
        if not block or not block.statements:
            return

        # Rebuilt rather than assigned in place: recovery can turn one loop into a
        # loop plus the statements hoisted out after it
        recovered: List[HLILStatement] = []

        for stmt in block.statements:
            for child in sub_blocks(stmt):
                self._process_block(child)

            if isinstance(stmt, HLILWhile):
                recovered.extend(self._recover_loop(stmt))

            else:
                recovered.append(stmt)

        block.statements = recovered

    def _recover_loop(self, loop: HLILWhile) -> List[HLILStatement]:
        '''Rewrite an unconditional loop whose body only guards its own exit'''
        # A jump HLIL could not express may leave or re-enter the loop: keep the loop as built
        if any(isinstance(node, HLILUnstructured) for node in iter_tree(loop.body)):
            return [loop]

        self._drop_trailing_continue(loop.body)
        loop.condition = self._fold_constant_condition(loop.condition)

        if not self._is_always_true(loop.condition):
            return [loop]

        guarded = self._guarded_body(loop.body)
        if guarded is not None:
            loop.condition, loop.body = guarded
            self._drop_trailing_continue(loop.body)
            return [loop]

        leading_exit = self._leading_exit_condition(loop.body)
        if leading_exit is not None:
            loop.condition = leading_exit
            return [loop]

        leading_return = self._leading_exit_return(loop.body)
        if leading_return is not None:
            loop.condition, trailing = leading_return
            return [loop] + trailing

        # Checked before _trailing_exit_condition, which mutates loop.body - refusing after
        # that mutation would return a "left unchanged" while(1) loop that had already lost
        # its own trailing break
        if contains_escaping_exit(loop.body, HLILContinue, include_labeled = True):
            return [loop]

        trailing_exit = self._trailing_exit_condition(loop.body)
        if trailing_exit is not None:
            new_loop = HLILDoWhile(trailing_exit, loop.body, label = loop.label)
            new_loop.address = loop.address
            new_loop.mlil_index = loop.mlil_index
            return [new_loop]

        return [loop]

    def _guarded_body(self, body: HLILBlock) -> Optional[tuple]:
        '''while (1) { if (c) {...} else { break } } -> while (c) { ... }'''
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
        for comment in reversed(body.statements[:index]):
            new_body.statements.insert(0, comment)

        return (condition, new_body)

    def _is_only_break(self, block: Optional[HLILBlock]) -> bool:
        '''Check that a block does nothing but leave the loop'''
        inner = sole_statement(block)
        return isinstance(inner, HLILBreak) and inner.label is None

    def _leading_exit_condition(self, body: HLILBlock) -> Optional[HLILExpression]:
        '''Condition of a leading `if (c) break;`, negated to become the loop test'''
        index = self._first_real_statement(body)
        if index is None:
            return None

        stmt = body.statements[index]
        if not self._is_lone_break(stmt):
            return None

        # Comments above the test stay at the top of the body, with the test - and the
        # break's own comments stay where the test was, since the break becomes that test
        comments = [s for s in stmt.true_block.statements if isinstance(s, HLILComment)]
        body.statements[index : index + 1] = comments
        return negate_condition(stmt.condition)

    def _leading_exit_return(self, body: HLILBlock) -> Optional[tuple]:
        '''Leading `if (c) { return x; }` becomes the test, with the return after the loop

        Only sound while nothing in the body breaks out of this loop: a break leaves
        it without returning, and the hoisted return would then swallow that path.
        '''
        index = self._first_real_statement(body)
        if index is None:
            return None

        stmt = body.statements[index]
        if not self._is_lone_return(stmt):
            return None

        if contains_escaping_exit(body, HLILBreak, include_labeled = True):
            return None

        # The guard's whole body moves out, comments included, so a line comment
        # stays with the return it belongs to
        trailing = list(stmt.true_block.statements)
        del body.statements[index]

        return (negate_condition(stmt.condition), trailing)

    def _is_lone_return(self, stmt: HLILStatement) -> bool:
        '''Check for `if (c) { return x; }` with no else branch'''
        if not isinstance(stmt, HLILIf):
            return False

        if stmt.false_block and stmt.false_block.statements:
            return False

        return isinstance(sole_statement(stmt.true_block), HLILReturn)

    def _trailing_exit_condition(self, body: HLILBlock) -> Optional[HLILExpression]:
        '''Condition of a trailing `if (c) break;`, negated to become the loop test'''
        if not body.statements:
            return None

        stmt = body.statements[-1]
        if not self._is_lone_break(stmt):
            return None

        # A body that is only its own exit test is not a do-while
        if self._first_real_statement(body) == len(body.statements) - 1:
            return None

        # The break becomes the loop test, so its comments stay where the test was
        comments = [s for s in stmt.true_block.statements if isinstance(s, HLILComment)]
        body.statements[-1:] = comments
        return negate_condition(stmt.condition)

    def _is_lone_break(self, stmt: HLILStatement) -> bool:
        '''Check for `if (c) break;` with no else branch'''
        if not isinstance(stmt, HLILIf):
            return False

        if stmt.false_block and stmt.false_block.statements:
            return False

        return self._is_only_break(stmt.true_block)

    def _first_real_statement(self, body: HLILBlock) -> Optional[int]:
        '''Index of the first statement that is not a comment'''
        for index, stmt in enumerate(body.statements):
            if not isinstance(stmt, HLILComment):
                return index

        return None

    def _drop_trailing_continue(self, body: HLILBlock):
        '''Remove a continue that only restates what the end of the body does'''
        if body.statements and isinstance(body.statements[-1], HLILContinue):
            if body.statements[-1].label is None:
                body.statements.pop()

    def _fold_constant_condition(self, condition: HLILExpression) -> HLILExpression:
        '''Reduce an == or != between two constants to a single constant'''
        if not isinstance(condition, HLILBinaryOp) or condition.op not in (BinaryOp.EQ, BinaryOp.NE):
            return condition

        if not isinstance(condition.lhs, HLILConst) or not isinstance(condition.rhs, HLILConst):
            return condition

        # Float comparisons are unverified in the VM
        if isinstance(condition.lhs.value, float) or isinstance(condition.rhs.value, float):
            return condition

        return HLILConst(int(COMPARISON_FUNCTIONS[condition.op](condition.lhs.value, condition.rhs.value)))

    def _is_always_true(self, condition: HLILExpression) -> bool:
        # Float truth is unverified in the VM
        if not isinstance(condition, HLILConst) or isinstance(condition.value, float):
            return False

        return condition.value not in (0, False)
