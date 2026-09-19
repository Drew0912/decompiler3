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
    HLILUnaryOp,
    HLILIf,
    HLILWhile,
    HLILDoWhile,
    HLILSwitch,
    HLILBreak,
    HLILContinue,
    HLILReturn,
    HLILComment,
    BinaryOp,
    UnaryOp,
)


NEGATED_COMPARISON = {
    BinaryOp.EQ: BinaryOp.NE,
    BinaryOp.NE: BinaryOp.EQ,
    BinaryOp.LT: BinaryOp.GE,
    BinaryOp.GE: BinaryOp.LT,
    BinaryOp.GT: BinaryOp.LE,
    BinaryOp.LE: BinaryOp.GT,
}


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
            if isinstance(stmt, HLILIf):
                self._process_block(stmt.true_block)
                self._process_block(stmt.false_block)
                recovered.append(stmt)

            elif isinstance(stmt, (HLILWhile, HLILDoWhile)):
                self._process_block(stmt.body)

                if isinstance(stmt, HLILWhile):
                    recovered.extend(self._recover_loop(stmt))

                else:
                    recovered.append(stmt)

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    self._process_block(case.body)

                recovered.append(stmt)

            else:
                recovered.append(stmt)

        block.statements = recovered

    def _recover_loop(self, loop: HLILWhile) -> List[HLILStatement]:
        '''Rewrite an unconditional loop whose body only guards its own exit'''
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

        trailing_exit = self._trailing_exit_condition(loop.body)
        if trailing_exit is not None:
            return [HLILDoWhile(trailing_exit, loop.body)]

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
            condition = self._negate(stmt.condition)
            new_body = stmt.false_block

        else:
            return None

        # Comments above the test are re-read on every iteration with it
        for comment in reversed(body.statements[:index]):
            new_body.statements.insert(0, comment)

        return (condition, new_body)

    def _is_only_break(self, block: Optional[HLILBlock]) -> bool:
        '''Check that a block does nothing but leave the loop'''
        if not block or not block.statements:
            return False

        real_stmts = [stmt for stmt in block.statements if not isinstance(stmt, HLILComment)]
        if len(real_stmts) != 1:
            return False

        return isinstance(real_stmts[0], HLILBreak) and real_stmts[0].label is None

    def _leading_exit_condition(self, body: HLILBlock) -> Optional[HLILExpression]:
        '''Condition of a leading `if (c) break;`, negated to become the loop test'''
        index = self._first_real_statement(body)
        if index is None:
            return None

        stmt = body.statements[index]
        if not self._is_lone_break(stmt):
            return None

        # Comments above the test stay at the top of the body, with the test
        del body.statements[index]
        return self._negate(stmt.condition)

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

        if self._contains_loop_break(body):
            return None

        # The guard's whole body moves out, comments included, so a line comment
        # stays with the return it belongs to
        trailing = list(stmt.true_block.statements)
        del body.statements[index]

        return (self._negate(stmt.condition), trailing)

    def _is_lone_return(self, stmt: HLILStatement) -> bool:
        '''Check for `if (c) { return x; }` with no else branch'''
        if not isinstance(stmt, HLILIf):
            return False

        if stmt.false_block and stmt.false_block.statements:
            return False

        if not stmt.true_block:
            return False

        real_stmts = [inner for inner in stmt.true_block.statements
                      if not isinstance(inner, HLILComment)]

        return len(real_stmts) == 1 and isinstance(real_stmts[0], HLILReturn)

    def _contains_loop_break(self, block: Optional[HLILBlock], nested: bool = False) -> bool:
        '''Check for a break that would leave this loop

        A bare break inside a nested loop or switch belongs to that construct, but a
        labelled one can still name this loop, so any label counts wherever it sits.
        '''
        if not block or not block.statements:
            return False

        for stmt in block.statements:
            if isinstance(stmt, HLILBreak):
                if stmt.label is not None or not nested:
                    return True

            elif isinstance(stmt, HLILIf):
                if (self._contains_loop_break(stmt.true_block, nested) or
                        self._contains_loop_break(stmt.false_block, nested)):
                    return True

            elif isinstance(stmt, (HLILWhile, HLILDoWhile)):
                if self._contains_loop_break(stmt.body, True):
                    return True

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    if self._contains_loop_break(case.body, True):
                        return True

        return False

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

        body.statements.pop()
        return self._negate(stmt.condition)

    def _is_lone_break(self, stmt: HLILStatement) -> bool:
        '''Check for `if (c) break;` with no else branch'''
        if not isinstance(stmt, HLILIf):
            return False

        if stmt.false_block and stmt.false_block.statements:
            return False

        if not stmt.true_block or len(stmt.true_block.statements) != 1:
            return False

        inner = stmt.true_block.statements[0]
        return isinstance(inner, HLILBreak) and inner.label is None

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
        '''Reduce a comparison between two constants to a single constant'''
        if not isinstance(condition, HLILBinaryOp):
            return condition

        if not isinstance(condition.lhs, HLILConst) or not isinstance(condition.rhs, HLILConst):
            return condition

        if condition.op == BinaryOp.NE:
            return HLILConst(1 if condition.lhs.value != condition.rhs.value else 0)

        if condition.op == BinaryOp.EQ:
            return HLILConst(1 if condition.lhs.value == condition.rhs.value else 0)

        return condition

    def _is_always_true(self, condition: HLILExpression) -> bool:
        return isinstance(condition, HLILConst) and condition.value not in (0, False)

    def _negate(self, condition: HLILExpression) -> HLILExpression:
        '''Negate a condition, keeping it readable where possible'''
        if isinstance(condition, HLILUnaryOp) and condition.op == UnaryOp.NOT:
            return condition.operand

        if isinstance(condition, HLILBinaryOp) and condition.op in NEGATED_COMPARISON:
            return HLILBinaryOp(NEGATED_COMPARISON[condition.op], condition.lhs, condition.rhs)

        return HLILUnaryOp(UnaryOp.NOT, condition)
