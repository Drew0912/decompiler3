'''Branch Order Normalization Pass

Structuring picks which arm of an `if` becomes the body based on control-flow
shape, which regularly puts the later-written arm first:

    if (c) { /* line 766 */ } else { /* line 758 */ }

Swapping the arms and negating the test is an identity, so restoring source order
costs nothing but the negation:

    if (!c) { /* line 758 */ } else { /* line 766 */ }

This is the one pass that deliberately diverges from the order the bytecode was
emitted in, so it is optional - see `normalize_branch_order` in
falcom/ed9/hlil_converter.py.
'''

import re
from typing import Optional

from ir.pipeline import Pass
from ..hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILComment,
    HLILDoWhile,
    HLILFor,
    HLILIf,
    HLILSwitch,
    HLILWhile,
)
from ..mlil_to_hlil import _negate_condition


DE_MORGAN = {
    BinaryOp.AND: BinaryOp.OR,
    BinaryOp.OR : BinaryOp.AND,
}


LINE_COMMENT = re.compile(r'line\((\d+)\)')


class BranchOrderNormalizationPass(Pass):
    '''Swap if/else arms that structuring left in reverse source order'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._process_block(func.body)
        return func

    def _process_block(self, block: Optional[HLILBlock]):
        if not block or not block.statements:
            return

        for stmt in block.statements:
            if isinstance(stmt, HLILIf):
                # Settle nested arms first: a swap below changes the first line
                # this level reads
                self._process_block(stmt.true_block)
                self._process_block(stmt.false_block)
                self._normalize(stmt)

            elif isinstance(stmt, (HLILWhile, HLILDoWhile, HLILFor)):
                self._process_block(stmt.body)

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    self._process_block(case.body)

    def _normalize(self, stmt: HLILIf):
        '''Swap this if's arms when doing so restores ascending line order'''
        if not self._has_statements(stmt.true_block) or not self._has_statements(stmt.false_block):
            return

        # An else-if chain reads as a chain; swapping would bury the next test
        if self._is_else_if_chain(stmt.false_block):
            return

        true_line = self._first_line(stmt.true_block)
        false_line = self._first_line(stmt.false_block)

        if true_line is None or false_line is None:
            return

        if false_line >= true_line:
            return

        stmt.condition = self._negate(stmt.condition)
        stmt.true_block, stmt.false_block = stmt.false_block, stmt.true_block

    def _negate(self, condition):
        '''Negate a condition, pushing through && and || rather than wrapping them

        Without De Morgan's a swapped `a != 1 && a != 3` becomes `NOT(a != 1 && a != 3)`,
        which reads worse than what it replaced; distributing gives `a == 1 || a == 3`.
        '''
        if isinstance(condition, HLILBinaryOp) and condition.op in DE_MORGAN:
            return HLILBinaryOp(DE_MORGAN[condition.op],
                                self._negate(condition.lhs),
                                self._negate(condition.rhs))

        return _negate_condition(condition)

    @classmethod
    def _has_statements(cls, block: Optional[HLILBlock]) -> bool:
        return bool(block and block.statements)

    @classmethod
    def _is_else_if_chain(cls, block: HLILBlock) -> bool:
        '''An else branch that is nothing but the next test in a chain'''
        real_stmts = [stmt for stmt in block.statements if not isinstance(stmt, HLILComment)]

        return len(real_stmts) == 1 and isinstance(real_stmts[0], HLILIf)

    def _first_line(self, block: Optional[HLILBlock]) -> Optional[int]:
        '''First line number this block prints, nested statements included'''
        if not block or not block.statements:
            return None

        for stmt in block.statements:
            if isinstance(stmt, HLILComment):
                match = LINE_COMMENT.search(stmt.text)
                if match:
                    return int(match.group(1))

            elif isinstance(stmt, HLILIf):
                for branch in (stmt.true_block, stmt.false_block):
                    line = self._first_line(branch)
                    if line is not None:
                        return line

            elif isinstance(stmt, (HLILWhile, HLILDoWhile, HLILFor)):
                line = self._first_line(stmt.body)
                if line is not None:
                    return line

            elif isinstance(stmt, HLILSwitch):
                for case in stmt.cases:
                    line = self._first_line(case.body)
                    if line is not None:
                        return line

        return None
