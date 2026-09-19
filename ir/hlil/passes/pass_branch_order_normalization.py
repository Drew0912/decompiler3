'''Branch Order Normalization Pass

Structuring picks which arm of an `if` becomes the body based on control-flow
shape, which regularly puts the later-written arm first:

    if (c) { /* line 766 */ } else { /* line 758 */ }

Swapping the arms and negating the test is an identity, so restoring source order
costs nothing but the negation:

    if (!c) { /* line 758 */ } else { /* line 766 */ }

This is the only place arm order is decided. The TypeScript emitter used to make
the same choice again by nesting depth, which contradicted source order 146 times
against 7 and left `.hlil.ts` and `.ts` disagreeing about the same function; that
rule now lives here as the tie-break for arms carrying no line number.

This is the one pass that deliberately diverges from the order the bytecode was
emitted in, so it is optional - see `normalize_branch_order` in
falcom/ed9/hlil_converter.py.
'''

import re
from typing import Optional

from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILComment,
    HLILDoWhile,
    HLILFor,
    HLILIf,
    HLILSwitch,
    HLILWhile,
)
from ..mlil_to_hlil import _negate_condition


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
        '''Swap this if's arms when the other order reads better'''
        if not self._has_statements(stmt.true_block) or not self._has_statements(stmt.false_block):
            return

        true_is_chain = self._is_else_if_chain(stmt.true_block)
        false_is_chain = self._is_else_if_chain(stmt.false_block)

        # Moving a chain into the then-branch buries the next test in it. Only a
        # problem when the arms differ: if false is already the chain, it's fine
        if false_is_chain and not true_is_chain:
            return

        # The chain sits in the then-branch instead: the pairwise line/depth
        # tie-break below only reliably catches this at the outermost link (its
        # entry comment reads as an earlier line than the sibling case body), so
        # a deeper cascade stays buried unless this is unconditional
        if true_is_chain and not false_is_chain:
            self._swap(stmt)
            return

        # Both arms are chains: codegen can only flatten the false/else side, so
        # something nests either way. Flatten whichever chain runs longer and
        # bury the shorter one; an equal-length tie falls through to the same
        # line/depth tie-break used for ordinary sibling arms below
        if true_is_chain and false_is_chain:
            true_len = self._chain_length(stmt.true_block)
            false_len = self._chain_length(stmt.false_block)

            if true_len != false_len:
                if true_len > false_len:
                    self._swap(stmt)
                return

        if not self._should_swap(stmt):
            return

        self._swap(stmt)

    @classmethod
    def _chain_length(cls, block: Optional[HLILBlock]) -> int:
        '''How many further else-if links follow from this lone-if block'''
        if not cls._is_else_if_chain(block):
            return 0

        inner_if = next(s for s in block.statements if isinstance(s, HLILIf))
        return 1 + max(cls._chain_length(inner_if.true_block), cls._chain_length(inner_if.false_block))

    @classmethod
    def _swap(cls, stmt: HLILIf):
        stmt.condition = _negate_condition(stmt.condition)
        stmt.true_block, stmt.false_block = stmt.false_block, stmt.true_block

    def _should_swap(self, stmt: HLILIf) -> bool:
        '''Whether the false arm belongs first

        Source order decides wherever both arms carry a line number, because the
        corpus says the nesting rule contradicts it 146 times against 7. Depth is
        the tie-break for the rest, which is where that rule went uncontested.
        '''
        true_line = self._first_line(stmt.true_block)
        false_line = self._first_line(stmt.false_block)

        if true_line is not None and false_line is not None and true_line != false_line:
            return false_line < true_line

        # Shallower arm first, so the deeper one lands in the else and flattens
        # into an else-if chain instead of nesting
        return self._if_depth(stmt.true_block) > self._if_depth(stmt.false_block)

    @classmethod
    def _if_depth(cls, block: Optional[HLILBlock]) -> int:
        '''Maximum if nesting depth inside a block'''
        if not block or not block.statements:
            return 0

        max_depth = 0
        stack = [(block, 0)]

        while stack:
            current, depth = stack.pop()

            if not current or not current.statements:
                continue

            for stmt in current.statements:
                if isinstance(stmt, HLILIf):
                    max_depth = max(max_depth, depth + 1)
                    stack.append((stmt.true_block, depth + 1))
                    stack.append((stmt.false_block, depth + 1))

        return max_depth

    @classmethod
    def _has_statements(cls, block: Optional[HLILBlock]) -> bool:
        return bool(block and block.statements)

    @classmethod
    def _is_else_if_chain(cls, block: Optional[HLILBlock]) -> bool:
        '''An else branch that is nothing but the next test in a chain'''
        if not block or not block.statements:
            return False

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
