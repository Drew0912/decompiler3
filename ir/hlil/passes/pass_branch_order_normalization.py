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
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILCall,
    HLILComment,
    HLILExternCall,
    HLILIf,
    HLILSyscall,
    HLILUnaryOp,
    HLILVar,
    UnaryOp,
    COMPARISON_OPS,
    negate_condition,
    sole_statement,
    sub_blocks,
)


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
            # Settle nested arms first: a swap below changes the first line
            # this level reads
            for child in sub_blocks(stmt):
                self._process_block(child)

            if isinstance(stmt, HLILIf):
                self._normalize(stmt)

    def _normalize(self, stmt: HLILIf):
        '''Swap this if's arms when the other order reads better'''
        if not self._has_statements(stmt.true_block) or not self._has_statements(stmt.false_block):
            return

        true_is_chain = self._is_else_if_chain(stmt.true_block)
        false_is_chain = self._is_else_if_chain(stmt.false_block)

        # Moving a chain into the then-branch buries the next test in it. Only a
        # problem when the arms differ: if false is already the chain, it's fine -
        # unless the chain isn't really a continuation of THIS test at all (just a
        # coincidentally-nested, unrelated if), in which case treat it like any
        # other pair of sibling arms instead of protecting it unconditionally
        if false_is_chain and not true_is_chain:
            if self._looks_like_same_chain(stmt.condition, stmt.false_block):
                return

            if not self._should_swap(stmt):
                return

            self._swap(stmt)
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
        inner_if = sole_statement(block)
        if not isinstance(inner_if, HLILIf):
            return 0

        return 1 + max(cls._chain_length(inner_if.true_block), cls._chain_length(inner_if.false_block))

    @classmethod
    def _looks_like_same_chain(cls, condition, chain_block: HLILBlock) -> bool:
        '''Whether a lone-if chain block continues testing the same thing as `condition`

        Conservative by design: stays True (protect the chain) whenever either side's
        scrutinee can't be identified, since the cost of a missed swap is just a less
        tidy chain, while wrongly reordering a real dispatch chain would bury it again.
        '''
        inner_if = sole_statement(chain_block)
        if not isinstance(inner_if, HLILIf):
            return True

        head = cls._chain_head(condition)
        inner_head = cls._chain_head(inner_if.condition)

        if head is None or inner_head is None:
            return True

        return head == inner_head

    @classmethod
    def _chain_head(cls, condition):
        '''Identity of what a condition tests, ignoring the literal it's compared against -
        e.g. `global_work(12) == 1` and `global_work(12) == 2` share a head, `flag(9023) == 0`
        and `flag(9017) == 0` share a head (same call, different constant argument), but
        `menu_is_canceled(1) != 0` and `var_s1 == 0` do not (unrelated things being tested)
        '''
        scrutinee = cls._scrutinee(condition)

        if isinstance(scrutinee, HLILCall):
            return ('call', scrutinee.func_name)

        if isinstance(scrutinee, HLILSyscall):
            return ('syscall', scrutinee.subsystem, scrutinee.cmd)

        if isinstance(scrutinee, HLILExternCall):
            return ('extern', scrutinee.target)

        if isinstance(scrutinee, HLILVar):
            return ('var', scrutinee.var)

        return None

    @classmethod
    def _scrutinee(cls, condition):
        '''The thing a condition is testing, unwrapping negation and comparison operators'''
        if isinstance(condition, HLILUnaryOp) and condition.op == UnaryOp.NOT:
            return cls._scrutinee(condition.operand)

        if isinstance(condition, HLILBinaryOp):
            if condition.op in COMPARISON_OPS:
                return condition.lhs

            if condition.op in (BinaryOp.AND, BinaryOp.OR):
                return cls._scrutinee(condition.lhs)

        return condition

    @classmethod
    def _swap(cls, stmt: HLILIf):
        stmt.condition = negate_condition(stmt.condition)
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
        return isinstance(sole_statement(block), HLILIf)

    def _first_line(self, block: Optional[HLILBlock]) -> Optional[int]:
        '''First line number this block prints, nested statements included'''
        if not block or not block.statements:
            return None

        for stmt in block.statements:
            if isinstance(stmt, HLILComment):
                match = LINE_COMMENT.search(stmt.text)
                if match:
                    return int(match.group(1))

            for child in sub_blocks(stmt):
                line = self._first_line(child)
                if line is not None:
                    return line

        return None
