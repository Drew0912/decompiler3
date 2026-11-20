"""Branch Address Order Pass: each if's arms in the order its code lays them out, as the HLIL DSL lowers them"""

from ir.core import is_int_zero
from ir.pipeline import Pass
from ...hlil import (
    BinaryOp,
    HighLevelILFunction,
    HLILBinaryOp,
    HLILBlock,
    HLILConst,
    HLILExpression,
    HLILIf,
    HLILInstruction,
    HLILReturn,
    HLILStatement,
    sub_blocks,
)

# A truth test's two senses: E != 0 enters the arm when E is not zero, E == 0 when it is
FLIPPED_TRUTH_TEST = {BinaryOp.NE: BinaryOp.EQ, BinaryOp.EQ: BinaryOp.NE}


def flipped_truth_test(condition: HLILExpression) -> HLILBinaryOp | None:
    """condition with its sense the other way, when it is a truth test against a plain 0 (E != 0 for E == 0, and
    back: the two are each other's negation for any E, a NaN included); None for any other condition, which is left
    as it is: a comparison inside the test is never complemented"""
    if not (isinstance(condition, HLILBinaryOp) and condition.op in FLIPPED_TRUTH_TEST
            and isinstance(condition.rhs, HLILConst) and is_int_zero(condition.rhs.value)):
        return None

    return with_source_of(HLILBinaryOp(FLIPPED_TRUTH_TEST[condition.op], condition.lhs, condition.rhs), condition)


def with_source_of[Node: HLILInstruction](node: Node, source: HLILInstruction) -> Node:
    """node, given source's bytecode address and MLIL index"""
    node.address = source.address
    node.mlil_index = source.mlil_index
    return node


def ends_in_return(statements: list[HLILStatement]) -> bool:
    return bool(statements) and isinstance(statements[-1], HLILReturn)


class BranchAddressOrderPass(Pass):
    """Each if's arms in the order the code lays them out (the arms' recorded entry addresses): the HLIL DSL lowers
    arms in the order they print, so an arm structuring left reversed would compile to other jumps.

    An if / else whose else arm comes first in the code is swapped; an early return, if (c) { A; return } R, whose
    following code R comes first and ends in a return of its own becomes if (!c) { R } A; return. Each flips the
    test's sense (flipped_truth_test) and is left alone when the test is not a truth test or a position is unknown.
    Equivalent wherever its result lowers to the code's jumps; the DSL's exact check refuses the rest
    """

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._order(func.body)
        return func

    @classmethod
    def _order(cls, block: HLILBlock):
        """block's statements in code order, the blocks inside them first"""
        for index, stmt in enumerate(block.statements):
            for child in sub_blocks(stmt):
                cls._order(child)

            if not isinstance(stmt, HLILIf):
                continue

            cls._order_arms(stmt)

            # What followed the guard now sits in its arm, ordered there
            if cls._turn_guard(block, index):
                return

    @classmethod
    def _order_arms(cls, stmt: HLILIf):
        if stmt.false_block is None or not stmt.false_block.statements:
            return

        true_at, false_at = stmt.true_block.entry_address, stmt.false_block.entry_address
        if true_at is None or false_at is None or false_at >= true_at:
            return

        flipped = flipped_truth_test(stmt.condition)
        if flipped is not None:
            stmt.condition = flipped
            stmt.true_block, stmt.false_block = stmt.false_block, stmt.true_block

    @classmethod
    def _turn_guard(cls, block: HLILBlock, index: int) -> bool:
        """block.statements[index], an early return whose following code comes first in the code, turned around;
        True when it was"""
        stmt = block.statements[index]
        following = block.statements[index + 1:]
        arm = stmt.true_block
        if stmt.false_block is not None or not ends_in_return(arm.statements) or not ends_in_return(following):
            return False

        if stmt.following_address is None or arm.entry_address is None or stmt.following_address >= arm.entry_address:
            return False

        flipped = flipped_truth_test(stmt.condition)
        if flipped is None:
            return False

        moved = HLILBlock(following)
        moved.entry_address = stmt.following_address
        turned = with_source_of(HLILIf(flipped, moved), stmt)
        turned.following_address = arm.entry_address
        block.statements[index:] = [turned, *arm.statements]
        cls._order(moved)
        return True
