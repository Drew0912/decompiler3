'''Line Marker Removal Pass'''

from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILIf,
    line_marker_number,
    negate_condition,
    sub_blocks,
)


class LineMarkerRemovalPass(Pass):
    '''Drop the line(N) comments, then tidy the if arms left empty.

    Runs last: structuring and branch-order normalization read the markers, so
    dropping them earlier would change the code, not just hide the comments.
    '''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._remove_markers(func.body)
        return func

    @classmethod
    def _remove_markers(cls, block: HLILBlock):
        block.statements = [stmt for stmt in block.statements if line_marker_number(stmt) is None]

        for stmt in block.statements:
            for child in sub_blocks(stmt):
                cls._remove_markers(child)

            if isinstance(stmt, HLILIf):
                cls._tidy_arms(stmt)

    @classmethod
    def _tidy_arms(cls, stmt: HLILIf):
        '''An else left empty goes; a then left empty takes the else, the condition negated'''
        if stmt.false_block is not None and not stmt.false_block.statements:
            stmt.false_block = None

        if not stmt.true_block.statements and stmt.false_block is not None:
            stmt.condition = negate_condition(stmt.condition)
            stmt.true_block, stmt.false_block = stmt.false_block, None
