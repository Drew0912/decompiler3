'''Dead Code Elimination Pass'''

from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    TERMINAL_STATEMENTS,
    sub_blocks,
)


class DeadCodeEliminationPass(Pass):
    '''Remove unreachable code after a terminal statement'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._remove_unreachable(func.body)
        return func

    def _remove_unreachable(self, block: HLILBlock):
        if not block or not block.statements:
            return

        for stmt in block.statements:
            for child in sub_blocks(stmt):
                self._remove_unreachable(child)

        for i, stmt in enumerate(block.statements):
            if isinstance(stmt, TERMINAL_STATEMENTS):
                if i + 1 < len(block.statements):
                    block.statements = block.statements[:i + 1]
                break
