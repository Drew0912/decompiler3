"""Common Return Extraction Pass"""

from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILIf,
    HLILSwitch,
    HLILReturn,
    sub_blocks,
    contains_bare_break,
    same_const_or_var,
)


class CommonReturnExtractionPass(Pass):
    """Extract common return statements from branches"""

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._extract_common_returns(func.body)
        return func

    def _extract_common_returns(self, block: HLILBlock):
        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]

            for child in sub_blocks(stmt):
                self._extract_common_returns(child)

            # Each arm or case was checked to end in the common return
            if isinstance(stmt, HLILIf):
                common_return = self._get_common_if_return(stmt)
                if common_return is not None:
                    stmt.true_block.statements.pop()
                    stmt.false_block.statements.pop()
                    block.statements.insert(i + 1, common_return)
            elif isinstance(stmt, HLILSwitch):
                common_return = self._get_common_switch_return(stmt)
                if common_return is not None:
                    for case in stmt.cases:
                        case.body.statements.pop()

                    block.statements.insert(i + 1, common_return)

            i += 1

    def _get_common_switch_return(self, switch_stmt: HLILSwitch) -> HLILReturn | None:
        # An unmatched value, or a case's bare break, leaves the switch and runs what follows it
        if not any(case.is_default() for case in switch_stmt.cases):
            return None

        if any(contains_bare_break(case.body) for case in switch_stmt.cases):
            return None

        common_return = None

        for case in switch_stmt.cases:
            if not case.body.statements:
                return None

            last_stmt = case.body.statements[-1]
            if not isinstance(last_stmt, HLILReturn):
                return None

            if common_return is None:
                common_return = last_stmt
                continue

            if not self._return_values_equal(common_return, last_stmt):
                return None

        return common_return

    def _return_values_equal(self, ret1: HLILReturn, ret2: HLILReturn) -> bool:
        if ret1.value is None or ret2.value is None:
            return ret1.value is ret2.value

        return same_const_or_var(ret1.value, ret2.value)

    def _get_common_if_return(self, if_stmt: HLILIf) -> HLILReturn | None:
        if not if_stmt.false_block:
            return None

        if not if_stmt.true_block.statements or not if_stmt.false_block.statements:
            return None

        true_last = if_stmt.true_block.statements[-1]
        false_last = if_stmt.false_block.statements[-1]

        if not isinstance(true_last, HLILReturn) or not isinstance(false_last, HLILReturn):
            return None

        if self._return_values_equal(true_last, false_last):
            return true_last

        return None
