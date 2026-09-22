'''Common Return Extraction Pass'''

from typing import Optional
from ir.pipeline import Pass
from ..hlil import (
    HighLevelILFunction,
    HLILBlock,
    HLILVar,
    HLILConst,
    HLILIf,
    HLILSwitch,
    HLILReturn,
    sub_blocks,
)


class CommonReturnExtractionPass(Pass):
    '''Extract common return statements from branches'''

    def run(self, func: HighLevelILFunction) -> HighLevelILFunction:
        self._extract_common_returns(func.body)
        return func

    def _extract_common_returns(self, block: HLILBlock):
        if not block or not block.statements:
            return

        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]

            for child in sub_blocks(stmt):
                self._extract_common_returns(child)

            if isinstance(stmt, HLILIf):
                common_return = self._get_common_if_return(stmt)
                if common_return is not None:
                    if stmt.true_block.statements and isinstance(stmt.true_block.statements[-1], HLILReturn):
                        stmt.true_block.statements.pop()

                    if stmt.false_block and stmt.false_block.statements and isinstance(stmt.false_block.statements[-1], HLILReturn):
                        stmt.false_block.statements.pop()

                    block.statements.insert(i + 1, common_return)

            elif isinstance(stmt, HLILSwitch):
                common_return = self._get_common_switch_return(stmt)
                if common_return is not None:
                    for case in stmt.cases:
                        if case.body.statements and isinstance(case.body.statements[-1], HLILReturn):
                            case.body.statements.pop()

                    block.statements.insert(i + 1, common_return)

            i += 1

    def _get_common_switch_return(self, switch_stmt: HLILSwitch) -> Optional[HLILReturn]:
        if not switch_stmt.cases:
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
        if ret1.value is None and ret2.value is None:
            return True

        if ret1.value is None or ret2.value is None:
            return False

        if isinstance(ret1.value, HLILConst) and isinstance(ret2.value, HLILConst):
            return ret1.value.value == ret2.value.value

        if isinstance(ret1.value, HLILVar) and isinstance(ret2.value, HLILVar):
            return ret1.value.var == ret2.value.var

        return False

    def _get_common_if_return(self, if_stmt: HLILIf) -> Optional[HLILReturn]:
        if not if_stmt.true_block or not if_stmt.false_block:
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
