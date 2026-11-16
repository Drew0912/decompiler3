"""The SSA path's MLIL listing"""

from ir.mlil.mlil_formatter import MLILFormatter
from .mlil_ssa_function import MediumLevelILFunctionSSA


class MLILFormatterSSA(MLILFormatter):
    """The SSA path's MLIL listing: the header adds the inferred types"""

    @classmethod
    def format_header(cls, func: MediumLevelILFunctionSSA) -> list[str]:
        result = super().format_header(func)
        if func.var_types:
            result.extend([';', '; Inferred Types:'])
            result.extend(f';   {name}: {func.var_types[name]}' for name in sorted(func.var_types))
        return result
