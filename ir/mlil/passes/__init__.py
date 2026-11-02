"""MLIL passes: the decompile path's, after its translator (BlockMergePass and BitwiseHexPass the SSA path's too; its
own are in ir/mlil_ssa/passes/)"""

from .pass_block_merge import BlockMergePass
from .pass_call_result import CallResultPass
from .pass_return_value import ReturnValuePass
from .pass_bitwise_hex import BitwiseHexPass

__all__ = [
    'BlockMergePass',
    'CallResultPass',
    'ReturnValuePass',
    'BitwiseHexPass',
]
