"""The HLIL DSL's own passes: shaping only its conversion runs (convert_ed9_mlil_to_hlil_dsl,
falcom/ed9/ir/hlil/hlil_converter.py), so the HLIL it prints lowers back to the code's own jumps; the shared pipeline
(.ts, .hlil.ts) never runs them"""

from .pass_branch_address_order import BranchAddressOrderPass

__all__ = [
    'BranchAddressOrderPass',
]
