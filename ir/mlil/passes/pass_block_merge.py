"""Block merge pass - splice single-predecessor goto targets into the block that jumps to them"""

from ir.pipeline import Pass
from ..mlil import MediumLevelILFunction, MediumLevelILBasicBlock, MLILGoto


class BlockMergePass(Pass):
    """Merge every block whose only way in is another block's unconditional goto.

    A LowLevelILCall is a block terminator, so the LLIL->MLIL translator ends every call block
    with `goto <return block>` - nearly every call site cuts straight-line code in two. This
    undoes that split (and any other single-predecessor goto chain, including a real bytecode
    jump) by splicing the target block's instructions into the block that jumps to it.

    Must run on pre-SSA MLIL: Phi nodes name predecessor blocks by identity, and absorbing one
    of those blocks would leave a Phi's sources dangling.
    """

    def run(self, func: MediumLevelILFunction) -> MediumLevelILFunction:
        if not func.basic_blocks:
            return func

        entry = func.basic_blocks[0]
        absorbed: set[MediumLevelILBasicBlock] = set()

        for head in func.basic_blocks:
            if head in absorbed:
                continue

            # Absorbing a target makes its own terminal the head's, which may itself be
            # another mergeable goto - drain the whole chain so one sweep reaches the fixpoint
            target = self._mergeable_target(head, entry)

            while target is not None:
                self._absorb(head, target)
                absorbed.add(target)
                target = self._mergeable_target(head, entry)

        if absorbed:
            func.basic_blocks = [b for b in func.basic_blocks if b not in absorbed]
            func.renumber_blocks()

        return func

    def _mergeable_target(self, head: MediumLevelILBasicBlock,
                          entry: MediumLevelILBasicBlock) -> MediumLevelILBasicBlock | None:
        if not head.instructions:
            return None

        terminal = head.instructions[-1]

        if not isinstance(terminal, MLILGoto):
            return None

        target = terminal.target

        if target is entry or target is head or len(target.incoming_edges) != 1:
            return None

        return target

    def _absorb(self, head: MediumLevelILBasicBlock, target: MediumLevelILBasicBlock):
        """Replace head's goto with target's body and take over target's edges"""
        head.instructions[-1:] = target.instructions
        head.outgoing_edges = list(target.outgoing_edges)

        # head's only successor was target, so it sits in no other incoming list yet -
        # replacing target by head can never create a duplicate entry
        for succ in target.outgoing_edges:
            succ.incoming_edges = [head if b is target else b for b in succ.incoming_edges]

        target.instructions = []
        target.incoming_edges = []
        target.outgoing_edges = []
