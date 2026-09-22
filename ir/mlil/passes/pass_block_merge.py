'''Block merge pass - splice single-predecessor goto targets into the block that jumps to them'''

from typing import Optional, Set

from ir.core import Terminal
from ir.pipeline import Pass
from ..mlil import MediumLevelILFunction, MediumLevelILBasicBlock, MLILGoto
from ..mlil_ssa import MLILPhi


class BlockMergePass(Pass):
    '''Merge every block whose only way in is another block's unconditional goto.

    A LowLevelILCall is a block terminator, so the LLIL->MLIL translator ends every call block
    with `goto <return block>` - nearly every call site cuts straight-line code in two. This
    undoes that split (and any other single-predecessor goto chain, including a real bytecode
    JMP) by splicing the target block's instructions into the block that jumps to it.

    Must run on pre-SSA MLIL: Phi nodes name predecessor blocks by identity, and absorbing one
    of those blocks would leave a Phi's sources dangling.
    '''

    def run(self, mlil_func: MediumLevelILFunction) -> MediumLevelILFunction:
        if not mlil_func.basic_blocks:
            return mlil_func

        self._reject_phi_nodes(mlil_func)

        entry = mlil_func.basic_blocks[0]
        block_set = set(mlil_func.basic_blocks)
        absorbed: Set[MediumLevelILBasicBlock] = set()

        for head in list(mlil_func.basic_blocks):
            if head in absorbed:
                continue

            # Absorbing a target makes its own terminal the head's, which may itself be
            # another mergeable goto - drain the whole chain so one sweep reaches the fixpoint
            target = self._mergeable_target(head, entry, block_set)

            while target is not None:
                self._absorb(head, target)
                absorbed.add(target)
                target = self._mergeable_target(head, entry, block_set)

        if absorbed:
            mlil_func.basic_blocks = [b for b in mlil_func.basic_blocks if b not in absorbed]
            mlil_func.renumber_blocks()  # also rebuilds _inst_block_map (ir/mlil/mlil.py)

        return mlil_func

    def _mergeable_target(self, head: MediumLevelILBasicBlock, entry: MediumLevelILBasicBlock,
                          block_set: Set[MediumLevelILBasicBlock]) -> Optional[MediumLevelILBasicBlock]:
        if not head.instructions:
            return None

        terminal = head.instructions[-1]

        if not isinstance(terminal, MLILGoto):
            return None

        target = terminal.target

        if target is entry or target is head or len(target.incoming_edges) != 1:
            return None

        self._check_edge_invariant(head, target, block_set)

        return target

    def _check_edge_invariant(self, head: MediumLevelILBasicBlock, target: MediumLevelILBasicBlock,
                              block_set: Set[MediumLevelILBasicBlock]):
        '''Fail loud on a broken CFG rather than merge on top of it - an inconsistency here is a
        real bug upstream, not a case worth silently tolerating'''
        if target not in block_set:
            raise RuntimeError(f'{target.label}: not a block of this function')

        if head.outgoing_edges != [target]:
            raise RuntimeError(
                f'{head.label}: outgoing_edges {[b.label for b in head.outgoing_edges]} '
                f'disagrees with its own goto target {target.label}')

        if target.incoming_edges[0] is not head:
            raise RuntimeError(
                f'{target.label}: recorded predecessor {target.incoming_edges[0].label} '
                f'is not the block jumping to it ({head.label})')

        if not target.instructions or not isinstance(target.instructions[-1], Terminal):
            raise RuntimeError(f'{target.label}: has no terminal instruction')

        for succ in target.outgoing_edges:
            if target not in succ.incoming_edges:
                raise RuntimeError(
                    f'{succ.label}: does not record {target.label} as a predecessor, despite '
                    f'{target.label} listing it as a successor')

    def _absorb(self, head: MediumLevelILBasicBlock, target: MediumLevelILBasicBlock):
        '''Replace head's goto with target's body and take over target's edges'''
        head.instructions[-1:] = target.instructions
        head.outgoing_edges = list(target.outgoing_edges)

        # head's only successor was target, so it sits in no other incoming list yet -
        # replacing target by head can never create a duplicate entry
        for succ in target.outgoing_edges:
            succ.incoming_edges = [head if b is target else b for b in succ.incoming_edges]

        target.instructions = []
        target.incoming_edges = []
        target.outgoing_edges = []

    def _reject_phi_nodes(self, mlil_func: MediumLevelILFunction):
        '''Phi sources name predecessor blocks by identity - absorbing one would leave them
        dangling, so this pass only supports pre-SSA MLIL'''
        for block in mlil_func.basic_blocks:
            for inst in block.instructions:
                if isinstance(inst, MLILPhi):
                    raise RuntimeError('BlockMergePass must run on non-SSA MLIL')
