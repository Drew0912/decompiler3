'''MLIL SSA Optimizer - orchestrates SSA optimization passes'''

import sys
from enum import Enum

from .mlil import MediumLevelILBasicBlock, MediumLevelILFunction, MediumLevelILInstruction
from .passes import (
    NNFPass,
    SCCP,
    ConstantPropagationPass,
    CopyPropagationPass,
    ExpressionSimplificationPass,
    ConditionSimplificationPass,
    ExpressionInliningPass,
    SSADeadCodeEliminationPass,
    DeadPhiSourceEliminationPass,
)

SSA_OPTIMIZER_MAX_ITERATIONS = 10

# _structural_key excludes these - address/inst_index/llil_index are source-tracking metadata,
# options is formatting-only metadata - none ever reflect a semantic change between fixpoint
# iterations (MediumLevelILInstruction.__init__/ILOptions in mlil.py)
_SNAPSHOT_EXCLUDED_ATTRS = frozenset({'address', 'inst_index', 'llil_index', 'options'})


class SSAOptimizer:
    '''Orchestrates SSA optimization passes'''

    def __init__(self, function: MediumLevelILFunction):
        self.function = function

    def optimize(self) -> MediumLevelILFunction:
        '''Run all optimization passes'''
        # Run SCCP first for aggressive constant propagation and unreachable code elimination
        sccp = SCCP(self.function)
        sccp.run()

        # Passes to run iteratively until fixpoint
        passes = [
            ConstantPropagationPass(),
            ExpressionSimplificationPass(),
            ConditionSimplificationPass(),
            NNFPass(),
            CopyPropagationPass(),
            ExpressionInliningPass(),
            SSADeadCodeEliminationPass(sccp_replaced_vars = sccp.replaced_vars),
            DeadPhiSourceEliminationPass(sccp_replaced_vars = sccp.replaced_vars),
        ]

        # Iterative optimization until fixpoint
        snapshot = self._snapshot()
        for _ in range(SSA_OPTIMIZER_MAX_ITERATIONS):
            for p in passes:
                p.run(self.function)

            previous, snapshot = snapshot, self._snapshot()
            if snapshot == previous:
                break

        else:
            print(f'[optimizer] {self.function.name} did not converge after '
                  f'{SSA_OPTIMIZER_MAX_ITERATIONS} iterations', file = sys.stderr)

        return self.function

    def _snapshot(self) -> tuple:
        '''Exact structural key of function state, for fixpoint change detection.

        repr(inst) is just "<ClassName OP>" - no MLIL class overrides __repr__ - so an
        operand-only rewrite (a constant folded, a variable substituted) looked identical to
        the previous snapshot and could stop the loop one iteration early. str(inst) is not
        exact either: MLILConst prints a SourceFloat as its source text and hex ints masked to
        32 bits, so distinct constants can render the same text. This walks each
        instruction's actual attributes instead.
        '''
        blocks_key = []
        for block in self.function.basic_blocks:
            inst_keys = tuple(self._structural_key(inst) for inst in block.instructions)
            successor_indices = tuple(succ.index for succ in block.outgoing_edges)
            blocks_key.append((block.index, inst_keys, successor_indices))
        return tuple(blocks_key)

    @classmethod
    def _structural_key(cls, value):
        '''Recursively reduce an instruction, or any attribute value reachable from one, to an
        exact and hashable key. One generic walk over each object's own attributes instead of a
        per-node-type walker (CLAUDE.md -0.04), so a new instruction/operand type is covered
        without a change here. Every branch tags its result with the value's actual type object
        (not its name - two distinct classes can share a __name__), so values of different types
        can never collide even if their content normalizes to the same text (e.g. MLILConst(1.0)
        vs a string that happens to equal its hex form).
        '''
        if isinstance(value, MediumLevelILBasicBlock):
            # Identity only - walking a target block's own attributes would inline its entire
            # instruction list into every jump/phi that names it, and blocks form cycles
            # through loop back-edges.
            return (MediumLevelILBasicBlock, value.index)

        if isinstance(value, float):
            # type and str(): a SourceFloat losing or changing its text is a change
            return (type(value), value.hex(), str(value))

        if isinstance(value, Enum):
            return (type(value), value.name)

        if isinstance(value, (list, tuple)):
            return (type(value), tuple(cls._structural_key(item) for item in value))

        if isinstance(value, MediumLevelILInstruction):
            attrs = {k: v for k, v in vars(value).items() if k not in _SNAPSHOT_EXCLUDED_ATTRS}
            return (type(value), tuple((k, cls._structural_key(v)) for k, v in sorted(attrs.items())))

        if hasattr(value, '__dict__'):
            return (type(value), tuple((k, cls._structural_key(v)) for k, v in sorted(vars(value).items())))

        try:
            hash(value)

        except TypeError:
            # No current construction path produces an unhashable attribute value (MLILDebug.value/
            # MLILConst.value are typed Any, but nothing populates them with a dict/set/etc.) -
            # fail loud instead of silently returning an unfrozen, potentially mutable key.
            raise NotImplementedError(f'_structural_key: unhashable attribute value not supported ({value!r})')

        return (type(value), value)
