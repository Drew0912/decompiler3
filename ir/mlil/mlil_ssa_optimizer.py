"""MLIL SSA Optimizer - orchestrates SSA optimization passes"""

from enum import Enum

from dc3.logging import log
from .mlil import MediumLevelILBasicBlock, MediumLevelILFunction, MediumLevelILInstruction
from .passes import (
    NNFPass,
    ConstantPropagationPass,
    CopyPropagationPass,
    ConditionSimplificationPass,
    ExpressionInliningPass,
    SSADeadCodeEliminationPass,
    DeadPhiSourceEliminationPass,
)

SSA_OPTIMIZER_MAX_ITERATIONS = 10

# _structural_key skips the source tracking: it never reflects a semantic change between fixpoint iterations
_SNAPSHOT_EXCLUDED_ATTRS = frozenset({'address', 'inst_index', 'llil_index'})

# _structural_key's branch for a value, decided once per class (_key_kind)
_KEY_BLOCK, _KEY_FLOAT, _KEY_ENUM, _KEY_SEQUENCE, _KEY_INSTRUCTION, _KEY_OTHER, _KEY_ATOM = range(7)
# Seeded with exact types only (no __dict__, so the fallback's key): a subclass of int or str takes _key_kind's
# checks, as before
_KEY_KINDS = {int: _KEY_ATOM, bool: _KEY_ATOM, str: _KEY_ATOM, type(None): _KEY_ATOM}
# Each attribute layout's sorted names, keyed by (the names in insertion order, the names excluded)
_ATTRIBUTE_ORDERS = {}


def _key_kind(value_type: type) -> int:
    """value_type's _structural_key branch: the isinstance checks of the key's original ladder, in its order"""
    if issubclass(value_type, MediumLevelILBasicBlock):
        kind = _KEY_BLOCK
    elif issubclass(value_type, float):
        kind = _KEY_FLOAT
    elif issubclass(value_type, Enum):
        kind = _KEY_ENUM
    elif issubclass(value_type, (list, tuple)):
        kind = _KEY_SEQUENCE
    elif issubclass(value_type, MediumLevelILInstruction):
        kind = _KEY_INSTRUCTION
    else:
        kind = _KEY_OTHER
    _KEY_KINDS[value_type] = kind
    return kind


def _attribute_order(attrs: dict, excluded: frozenset = frozenset()) -> list[str]:
    """attrs' names sorted, without excluded; sorted once per attribute layout"""
    layout = tuple(attrs)
    order = _ATTRIBUTE_ORDERS.get((layout, excluded))
    if order is None:
        order = _ATTRIBUTE_ORDERS[(layout, excluded)] = [name for name in sorted(layout) if name not in excluded]
    return order


class SSAOptimizer:
    """Orchestrates SSA optimization passes"""

    def __init__(self, function: MediumLevelILFunction):
        self.function = function

    def optimize(self) -> MediumLevelILFunction:
        """Run the passes to a fixpoint. None computes a value the bytecode does not hold: SCCP and
        ExpressionSimplificationPass (folds, algebraic identities) are left out but kept (docs/mlil/MLIL_DESIGN.md)"""
        constant_propagation = ConstantPropagationPass()

        # Passes to run iteratively until fixpoint
        passes = [
            constant_propagation,
            ConditionSimplificationPass(),
            NNFPass(),
            CopyPropagationPass(),
            ExpressionInliningPass(),
            SSADeadCodeEliminationPass(replaced_vars=constant_propagation.replaced_vars),
            DeadPhiSourceEliminationPass(replaced_vars=constant_propagation.replaced_vars),
        ]

        # Iterative optimization until fixpoint
        snapshot = self._snapshot()
        for _ in range(SSA_OPTIMIZER_MAX_ITERATIONS):
            for optimization_pass in passes:
                optimization_pass.run(self.function)

            previous, snapshot = snapshot, self._snapshot()
            if snapshot == previous:
                break
        else:
            log.warning(f'[optimizer] {self.function.name} did not converge after '
                        f'{SSA_OPTIMIZER_MAX_ITERATIONS} iterations')

        return self.function

    def _snapshot(self) -> tuple:
        """Exact structural key of function state, for fixpoint change detection.

        repr(inst) is just "<ClassName OP>" - no MLIL class overrides __repr__ - so an
        operand-only rewrite (a constant folded, a variable substituted) looked identical to
        the previous snapshot and could stop the loop one iteration early. str(inst) is not
        exact either: MLILConst prints a SourceFloat as its source text and hex ints masked to
        32 bits, so distinct constants can render the same text. This walks each
        instruction's actual attributes instead.
        """
        blocks_key = []
        for block in self.function.basic_blocks:
            inst_keys = tuple([self._structural_key(inst) for inst in block.instructions])
            successor_indices = tuple([succ.index for succ in block.outgoing_edges])
            blocks_key.append((block.index, inst_keys, successor_indices))
        return tuple(blocks_key)

    @classmethod
    def _structural_key(cls, value):
        """Recursively reduce an instruction, or any attribute value reachable from one, to an
        exact comparison key. One generic walk over each object's own attributes instead of a
        per-node-type walker (`.claude/rules/ir.md`), so a new instruction/operand type is covered
        without a change here. Every branch tags its result with the value's actual type object
        (not its name - two distinct classes can share a __name__), so values of different types
        can never collide even if their content normalizes to the same text (e.g. MLILConst(1.0)
        vs a string that happens to equal its hex form). Each value type's branch is decided once
        (`_key_kind`) and each attribute layout's sorted order once (`_attribute_order`): the key is
        the same tuple the isinstance ladder built.
        """
        value_type = type(value)
        kind = _KEY_KINDS.get(value_type)
        if kind is None:
            kind = _key_kind(value_type)

        if kind == _KEY_INSTRUCTION:
            attrs = vars(value)
            return (value_type, tuple([(name, cls._structural_key(attrs[name]))
                                       for name in _attribute_order(attrs, _SNAPSHOT_EXCLUDED_ATTRS)]))

        if kind == _KEY_ATOM:
            return (value_type, value)

        if kind == _KEY_SEQUENCE:
            return (value_type, tuple([cls._structural_key(item) for item in value]))

        if kind == _KEY_BLOCK:
            # Identity only - walking a target block's own attributes would inline its entire
            # instruction list into every jump/phi that names it, and blocks form cycles
            # through loop back-edges
            return (MediumLevelILBasicBlock, value.index)

        if kind == _KEY_ENUM:
            # _name_ is what Enum.name returns, read without the Python-level property
            return (value_type, value._name_)

        if kind == _KEY_FLOAT:
            # type and str(): a SourceFloat losing or changing its text is a change
            return (value_type, value.hex(), str(value))

        if hasattr(value, '__dict__'):
            attrs = vars(value)
            return (value_type, tuple([(name, cls._structural_key(attrs[name])) for name in _attribute_order(attrs)]))

        return (value_type, value)
