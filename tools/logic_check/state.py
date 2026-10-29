"""The storage state of the evaluation walk: storage key -> value tree, with the write epochs reads are taken after

Storage keys mean the same on every layer: ('stack', slot), ('param', n), ('reg', n), ('global', n); a layer's own
storage with no counterpart (a renamed variable) keeps a key of its own, and only values read from it are compared"""

from .neutral_names import Fingerprints
from .trees import ENTRY, tagged_leaves

GLOBAL_EPOCH = ('epoch', 'global')      # the address of the last call that may have written any global
MEMORY_EPOCH = ('epoch', 'memory')      # the same for memory behind a pointer
PHI_DEPTH = 3                           # a deeper phi becomes a leaf of its join holding the phi's fingerprint
DEEP_PHI_KEPT_LEAVES = ('loop', 'address')  # what a deep phi's leaf keeps of the phi, for the comparison to find
ESCAPED = 'escaped'                     # (ESCAPED, key) is set for a local whose address escaped (VMEffects)


class State:
    __slots__ = ('items',)

    def __init__(self, items: dict | None = None):
        self.items = dict(items) if items else {}

    def copy(self) -> State:
        return State(self.items)

    def get(self, key: tuple, default):
        return self.items.get(key, default)

    def set(self, key: tuple, value):
        self.items[key] = value

    def register(self, index: int) -> tuple:
        return self.items.get(('reg', index), ('reg', index, ENTRY))

    def global_value(self, index: int) -> tuple:
        return self.items.get(('global', index), ('global', index, self.items.get(GLOBAL_EPOCH, ENTRY)))


def phi_depth(tree, memo: dict | None = None) -> int:
    """Joins nested in tree; memoised by identity: a tree shares its subtrees"""
    if not isinstance(tree, tuple):     # an epoch is a plain address
        return 0
    memo = {} if memo is None else memo
    found = memo.get(id(tree))
    if found is not None:
        return found

    if tree[0] == 'phi':
        depth = 1 + max((phi_depth(value, memo) for _, value in tree[2]), default=0)
    elif tree[0] == 'gamma':
        depth = 1 + max((phi_depth(value, memo) for _, value in tree[1]), default=0)
    elif tree[0] == 'op':
        depth = max((phi_depth(operand, memo) for operand in tree[2]), default=0)
    else:
        depth = 0
    memo[id(tree)] = depth
    return depth


def incoming_value(key: tuple, neutral_key) -> tuple:
    """A key's value on a path that never wrote it: a register's or a parameter's the function came in with, as a read
    finds it (one layer may copy it, the other leave it), anything else absent"""
    if key[0] == 'reg':
        return ('reg', key[1], ENTRY)
    if key[0] == 'param':
        return key

    return ('absent', neutral_key(key))


def merge(join, states: list[tuple], fingerprints: Fingerprints) -> State:
    """A join's entry state from its predecessors' (edge name, exit state), as merged_value merges each key"""
    keys = set().union(*(state.items.keys() for _, state in states))
    merged = State()
    for key in keys:
        merged.items[key] = merged_value(join, key, states, fingerprints)
    return merged


def merged_value(join, key: tuple, states: list[tuple], fingerprints: Fingerprints):
    """key's value at a join from its predecessors' (edge name, exit state): the value they agree on, else a phi over
    the predecessors ordered by edge name, the terminal address (join an identity), or a gated choice over the path
    conditions the edges are taken under (join None; FormulaKeys compares them). Past PHI_DEPTH the merge becomes a
    leaf, ('deep_phi', join, key, fingerprint, kept leaves): its fingerprint compares it whole, and its loop leaves and
    addresses stay visible, so the loop values and pointees it reads are still compared. A gated merge's choice is kept
    under its fingerprint (Fingerprints.deep_choices), opened where a value compared whole differs
    (compare.lift_choices): the layers cut at different depths"""
    neutral_key = fingerprints.neutral_key
    values = [(name, state.items.get(key, incoming_value(key, neutral_key))) for name, state in states]
    first = values[0][1]
    if all(value == first for _, value in values[1:]):
        return first

    if join is None:
        phi = ('gamma', tuple(values))
    else:
        phi = ('phi', join, tuple(sorted(values, key=lambda pair: pair[0])))
    if phi_depth(phi) <= PHI_DEPTH:
        return phi

    kept = dict.fromkeys(leaf for tag in DEEP_PHI_KEPT_LEAVES for leaf in tagged_leaves(phi, tag))
    fingerprint = fingerprints(phi)
    if join is None:
        fingerprints.deep_choices[fingerprint] = phi
    return ('deep_phi', join, neutral_key(key), fingerprint, tuple(kept))
