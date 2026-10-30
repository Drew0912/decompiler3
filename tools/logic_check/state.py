"""The storage state of the evaluation walk: storage key -> value tree, with the write epochs reads are taken after

Storage keys mean the same on every layer: ('stack', slot), ('param', n), ('reg', n), ('global', n); a layer's own
storage with no counterpart (a renamed variable) keeps a key of its own, and only values read from it are compared"""

from .neutral_names import Fingerprints
from .trees import ENTRY, equal_trees, tagged_leaves

GLOBAL_EPOCH = ('epoch', 'global')      # the address of the last call that may have written any global
REGISTER_EPOCH = ('epoch', 'register')  # ('after', the last call's address): what a register with no key is read after
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
        """The register's value: written, or read after the last call (REGISTER_EPOCH), which changed every register"""
        found = self.items.get(('reg', index))
        if found is not None:
            return found
        return register_after(index, self.items.get(REGISTER_EPOCH, ENTRY), {})

    def global_value(self, index: int) -> tuple:
        return self.items.get(('global', index), ('global', index, self.items.get(GLOBAL_EPOCH, ENTRY)))


def register_after(index: int, epoch, memo: dict) -> tuple:
    """Register index read after epoch; a gated choice of epochs is the choice of the register's values after each, as
    a merge of the register builds it, so a choice HLIL makes where MLIL keeps two paths (a common return) is lifted
    whole. An address-named phi of epochs stays inside the leaf: both layers build it alike, neither storing a copy a
    read gives (VMEffects.write). Memoised by identity: a choice shares its earlier ones"""
    if not isinstance(epoch, tuple) or epoch[0] != 'gamma':
        return ('reg', index, epoch)
    found = memo.get(id(epoch))
    if found is not None:
        return found[1]

    result = ('gamma', tuple([(formula, register_after(index, value, memo)) for formula, value in epoch[1]]))
    memo[id(epoch)] = (epoch, result)       # the epoch kept alive, so its id is not reused
    return result


def phi_depth(tree, memo: dict | None = None) -> int:
    """Phis nested in tree, through its operations (a gated merge is never cut); memoised by identity: a tree shares its
    subtrees, and a value merged at one join is merged again at the next (memo: a walk_forward round's)"""
    if not isinstance(tree, tuple):     # a global or memory epoch is a plain address
        return 0
    memo = {} if memo is None else memo
    found = memo.get(id(tree))
    if found is not None:
        return found[1]

    if tree[0] == 'phi':
        depth = 1 + max((phi_depth(value, memo) for _, value in tree[2]), default=0)
    elif tree[0] == 'op':
        depth = max((phi_depth(operand, memo) for operand in tree[2]), default=0)
    else:
        depth = 0
    memo[id(tree)] = (tree, depth)      # the tree kept alive, so its id is not reused
    return depth


def incoming_value(state: State, key: tuple, neutral_key) -> tuple:
    """A key's value on a path that never wrote it: a register's as a read finds it on that path (State.register: as
    the function came in, or after the path's last call), a write epoch's the entry, as a read takes it (one layer may
    merge a path with no call where the other repeats what follows), a parameter's the function came in with (one
    layer may copy it, the other leave it), anything else absent"""
    if key[0] == 'reg':
        return state.register(key[1])
    if key[0] == 'epoch':
        return ENTRY
    if key[0] == 'param':
        return key

    return ('absent', neutral_key(key))


def merge(join, states: list[tuple], fingerprints: Fingerprints, depths: dict | None = None) -> State:
    """A join's entry state from its predecessors' (edge name, exit state), as merged_value merges each key"""
    keys = set().union(*(state.items.keys() for _, state in states))
    merged = State()
    for key in keys:
        merged.items[key] = merged_value(join, key, states, fingerprints, depths)
    return merged


def merged_value(join, key: tuple, states: list[tuple], fingerprints: Fingerprints, depths: dict | None = None):
    """key's value at a join from its predecessors' (edge name, exit state): the value they agree on (equal_trees,
    exact: two de-SSA splits of one slot stay two values), else a phi over the predecessors ordered by edge name, the
    terminal address (join an identity), or a gated choice over the path conditions the edges are taken under (join
    None; FormulaKeys compares them), never cut. A phi past PHI_DEPTH becomes a leaf, ('deep_phi', join, key,
    fingerprint, kept leaves): its fingerprint compares it whole, and its loop leaves and addresses stay visible, so the
    loop values and pointees it reads are still compared"""
    neutral_key = fingerprints.neutral_key
    values = [(name, state.items.get(key, incoming_value(state, key, neutral_key))) for name, state in states]
    first = values[0][1]
    if all(equal_trees(value, first) for _, value in values[1:]):
        return first

    if join is None:
        return ('gamma', tuple(values))

    phi = ('phi', join, tuple(sorted(values, key=lambda pair: pair[0])))
    if phi_depth(phi, depths) <= PHI_DEPTH:
        return phi

    kept = dict.fromkeys(leaf for tag in DEEP_PHI_KEPT_LEAVES for leaf in tagged_leaves(phi, tag))
    return ('deep_phi', join, neutral_key(key), fingerprints(phi), tuple(kept))
