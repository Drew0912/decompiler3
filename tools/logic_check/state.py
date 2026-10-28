"""The storage state of the evaluation walk: storage key -> value tree, with the write epochs reads are taken after

Storage keys mean the same on every layer: ('stack', slot), ('param', n), ('reg', n), ('global', n); a layer's own
storage with no counterpart (a renamed variable) keeps a key of its own, and only values read from it are compared"""

from .neutral_names import Fingerprints
from .trees import ENTRY, tagged_leaves

REGISTER_COUNT = 16
RESULT_REGISTER = 0
GLOBAL_EPOCH = ('epoch', 'global')      # the address of the last call that may have written any global
MEMORY_EPOCH = ('epoch', 'memory')      # the same for memory behind a pointer
PHI_DEPTH = 3                           # a deeper phi becomes a leaf of its join holding the phi's fingerprint
DEEP_PHI_KEPT_LEAVES = ('loop', 'address')  # what a deep phi's leaf keeps of the phi, for the comparison to find
ESCAPED = 'escaped'                     # (ESCAPED, key) is set for a local whose address escaped


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

    def reachable_locals(self, args: tuple, address_taken: set, neutral_key) -> list[tuple]:
        """The address-taken locals a callee can reach, by neutral key: those the arguments hold the address of and
        those whose address escaped before (State.escape), then, to a fixed point, those a reached local's value holds
        the address of (a pointer to a pointer). Not every address-taken local: its slot may hold a call's setup
        elsewhere, after the local's scope ends"""
        owners = {}                     # neutral key -> the layer's own keys
        for key in address_taken:
            owners.setdefault(neutral_key(key), []).append(key)

        def pointed_by(tree) -> list[tuple]:
            return [key for leaf in tagged_leaves(tree, 'address') for key in owners.get(leaf[1], ())]

        reached = set()
        pending = [key for key in address_taken if (ESCAPED, key) in self.items] + pointed_by(args)
        while pending:
            key = pending.pop()
            if key not in reached:
                reached.add(key)
                pending.extend(pointed_by(self.items.get(key)))

        return sorted(reached, key=lambda key: repr(neutral_key(key)))

    def escape(self, value, address_taken: set, neutral_key):
        """A local's address stored outside a call's arguments (in a global, through a pointer, in a register)
        escapes: every later call can reach the local. Real bytecode stores none (a census of validator-300)"""
        stored = {leaf[1] for leaf in tagged_leaves(value, 'address')}
        for key in address_taken:
            if neutral_key(key) in stored:
                self.items[(ESCAPED, key)] = (ESCAPED,)

    def local_values(self, keys: list[tuple], neutral_key) -> tuple:
        """(neutral key, value) of each local: what a callee can read behind its pointers"""
        return tuple((neutral_key(key), self.items.get(key, key if key[0] == 'param' else ('undef', neutral_key(key))))
                     for key in keys)

    def return_registers(self) -> tuple:
        """(key, value) of every register but the result, which the return passes on: VM state the caller can read
        after the call. A call's registers are not its inputs: no function reads a register it has not written"""
        return tuple((('reg', index), self.register(index)) for index in range(REGISTER_COUNT)
                     if index != RESULT_REGISTER)

    def call(self, address: int, args: tuple, address_taken: set, neutral_key) -> tuple:
        """A call's passing and changing: returns the locals it can reach (reachable_locals) as local_values gives them,
        then changes every register (the result to the call's), every global, memory behind a pointer and those
        locals"""
        pointed = self.reachable_locals(args, address_taken, neutral_key)
        passed = self.local_values(pointed, neutral_key)
        for index in range(REGISTER_COUNT):
            if index != RESULT_REGISTER:
                self.items[('reg', index)] = ('reg', index, ('after', address))
        for key in [key for key in self.items if key[0] == 'global']:
            del self.items[key]
        self.items[GLOBAL_EPOCH] = address
        self.store_through_pointer(address)
        for key in pointed:
            self.items[key] = ('slot_after', key, address)
        self.items[('reg', RESULT_REGISTER)] = ('call', address)
        return passed

    def store_through_pointer(self, address: int):
        """A store through a pointer changes memory behind pointers, none of the function's locals: LLIL dereferences
        only a caller's pointer, and MLIL writes a local's memory form as the local"""
        self.items[MEMORY_EPOCH] = address


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
    addresses stay visible, so the loop values and pointees it reads are still compared"""
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
    return ('deep_phi', join, neutral_key(key), fingerprints(phi), tuple(kept))
