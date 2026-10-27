"""The storage state of the evaluation walk: storage key -> value tree, with the write epochs reads are taken after

Storage keys mean the same on every layer: ('stack', slot), ('param', n), ('reg', n), ('global', n); a layer's own
storage with no counterpart (a renamed variable) keeps a key of its own, and only values read from it are compared"""

import hashlib

from .trees import ENTRY, EQUALITIES, tagged_leaves

REGISTER_COUNT = 16
RESULT_REGISTER = 0
GLOBAL_EPOCH = ('epoch', 'global')      # the address of the last call that may have written any global
MEMORY_EPOCH = ('epoch', 'memory')      # the same for memory behind a pointer
PHI_DEPTH = 3                           # a deeper phi becomes a leaf of its join holding the phi's fingerprint
FINGERPRINT_BYTES = 16
DEEP_PHI_KEPT_LEAVES = ('loop', 'address')  # what a deep phi's leaf keeps of the phi, for the comparison to find


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

    def pointee_values(self, args: tuple, address_taken: set, neutral_key) -> tuple:
        """(neutral key, value) of each local the arguments hold the address of, sorted by key: what the callee can
        read behind its pointers. Only those: an address-taken local's slot may hold a call's setup elsewhere, after
        the local's scope ends"""
        pointed = {leaf[1] for leaf in tagged_leaves(args, 'address')}
        values = [(neutral_key(key), self.items.get(key, key if key[0] == 'param' else ('undef', neutral_key(key))))
                  for key in address_taken if neutral_key(key) in pointed]
        return tuple(sorted(values, key=lambda pair: repr(pair[0])))

    def return_registers(self) -> tuple:
        """(key, value) of every register but the result, which the return passes on: VM state the caller can read
        after the call. A call's registers are not its inputs: no function reads a register it has not written"""
        return tuple((('reg', index), self.register(index)) for index in range(REGISTER_COUNT)
                     if index != RESULT_REGISTER)

    def clobber(self, address: int, address_taken: set, *, registers: bool = True, globals_: bool = True):
        """What a call (or, with registers and globals_ off, a store through a pointer) may change: every register but
        the result, which the caller sets; every global; memory behind a pointer; every address-taken local"""
        if registers:
            for index in range(REGISTER_COUNT):
                if index != RESULT_REGISTER:
                    self.items[('reg', index)] = ('reg', index, ('after', address))
        if globals_:
            for key in [key for key in self.items if key[0] == 'global']:
                del self.items[key]
            self.items[GLOBAL_EPOCH] = address
        self.items[MEMORY_EPOCH] = address
        for key in address_taken:
            self.items[key] = ('slot_after', key, address)


def phi_depth(tree) -> int:
    if not isinstance(tree, tuple):     # an epoch is a plain address
        return 0
    if tree[0] == 'phi':
        return 1 + max((phi_depth(value) for _, value in tree[2]), default=0)
    if tree[0] == 'op':
        return max((phi_depth(operand) for operand in tree[2]), default=0)

    return 0


def merge(join: tuple, states: list[tuple[int, State]], neutral_key) -> State:
    """A join's entry state from its predecessors' (terminal address, exit state): a key on which they agree keeps its
    value, any other a phi over the predecessors ordered by terminal address (past PHI_DEPTH an opaque leaf of the
    join). neutral_key names a layer's key the way every layer does"""
    keys = set().union(*(state.items.keys() for _, state in states))
    merged = State()
    for key in keys:
        values = [(address, state.items.get(key, ('absent', neutral_key(key)))) for address, state in states]
        first = values[0][1]
        if all(value == first for _, value in values[1:]):
            merged.items[key] = first
            continue

        phi = ('phi', join, tuple(sorted(values, key=lambda pair: pair[0])))
        merged.items[key] = phi if phi_depth(phi) <= PHI_DEPTH else ('deep_phi', join, neutral_key(key))

    return merged
