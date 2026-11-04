"""What the VM's effects do to a layer's storage, one definition for every layer: a global's store, a store through a
pointer, a return, a call with its clobbering, and the write through which a local's address escapes. A layer's rule
picks its IR's operands, a call's kind and target and whether it clobbers, and calls the operation its instruction
makes"""

from typing import Callable

from falcom.ed9.disasm.stack_effects import REGISTER_COUNT, RESULT_REGISTER
from .facts import Effect
from .state import ESCAPED, GLOBAL_EPOCH, MEMORY_EPOCH, REGISTER_EPOCH, State
from .trees import equal_trees, tagged_leaves


class VMEffects:
    """The VM's effects bound to one layer: its neutral_key and the address-taken locals its evaluation meets
    (address_of). The register facts are the engine's, ED9's here: another engine's layers name a subclass with its own
    (their VM_EFFECTS)"""

    REGISTER_COUNT  = REGISTER_COUNT
    RESULT_REGISTER = RESULT_REGISTER

    def __init__(self, neutral_key: Callable):
        self.address_taken = set()      # the layer's own keys whose address a tree holds (address_of)
        self.neutral_key = neutral_key
        # every register but the result: a return passes them on
        self.other_registers = [('reg', index) for index in range(self.REGISTER_COUNT) if index != self.RESULT_REGISTER]

    def address_of(self, key: tuple) -> tuple:
        """The leaf holding the address of the layer's local key, which is address-taken from here on: its neutral key,
        which the comparison reads, then its own, which tells apart the locals of one slot (sibling scopes)"""
        self.address_taken.add(key)
        return ('address', self.neutral_key(key), key)

    def write(self, state: State, key: tuple, value):
        """key holds value; an address in it written to a register, or to a de-SSA split of one, escapes (escape). A
        register with no value stored, written with what a read gives (State.register), stays unstored: the de-SSA's
        copy of a register into itself after a call (reg5 = REG[5]), which another layer does not make, so both merge
        the register alike. A split is stored as written: the de-SSA makes no such copy under a split name"""
        if self.neutral_key(key)[0] == 'reg':
            self.escape(state, value)
        if key[0] == 'reg' and key not in state.items and equal_trees(value, state.register(key[1])):
            return
        state.set(key, value)

    def store_global(self, state: State, address: int, index: int, value) -> Effect:
        self.escape(state, value)
        state.set(('global', index), value)
        return Effect(address, 'store global', index, (value,))

    def store_deref(self, state: State, address: int, pointer, value) -> Effect:
        """A store through a pointer changes memory behind pointers, none of the function's locals: LLIL dereferences
        only a caller's pointer (a decompiler rule: the VM follows any Integer), and MLIL writes a local's memory form
        as the local"""
        self.escape(state, value)
        state.set(MEMORY_EPOCH, address)
        return Effect(address, 'store deref', None, (pointer, value))

    def ret(self, state: State, address: int, value=None) -> Effect:
        """value returned, or for none (a bare return) the result register's; every other register passed on"""
        if value is None:
            value = state.register(self.RESULT_REGISTER)
        return Effect(address, 'return', None, (value,), storage=self.return_registers(state))

    def call(self, state: State, address: int, kind: str, target, args: tuple, clobbers: bool = True,
             delivers_result: bool = True) -> Effect:
        """A call; one that clobbers passes the locals it can reach (reachable_locals) as local_values gives them, then
        changes every register (the result to the call's, every other read after it: REGISTER_EPOCH), every global,
        memory behind a pointer and those locals. Where the layer's call does not write the result register
        (delivers_result False: an MLIL call with another output or none, every HLIL call), the register holds
        uncaptured, a value no LLIL holds, so a read the layer never stored the result for differs"""
        effect = Effect(address, kind, target, args)
        if not clobbers:
            return effect

        pointed = self.reachable_locals(state, args)
        effect.storage = self.local_values(state, pointed)
        for key in [key for key in state.items if key[0] in ('global', 'reg')]:
            del state.items[key]
        state.set(GLOBAL_EPOCH, address)
        state.set(REGISTER_EPOCH, ('after', address))
        state.set(MEMORY_EPOCH, address)
        for key in pointed:
            state.set(key, ('slot_after', key, address))
        state.set(('reg', self.RESULT_REGISTER), ('call', address) if delivers_result else ('uncaptured', address))
        return effect

    def escape(self, state: State, value):
        """A local's address stored outside a call's arguments (in a global, through a pointer, in a register)
        escapes: every later call can reach the local. Real bytecode stores none (a census of validator-300)"""
        for key in self.pointed_by(value):
            state.set((ESCAPED, key), (ESCAPED,))

    def pointed_by(self, tree) -> list[tuple]:
        """The address-taken locals whose address tree holds, by their own keys; for a layer with none (most), no tree
        walked"""
        if not self.address_taken:
            return []

        return [leaf[-1] for leaf in tagged_leaves(tree, 'address') if leaf[-1] in self.address_taken]

    def reachable_locals(self, state: State, args: tuple) -> list[tuple]:
        """The address-taken locals a callee can reach, by own key: those the arguments hold the address of and those
        whose address escaped before (escape), then, to a fixed point, those a reached local's value holds the address
        of (a pointer to a pointer). Not every address-taken local: its slot may hold a call's setup elsewhere, after
        the local's scope ends. None for a layer with no address-taken local (most)"""
        if not self.address_taken:
            return []

        reached = set()
        pending = [key for key in self.address_taken if (ESCAPED, key) in state.items] + self.pointed_by(args)
        while pending:
            key = pending.pop()
            if key not in reached:
                reached.add(key)
                pending.extend(self.pointed_by(state.items.get(key)))

        return sorted(reached, key=lambda key: (repr(self.neutral_key(key)), repr(key)))

    def local_values(self, state: State, keys: list[tuple]) -> dict:
        """Neutral key -> value of each local: what a callee can read behind its pointers. Two locals of one slot
        reached at once keep the one sorted last: that takes a scope's address escaping before its slot is reused,
        which real bytecode never stores (escape)"""
        return {self.neutral_key(key):
                    state.items.get(key, key if key[0] == 'param' else ('undef', self.neutral_key(key)))
                for key in keys}

    def return_registers(self, state: State) -> dict:
        """Key -> value of every register but the result, which the return passes on: VM state the caller can read
        after the call. A call's registers are not its inputs: no function reads a register it has not written"""
        return {key: state.register(key[1]) for key in self.other_registers}
