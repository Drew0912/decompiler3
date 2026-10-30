"""What the VM's effects do to a layer's storage, one definition for every layer: a global's store, a store through a
pointer, a return, a call with its clobbering, and the write through which a local's address escapes. A layer's rule
picks its IR's operands, a call's kind and target and whether it clobbers, and calls the operation its instruction
makes"""

from typing import Callable

from falcom.ed9.disasm.stack_effects import REGISTER_COUNT, RESULT_REGISTER
from .facts import Effect
from .state import ESCAPED, GLOBAL_EPOCH, MEMORY_EPOCH, State
from .trees import tagged_leaves


class VMEffects:
    """The VM's effects bound to one layer: its neutral_key and the address-taken locals its evaluation meets
    (address_of). The register facts are the engine's, ED9's here: another engine's layers name a subclass with its own
    (their VM_EFFECTS)"""

    REGISTER_COUNT  = REGISTER_COUNT
    RESULT_REGISTER = RESULT_REGISTER

    def __init__(self, neutral_key: Callable):
        self.address_taken = set()      # the layer's own keys whose address a tree holds (address_of)
        self.neutral_key = neutral_key
        self.owners = {}                # neutral key -> the layer's own keys
        # every register but the result: a call changes them, a return passes them on
        self.other_registers = [('reg', index) for index in range(self.REGISTER_COUNT) if index != self.RESULT_REGISTER]

    def address_of(self, key: tuple) -> tuple:
        """The leaf holding the address of the layer's local key, which is address-taken from here on"""
        neutral = self.neutral_key(key)
        if key not in self.address_taken:
            self.address_taken.add(key)
            self.owners.setdefault(neutral, []).append(key)
        return ('address', neutral)

    def write(self, state: State, key: tuple, value):
        """key holds value; an address in it written to a register, or to a de-SSA split of one, escapes (escape)"""
        if self.neutral_key(key)[0] == 'reg':
            self.escape(state, value)
        state.set(key, value)

    def store_global(self, state: State, address: int, index: int, value) -> Effect:
        self.escape(state, value)
        state.set(('global', index), value)
        return Effect(address, 'store global', index, (value,))

    def store_deref(self, state: State, address: int, pointer, value) -> Effect:
        """A store through a pointer changes memory behind pointers, none of the function's locals: LLIL dereferences
        only a caller's pointer, and MLIL writes a local's memory form as the local"""
        self.escape(state, value)
        state.set(MEMORY_EPOCH, address)
        return Effect(address, 'store deref', None, (pointer, value))

    def ret(self, state: State, address: int, value=None) -> Effect:
        """value returned, or for none (a bare return) the result register's; every other register passed on"""
        if value is None:
            value = state.register(self.RESULT_REGISTER)
        return Effect(address, 'return', None, (value,), storage=self.return_registers(state))

    def call(self, state: State, address: int, kind: str, target, args: tuple, clobbers: bool = True) -> Effect:
        """A call; one that clobbers passes the locals it can reach (reachable_locals) as local_values gives them, then
        changes every register (the result to the call's), every global, memory behind a pointer and those locals"""
        effect = Effect(address, kind, target, args)
        if not clobbers:
            return effect

        pointed = self.reachable_locals(state, args)
        effect.storage = self.local_values(state, pointed)
        after = ('after', address)
        for key in self.other_registers:
            state.items[key] = ('reg', key[1], after)
        for key in [key for key in state.items if key[0] == 'global']:
            del state.items[key]
        state.set(GLOBAL_EPOCH, address)
        state.set(MEMORY_EPOCH, address)
        for key in pointed:
            state.set(key, ('slot_after', key, address))
        state.set(('reg', self.RESULT_REGISTER), ('call', address))
        return effect

    def escape(self, state: State, value):
        """A local's address stored outside a call's arguments (in a global, through a pointer, in a register)
        escapes: every later call can reach the local. Real bytecode stores none (a census of validator-300)"""
        for key in self.pointed_by(value):
            state.set((ESCAPED, key), (ESCAPED,))

    def pointed_by(self, tree) -> list[tuple]:
        """The address-taken locals whose address tree holds; for a layer with none (most), no tree walked"""
        if not self.owners:
            return []

        return [key for leaf in tagged_leaves(tree, 'address') for key in self.owners.get(leaf[1], ())]

    def reachable_locals(self, state: State, args: tuple) -> list[tuple]:
        """The address-taken locals a callee can reach, by neutral key: those the arguments hold the address of and
        those whose address escaped before (escape), then, to a fixed point, those a reached local's value holds the
        address of (a pointer to a pointer). Not every address-taken local: its slot may hold a call's setup
        elsewhere, after the local's scope ends. None for a layer with no address-taken local (most)"""
        if not self.owners:
            return []

        reached = set()
        pending = [key for key in self.address_taken if (ESCAPED, key) in state.items] + self.pointed_by(args)
        while pending:
            key = pending.pop()
            if key not in reached:
                reached.add(key)
                pending.extend(self.pointed_by(state.items.get(key)))

        return sorted(reached, key=lambda key: repr(self.neutral_key(key)))

    def local_values(self, state: State, keys: list[tuple]) -> dict:
        """Neutral key -> value of each local: what a callee can read behind its pointers"""
        return {self.neutral_key(key):
                    state.items.get(key, key if key[0] == 'param' else ('undef', self.neutral_key(key)))
                for key in keys}

    def return_registers(self, state: State) -> dict:
        """Key -> value of every register but the result, which the return passes on: VM state the caller can read
        after the call. A call's registers are not its inputs: no function reads a register it has not written"""
        return {key: state.register(key[1]) for key in self.other_registers}
