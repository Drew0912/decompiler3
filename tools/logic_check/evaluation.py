"""The evaluation walk: one layer's blocks in reverse post-order over its storage state, giving the facts compared
across layers - each effect with its argument trees and guard, each branch with its condition and targets, which
effect can run next, and each value a loop carries into its header

A layer adapter (llil_layer.py, mlil_layer.py) offers: entry; successors(block); predecessors(block);
terminal_address(block); branch(block) -> (address, true target, false target) or None; step(inst, state, facts) ->
the effects inst has (it records a branch in facts and changes state); neutral_key(key); OWN_STORAGE_NAMES"""

from dataclasses import dataclass, field
from typing import Callable, Hashable

from ir.core import reverse_post_order
from .post_dominators import control_dependence
from .state import Fingerprints, State, merge

MAX_ROUNDS = 64             # widening at loop headers converges in a few; past this the walk is an internal error
FUNCTION_ENTRY = -1         # the terminal address of the function entry's virtual predecessor
START, FALL_OFF = 'start', 'fall off'


@dataclass
class Effect:
    address: int
    kind: str               # 'call' (debug.log too), 'script call', 'syscall', 'store global', 'store deref', 'return'
    target: Hashable
    args: tuple
    guard: frozenset = frozenset()
    storage: tuple = ()     # what it passes on besides args, (neutral key, value) pairs: a call the locals they point
                            # to (State.local_values), a return the other registers (State.return_registers)

    @property
    def key(self) -> tuple:
        return (self.address, self.kind)


@dataclass
class Branch:
    address: int
    condition: tuple
    true_target: int        # target block start addresses
    false_target: int


@dataclass
class Facts:
    effects: dict[tuple, list[Effect]] = field(default_factory=dict)
    branches: dict[int, Branch] = field(default_factory=dict)
    next_effects: dict[Hashable, frozenset] = field(default_factory=dict)
    loop_values: dict[tuple, tuple] = field(default_factory=dict)   # (header, key, incoming terminal address) -> value
    neutral_key: Callable[[tuple], tuple] | None = None     # a layer's own storage key the way every layer names it


def join_identity(layer, block, reachable: dict) -> tuple:
    """A join's identity on every layer: the terminal addresses of the edges into it from reachable blocks (block
    merging and edge splitting keep the terminal instructions)"""
    identity = sorted(layer.terminal_address(predecessor) for predecessor in layer.predecessors(block)
                      if predecessor in reachable)
    return tuple(([FUNCTION_ENTRY] if block is layer.entry else []) + identity)


def run_block(layer, block, entry: State, facts: Facts) -> tuple[State, list[Effect]]:
    state = entry.copy()
    effects = []
    for inst in block.instructions:
        effects.extend(layer.step(inst, state, facts))

    return state, effects


def analyze(layer) -> Facts:
    """The facts of the layer's function. A loop header's storage is widened to a leaf of the header, ('loop', header,
    the layer's own key), where a back edge brings it a value other than the one it enters with; each round walks the
    blocks once over forward edges only, so given the widened storage every state is exact, and the widened storage
    only grows. A layer whose storage has names of its own (de-SSA's split ranges) hands its neutral_key to the
    comparison, which compares trees under neutral names and pairs loop leaves by the trees that read them"""
    order = reverse_post_order(layer.entry, layer.successors)
    position = {block: index for index, block in enumerate(order)}
    back_edges = [(source, target) for source in order for target in layer.successors(source)
                  if position[target] <= position[source]]
    joins = {block: join_identity(layer, block, position) for block in order}
    widened = {header: set() for _, header in back_edges}
    fingerprints = Fingerprints(layer.neutral_key)
    for _ in range(MAX_ROUNDS):
        entry_states, exit_states = walk_forward(layer, order, position, joins, widened, fingerprints)
        added = False
        for source, header in back_edges:
            carried, entering = exit_states[source].items, entry_states[header].items
            for key in carried.keys() | entering.keys():
                if key not in widened[header] and carried.get(key) != entering.get(key):
                    widened[header].add(key)
                    added = True
        if not added:
            break
    else:
        raise RuntimeError(f'the evaluation did not converge in {MAX_ROUNDS} rounds')

    facts = Facts(neutral_key=layer.neutral_key if layer.OWN_STORAGE_NAMES else None)
    effects_of = {}
    for block in order:
        exit_states[block], effects_of[block] = run_block(layer, block, entry_states[block], facts)
        for effect in effects_of[block]:
            facts.effects.setdefault(effect.key, []).append(effect)

    guards = control_dependence(order, layer.successors, layer.branch)
    for block, effects in effects_of.items():
        for effect in effects:
            effect.guard = guards[block]

    facts.next_effects = next_effects(layer, order, effects_of)
    for header, keys in widened.items():
        incoming = [(layer.terminal_address(predecessor), exit_states[predecessor])
                    for predecessor in layer.predecessors(header) if predecessor in position]
        if header is layer.entry:
            incoming.append((FUNCTION_ENTRY, State()))
        for key in keys:
            for address, state in incoming:
                facts.loop_values[(joins[header], key, address)] = \
                    state.items.get(key, ('absent', layer.neutral_key(key)))

    return facts


def walk_forward(layer, order: list, position: dict, joins: dict, widened: dict,
                 fingerprints: Fingerprints) -> tuple[dict, dict]:
    """Every block's entry and exit state, over forward edges only (the function entry's virtual predecessor holds
    nothing), each widened key of a loop header its leaf"""
    entry_states, exit_states = {}, {}
    for block in order:
        incoming = [(layer.terminal_address(predecessor), exit_states[predecessor])
                    for predecessor in layer.predecessors(block)
                    if predecessor in position and position[predecessor] < position[block]]
        if block is layer.entry:
            incoming.append((FUNCTION_ENTRY, State()))
        state = incoming[0][1].copy() if len(incoming) == 1 else merge(joins[block], incoming, fingerprints)
        for key in widened.get(block, ()):
            state.items[key] = ('loop', joins[block], key)

        entry_states[block] = state
        exit_states[block], _ = run_block(layer, block, state, Facts())

    return entry_states, exit_states


def next_effects(layer, order: list, effects_of: dict) -> dict[Hashable, frozenset]:
    """START or an effect's key -> the keys of the effects that can run next (FALL_OFF: the function ends without one;
    a return ends a path)"""
    first = {block: {effects_of[block][0].key} if effects_of[block] else set() for block in order}
    changed = True
    while changed:
        changed = False
        for block in reversed(order):
            if effects_of[block]:
                continue
            new = after(layer, block, first)
            if len(new) != len(first[block]):
                first[block] = new
                changed = True

    result = {START: frozenset(first[layer.entry])}
    for block in order:
        effects = effects_of[block]
        for index, effect in enumerate(effects):
            if effect.kind == 'return':
                result[effect.key] = frozenset()
            elif index + 1 < len(effects):
                result[effect.key] = frozenset({effects[index + 1].key})
            else:
                result[effect.key] = frozenset(after(layer, block, first))

    return result


def after(layer, block, first: dict) -> set:
    successors = layer.successors(block)
    if not successors:
        return {FALL_OFF}

    return set().union(*(first[successor] for successor in successors))
