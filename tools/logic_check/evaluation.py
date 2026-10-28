"""The evaluation walk: one layer's blocks in reverse post-order over its storage state, giving the facts compared
across layers (facts.py) - each effect with its argument trees and guard, each branch with its condition and targets,
which effect can run next, and each value a loop carries into its header

A layer adapter (llil_layer.py, mlil_layer.py, hlil_layer.py) offers: entry; successors(block); predecessors(block);
branch(block) -> (address, true target, false target) or None; step(inst, state, facts) -> the effects inst has (it
records a branch in facts and changes state); neutral_key(key); OWN_STORAGE_NAMES. Named by address (LLIL against
MLIL) it also offers terminal_address(block) and only_copies(block), whether it holds nothing but writes to stack,
parameters and registers and its jump; gated (MLIL against HLIL, whose structured statements keep no jump addresses)
header_name(block), the address naming a loop header on both layers"""

from typing import Callable, Hashable

from ir.core import reverse_post_order
from .facts import Effect, Facts
from .naming import AddressNaming, GatedNaming
from .neutral_names import Fingerprints
from .post_dominators import back_edges, control_dependence
from .state import State, merge

MAX_ROUNDS = 64             # widening at loop headers converges in a few; past this the walk is an internal error
START, FALL_OFF = 'start', 'fall off'


def run_block(layer, block, entry: State, facts: Facts) -> tuple[State, list[Effect]]:
    state = entry.copy()
    effects = []
    for inst in block.instructions:
        effects.extend(layer.step(inst, state, facts))

    return state, effects


def analyze(layer, *, gated: bool = False) -> Facts:
    """The facts of the layer's function, its joins named by address or gated (AddressNaming, GatedNaming). A loop
    header's storage is widened to a leaf of the header, ('loop', header, the layer's own key), where a back edge brings
    it a value other than the one it enters with; each round walks the blocks once over forward edges only, so given
    the widened storage every state is exact, and the widened storage only grows. A layer whose storage has names of
    its own (de-SSA's split ranges) hands its neutral_key to the comparison, which compares trees under neutral names
    and pairs loop leaves by the trees that read them"""
    order = reverse_post_order(layer.entry, layer.successors)
    position = {block: index for index, block in enumerate(order)}
    naming = (GatedNaming if gated else AddressNaming)(layer, order, position)
    fingerprints = Fingerprints(layer.neutral_key)
    entry_states, exit_states, widened = widen_loop_headers(layer, order, position, naming, fingerprints)

    facts = Facts(neutral_key=layer.neutral_key if layer.OWN_STORAGE_NAMES else None)
    effects_of = {}
    for block in order:
        exit_states[block], effects_of[block] = run_block(layer, block, entry_states[block], facts)
        for effect in effects_of[block]:
            facts.effects.setdefault(naming.effect_key(effect), []).append(effect)

    guards = control_dependence(order, layer.successors, layer.branch, exit_rank=naming.exit_rank)
    for block, effects in effects_of.items():
        for effect in effects:
            effect.guard = guards[block]
            if gated:
                effect.guard_formula = naming.guard_formula(block, facts)

    if gated:
        naming.mark_loops(order, effects_of, facts)
    loop_effects = {header: naming.loop_effects(header, facts) for header in widened}
    # A loop is a place in the order even where it makes no effect of its own: a store moved past a wait loop
    runs_first = {block: [*loop_effects.get(block, [])[:1], *effects] for block, effects in effects_of.items()}
    facts.next_effects = next_effects(layer, order, runs_first, naming.effect_key)
    for header, keys in widened.items():
        naming.loop_values(header, keys, exit_states, facts, fingerprints)
        for effect in loop_effects[header]:
            facts.effects.setdefault(naming.effect_key(effect), []).append(effect)

    return facts


def widen_loop_headers(layer, order: list, position: dict, naming,
                       fingerprints: Fingerprints) -> tuple[dict, dict, dict]:
    """(entry states, exit states, header -> its widened keys) once no back edge brings a header a value other than
    the one it enters with"""
    loops = back_edges(order, layer.successors)
    widened = {header: set() for _, header in loops}
    for _ in range(MAX_ROUNDS):
        entry_states, exit_states = walk_forward(layer, order, position, naming, widened, fingerprints)
        added = False
        for source, header in loops:
            carried, entering = exit_states[source].items, entry_states[header].items
            for key in carried.keys() | entering.keys():
                if key not in widened[header] and carried.get(key) != entering.get(key):
                    widened[header].add(key)
                    added = True
        if not added:
            return entry_states, exit_states, widened

    raise RuntimeError(f'the evaluation did not converge in {MAX_ROUNDS} rounds')


def walk_forward(layer, order: list, position: dict, naming, widened: dict,
                 fingerprints: Fingerprints) -> tuple[dict, dict]:
    """Every block's entry and exit state, over forward edges only (the function entry's virtual predecessor holds
    nothing), each widened key of a loop header its leaf"""
    entry_states, exit_states = {}, {}
    facts = Facts()             # the round's branches, for a gated merge's path conditions
    for block in order:
        states = [(predecessor, exit_states[predecessor]) for predecessor in layer.predecessors(block)
                  if predecessor in position and position[predecessor] < position[block]]
        incoming = naming.incoming(block, states, facts)
        state = incoming[0][1].copy() if len(incoming) == 1 else merge(naming.join(block), incoming, fingerprints)
        for key in widened.get(block, ()):
            state.items[key] = ('loop', naming.header(block), key)

        entry_states[block] = state
        exit_states[block], _ = run_block(layer, block, state, facts)

    return entry_states, exit_states


def next_effects(layer, order: list, effects_of: dict, key_of: Callable) -> dict[Hashable, frozenset]:
    """START or an effect's key -> the keys of the effects that can run next (FALL_OFF: the function ends without one;
    a return ends a path)"""
    first_effects = {block: {key_of(effects_of[block][0])} if effects_of[block] else set() for block in order}
    changed = True
    while changed:
        changed = False
        for block in reversed(order):
            if effects_of[block]:
                continue
            new = effects_after(layer, block, first_effects)
            if len(new) != len(first_effects[block]):
                first_effects[block] = new
                changed = True

    result = {START: frozenset(first_effects[layer.entry])}
    for block in order:
        effects = effects_of[block]
        for index, effect in enumerate(effects):
            key = key_of(effect)
            if effect.kind == 'return':
                following = frozenset()
            elif index + 1 < len(effects):
                following = frozenset({key_of(effects[index + 1])})
            else:
                following = frozenset(effects_after(layer, block, first_effects))
            result[key] = result.get(key, frozenset()) | following

    return result


def effects_after(layer, block, first_effects: dict) -> set:
    """The keys of the effects that can run first once block has run (FALL_OFF: the function ends)"""
    successors = layer.successors(block)
    if not successors:
        return {FALL_OFF}

    return set().union(*(first_effects[successor] for successor in successors))
