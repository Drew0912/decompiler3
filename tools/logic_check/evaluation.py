"""The evaluation walk: one layer's blocks in reverse post-order over its storage state, giving the facts compared
across layers - each effect with its argument trees and guard, each branch with its condition and targets, which
effect can run next, and each value a loop carries into its header

A layer adapter (llil_layer.py, mlil_layer.py, hlil_layer.py) offers: entry; successors(block); predecessors(block);
branch(block) -> (address, true target, false target) or None; step(inst, state, facts) -> the effects inst has (it
records a branch in facts and changes state); neutral_key(key); OWN_STORAGE_NAMES. Named by address (LLIL against
MLIL) it also offers terminal_address(block) and only_copies(block), whether it holds nothing but writes to stack,
parameters and registers and its jump; gated (MLIL against HLIL, whose structured statements keep no jump addresses)
header_name(block), the address naming a loop header on both layers"""

from dataclasses import dataclass, field
from typing import Callable, Hashable, NamedTuple

from ir.core import reverse_post_order
from .formulas import TRUE, conjunction, disjunction, literal
from .post_dominators import (
    TRUE_ARM, back_edges, control_dependence, immediate_dominators, immediate_post_dominators, iteration_dependence,
)
from .state import Fingerprints, State, incoming_value, merge, merged_value

MAX_ROUNDS = 64             # widening at loop headers converges in a few; past this the walk is an internal error
FUNCTION_ENTRY = -1         # the terminal address of the function entry's virtual predecessor
START, FALL_OFF = 'start', 'fall off'
RETURN_KEY = (None, 'return')   # a gated layer's returns, one effect: HLIL may merge two into one (a common return)
LOOP_ENTRY, LOOP_BACK = 'entry', 'back'


@dataclass
class Effect:
    address: int
    kind: str               # 'call' (debug.log too), 'script call', 'syscall', 'store global', 'store deref', 'return';
                            # gated, a loop's 'loop' and 'loop continue' (GatedNaming.loop_effects)
    target: Hashable
    args: tuple
    guard: frozenset = frozenset()
    storage: tuple = ()     # what it passes on besides args, (neutral key, value) pairs: a call the locals they point
                            # to (State.local_values), a return the other registers (State.return_registers)
    guard_formula: tuple = TRUE     # gated: the formula it runs under (GatedNaming.guard_formula)

    @property
    def key(self) -> tuple:
        return (self.address, self.kind)


@dataclass
class Branch:
    address: int
    condition: tuple
    true_target: int        # target block start addresses (HLIL: node indexes)
    false_target: int


@dataclass
class Facts:
    effects: dict[tuple, list[Effect]] = field(default_factory=dict)
    branches: dict[int, Branch] = field(default_factory=dict)
    next_effects: dict[Hashable, frozenset] = field(default_factory=dict)
    # (header, key, incoming edge) -> each copy of the loop's (formula it runs under, value): HLIL may rebuild one
    loop_values: dict[tuple, list[tuple]] = field(default_factory=dict)
    neutral_key: Callable[[tuple], tuple] | None = None    # a layer's own storage key the way every layer names it
    unstructured: list = field(default_factory=list)        # HLIL: the reachable jumps it could not express

    def neutral(self, key: tuple) -> tuple:
        """key the way every layer names it"""
        return key if self.neutral_key is None else self.neutral_key(key)


def edge_address(layer, predecessor) -> int:
    """The address naming the edge from predecessor on every layer: its terminal's (block merging and edge splitting
    keep the terminal instructions), or FUNCTION_ENTRY from an entry block that only copies and passes control on to
    one block: a preheader one layer puts in front of a loop at the function's start is the other's function entry
    edge"""
    if (predecessor is layer.entry and not layer.predecessors(predecessor)
            and len(layer.successors(predecessor)) == 1 and layer.only_copies(predecessor)):
        return FUNCTION_ENTRY

    return layer.terminal_address(predecessor)


class Arm(NamedTuple):
    """An arm a block runs under: its branch block's position in reverse post-order, its polarity (TRUE_ARM or
    FALSE_ARM), the branch block and the branch's address"""
    position: int
    polarity: str
    block: Hashable
    address: int


class AddressNaming:
    """LLIL against MLIL: a join named by the addresses of its incoming edges (edge_address), a merged value a phi over
    them, a loop value per incoming edge"""

    def __init__(self, layer, order: list, position: dict):
        self.layer = layer
        self.position = position
        self.joins = {block: self.join_identity(block) for block in order}

    def join_identity(self, block) -> tuple:
        """A join's identity on every layer: the addresses of the edges into it from reachable blocks"""
        identity = sorted(edge_address(self.layer, predecessor) for predecessor in self.layer.predecessors(block)
                          if predecessor in self.position)
        return tuple(([FUNCTION_ENTRY] if block is self.layer.entry else []) + identity)

    def join(self, block):
        return self.joins[block]

    def header(self, block):
        return self.joins[block]

    @classmethod
    def exit_rank(cls, block) -> int:
        """Which block of an endless region gets the EXIT edge (post_dominators.exit_blocks): the lowest address"""
        return block.start

    @classmethod
    def effect_key(cls, effect: Effect) -> tuple:
        return effect.key

    def incoming(self, block, states: list[tuple], facts: Facts) -> list[tuple]:
        """(edge name, exit state) of each predecessor's (block, exit state), the function entry's included"""
        incoming = [(edge_address(self.layer, predecessor), state) for predecessor, state in states]
        if block is self.layer.entry:
            incoming.append((FUNCTION_ENTRY, State()))
        return incoming

    @classmethod
    def loop_effects(cls, header, facts: Facts) -> list[Effect]:
        """None: LLIL against MLIL compares the branches that decide a loop"""
        return []

    def loop_values(self, header, keys: set, exit_states: dict, facts: Facts, fingerprints: Fingerprints):
        states = [(predecessor, exit_states[predecessor]) for predecessor in self.layer.predecessors(header)
                  if predecessor in self.position]
        for key in keys:
            for address, state in self.incoming(header, states, facts):
                facts.loop_values[(self.joins[header], key, address)] = \
                    [(TRUE, state.items.get(key, incoming_value(key, self.layer.neutral_key)))]


class GatedNaming:
    """MLIL against HLIL, whose structured statements keep no jump addresses: a merged value is a gated choice over the
    formulas each incoming edge is taken under once the join's immediate dominator has run (gated, within), a loop
    header is named by the layer (header_name), and a loop carries one value in along its entry edges and one round
    along its back edges, those gated from the header, each copy of a loop under the formula it runs or goes round
    under. No branch is compared on its own, so a loop's running and going round again are pseudo-effects
    (loop_effects)"""

    exit_rank = None        # a sink region's EXIT edge from its first block in reverse post-order, its loop's header

    def __init__(self, layer, order: list, position: dict):
        self.layer = layer
        self.position = position
        self.dominators = immediate_dominators(order, layer.predecessors)
        self.span = self.dominator_tree_span(order)
        dependence, self.innermost_header, self.bodies = iteration_dependence(
            order, layer.successors, layer.predecessors, layer.branch, exit_rank=self.exit_rank)
        self.post_dominators = immediate_post_dominators(order, layer.successors, exit_rank=self.exit_rank)
        self.only_ways = {}     # (branch block, target) -> whether its edge to target post-dominates it
        self.left_loops = {}    # (branch block, target) -> the header of the outermost loop that edge leaves, or None
        self.arms = self.earlier_arms(order, dependence)
        self.within_memo, self.within_memo_facts = {}, None

    def branch_blocks(self, order: list) -> dict:
        """branch address -> the block ending in it"""
        blocks = {}
        for block in order:
            branch = self.layer.branch(block)
            if branch is not None:
                blocks[branch[0]] = block
        return blocks

    def earlier_arms(self, order: list, dependence: dict) -> dict:
        """block -> its arms (control dependence within an iteration of its innermost loop) on earlier blocks, in
        order: an arm of a later block (a loop's own test) only repeats it, since the block ran before that test"""
        block_of = self.branch_blocks(order)
        arms = {}
        for block in order:
            found = [Arm(self.position[block_of[address]], polarity, block_of[address], address)
                     for address, polarity in dependence[block]]
            arms[block] = sorted((arm for arm in found if arm.position < self.position[block]),
                                 key=lambda arm: (arm.position, arm.polarity))
        return arms

    def dominator_tree_span(self, order: list) -> dict:
        """block -> (first, last) of its dominator subtree's numbers, a pre-order of the dominator tree"""
        children = {block: [] for block in order}
        for block in order[1:]:
            children[self.dominators[block]].append(block)
        span, number, pending = {}, 0, [(order[0], False)]
        while pending:
            block, done = pending.pop()
            if done:
                span[block] = (span[block], number - 1)
                continue
            span[block] = number
            number += 1
            pending.append((block, True))
            pending.extend((child, False) for child in reversed(children[block]))
        return span

    def dominates(self, a, b) -> bool:
        return self.span[a][0] <= self.span[b][0] <= self.span[a][1]

    @classmethod
    def join(cls, block):
        return None

    def header(self, block):
        return self.layer.header_name(block)

    @classmethod
    def effect_key(cls, effect: Effect) -> tuple:
        return RETURN_KEY if effect.kind == 'return' else effect.key

    def edge_condition(self, source, target, facts: Facts) -> tuple:
        """The arm the edge from source to target is, unless no arm: a jump, or an edge every path from source takes
        (only_way), whose arm holds whenever control leaves source for good (a loop's single exit, its test's last
        iteration); as control dependence reads an edge given a block of its own"""
        branch = self.layer.branch(source)
        if branch is None or branch[1] is branch[2] or self.only_way(source, target):
            return TRUE

        return literal(facts.branches[branch[0]].condition, target is branch[1])

    def only_way(self, source, target) -> bool:
        """Whether every path from branch source takes its edge to target: target post-dominates it, and the other arm
        reaches target only through source again"""
        key = (source, target)
        found = self.only_ways.get(key)
        if found is None:
            _, true_target, false_target = self.layer.branch(source)
            found = self.post_dominators.get(source) is target
            pending, seen = [false_target if target is true_target else true_target], {source}
            while found and pending:
                block = pending.pop()
                if block is target:
                    found = False
                elif block not in seen:
                    seen.add(block)
                    pending.extend(self.layer.successors(block))
            self.only_ways[key] = found
        return found

    def left_loop(self, source, target):
        """The header of the outermost loop an edge every path from source takes (only_way) leaves, or None"""
        key = (source, target)
        if key not in self.left_loops:
            branch = self.layer.branch(source)
            left = None
            if branch is not None and branch[1] is not branch[2] and self.only_way(source, target):
                left = max((header for header, body in self.bodies.items() if source in body and target not in body),
                           key=lambda header: len(self.bodies[header]), default=None)
            self.left_loops[key] = left
        return self.left_loops[key]

    def arrival(self, dominator, source, target, facts: Facts) -> tuple:
        """The formula the edge from source to target is taken under once dominator has run: source's and the edge's
        arm; for an edge out of loops every path from source takes, the outermost loop's own formula, since it is taken
        whenever the loop ends (an exit test HLIL splits in two, an `&&`, keeps the first test's arm in its source's)"""
        left = self.left_loop(source, target)
        if left is not None:
            return self.within(dominator, left, facts)

        return conjunction(self.within(dominator, source, facts), self.edge_condition(source, target, facts))

    def within(self, dominator, block, facts: Facts) -> tuple:
        """The formula block runs under once dominator has run: one of its arms taken, each under its own block's; an
        arm outside dominator's subtree means block runs whenever dominator does (it post-dominates it), and a block in
        a loop with no arm in its iteration runs whenever the iteration does, its header's formula. The function's entry
        as dominator gives the formula a block runs under (guard_formula)"""
        if facts is not self.within_memo_facts:
            self.within_memo, self.within_memo_facts = {}, facts    # a round's own branch conditions
        key = (dominator, block)
        found = self.within_memo.get(key)
        if found is not None:
            return found

        arms = self.arms[block]
        if any(arm.block is not dominator and not self.dominates(dominator, arm.block) for arm in arms):
            result = TRUE           # block post-dominates dominator: it runs whenever dominator does
        elif arms:
            result = disjunction(self.arm_formula(dominator, arm, facts) for arm in arms)
        else:
            result = self.iteration_formula(dominator, block, facts)
        self.within_memo[key] = result
        return result

    def arm_formula(self, dominator, arm, facts: Facts) -> tuple:
        """The formula arm is taken under once dominator has run: its branch block's, and the arm's own"""
        taken = literal(facts.branches[arm.address].condition, arm.polarity == TRUE_ARM)
        return taken if arm.block is dominator else conjunction(self.within(dominator, arm.block, facts), taken)

    def iteration_formula(self, dominator, block, facts: Facts) -> tuple:
        """The formula of a block with no arm in its iteration once dominator has run: the iteration's, its header's
        (none within dominator's own loop, or outside every loop)"""
        header = self.innermost_header.get(block)
        if header is None or self.dominates(header, dominator):
            return TRUE

        return self.within(dominator, header, facts)

    def gated(self, target, dominator, states: list[tuple], facts: Facts) -> list[tuple]:
        """(the formula its edge to target is taken under once dominator has run, exit state) of each predecessor's
        (block, exit state)"""
        if len(states) < 2:
            return [(TRUE, state) for _, state in states]

        return [(self.arrival(dominator, predecessor, target, facts), state) for predecessor, state in states]

    def incoming(self, block, states: list[tuple], facts: Facts) -> list[tuple]:
        if block is self.layer.entry:
            return [(TRUE, State())]   # the entry's other predecessors are back edges

        return self.gated(block, self.dominators[block], states, facts)

    def guard_formula(self, block, facts: Facts) -> tuple:
        """The formula block runs under"""
        return self.within(self.layer.entry, block, facts)

    def latches(self, header) -> list:
        return [predecessor for predecessor in self.layer.predecessors(header)
                if predecessor in self.position and self.position[predecessor] >= self.position[header]]

    def going_round(self, header, facts: Facts) -> tuple:
        """The formula a loop goes round again under: it runs, and an iteration ends on a back edge (gated from the
        header). The running part tells copies of a loop HLIL rebuilds on several paths (one stamp) apart"""
        again = disjunction(self.arrival(header, latch, header, facts) for latch in self.latches(header))
        return conjunction(self.guard_formula(header, facts), again)

    def loop_effects(self, header, facts: Facts) -> list[Effect]:
        """A loop's pseudo-effects, named by its header: 'loop' under the formula the loop runs under, 'loop continue'
        under the one it goes round again under"""
        name = self.header(header)
        return [Effect(name, 'loop', None, (), guard_formula=self.guard_formula(header, facts)),
                Effect(name, 'loop continue', None, (), guard_formula=self.going_round(header, facts))]

    def loop_values(self, header, keys: set, exit_states: dict, facts: Facts, fingerprints: Fingerprints):
        """The values the loop carries in under the formula it runs under, and round under the one it goes round again
        under: each copy of a loop HLIL rebuilds on several paths (one stamp) adds its own"""
        forward = [(predecessor, exit_states[predecessor]) for predecessor in self.layer.predecessors(header)
                   if predecessor in self.position and self.position[predecessor] < self.position[header]]
        back = [(latch, exit_states[latch]) for latch in self.latches(header)]
        groups = ((LOOP_ENTRY, self.guard_formula(header, facts), self.incoming(header, forward, facts)),
                  (LOOP_BACK, self.going_round(header, facts), self.gated(header, header, back, facts)))
        name = self.header(header)
        for key in keys:
            for edges, formula, incoming in groups:
                facts.loop_values.setdefault((name, key, edges), []).append(
                    (formula, merged_value(None, key, incoming, fingerprints)))


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

    facts.next_effects = next_effects(layer, order, effects_of, naming.effect_key)
    for header, keys in widened.items():
        naming.loop_values(header, keys, exit_states, facts, fingerprints)
        for effect in naming.loop_effects(header, facts):   # out of the next-effect relation
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
