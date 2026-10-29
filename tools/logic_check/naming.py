"""How a layer's joins and loop headers are named, so that the two layers compared name them alike: by the addresses
of the edges into them (AddressNaming, LLIL against MLIL), or gated, a merged value a choice over the formulas its
edges are taken under (GatedNaming, MLIL against HLIL)"""

from typing import Hashable, NamedTuple

from .facts import RETURN_KEY, Effect, Facts
from .formulas import TRUE, conjunction, disjunction, literal
from .neutral_names import Fingerprints
from .post_dominators import TRUE_ARM, ControlFlow
from .state import State, incoming_value, merged_value

FUNCTION_ENTRY = -1         # the terminal address of the function entry's virtual predecessor
LOOP_ENTRY, LOOP_BACK = 'entry', 'back'


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

    def __init__(self, layer, flow: ControlFlow):
        self.layer = layer
        self.flow = flow
        self.joins = {block: self.join_identity(block) for block in flow.order}

    def join_identity(self, block) -> tuple:
        """A join's identity on every layer: the addresses of the edges into it from reachable blocks"""
        identity = sorted(edge_address(self.layer, predecessor) for predecessor in self.layer.predecessors(block)
                          if predecessor in self.flow.position)
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

    def set_guard(self, effect: Effect, block, facts: Facts):
        """The arms block runs under, compared by address"""
        effect.guard = self.flow.dependence[block]

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
                  if predecessor in self.flow.position]
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

    def __init__(self, layer, flow: ControlFlow):
        self.layer = layer
        self.flow = flow
        self.only_ways = {}     # (branch block, target) -> whether its edge to target post-dominates it
        self.left_loops = {}    # (branch block, target) -> the header of the outermost loop that edge leaves, or None
        self.arms = self.earlier_arms()
        self.within_memo, self.within_memo_facts = {}, None
        self.inside_of, self.after_of = {}, {}     # block -> the loops (names) it is in, the loops it follows
        self.round_after = {}       # a loop's header -> the loops inside it whose exits end its iteration (after_loop)

    def branch_blocks(self) -> dict:
        """branch address -> the block ending in it"""
        blocks = {}
        for block in self.flow.order:
            branch = self.layer.branch(block)
            if branch is not None:
                blocks[branch[0]] = block
        return blocks

    def earlier_arms(self) -> dict:
        """block -> its arms (control dependence within an iteration of its innermost loop) on earlier blocks, in
        order: an arm of a later block (a loop's own test) only repeats it, since the block ran before that test"""
        block_of = self.branch_blocks()
        position, dependence = self.flow.position, self.flow.iteration_dependence
        arms = {}
        for block in self.flow.order:
            found = [Arm(position[block_of[address]], polarity, block_of[address], address)
                     for address, polarity in dependence[block]]
            arms[block] = sorted((arm for arm in found if arm.position < position[block]),
                                 key=lambda arm: (arm.position, arm.polarity))
        return arms

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
            found = self.flow.post_dominators.get(source) is target
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
                bodies = self.flow.loop_bodies
                left = max((header for header, body in bodies.items() if source in body and target not in body),
                           key=lambda header: len(bodies[header]), default=None)
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
        if any(arm.block is not dominator and not self.flow.dominates(dominator, arm.block) for arm in arms):
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
        header = self.flow.innermost_header.get(block)
        if header is None or self.flow.dominates(header, dominator):
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

        return self.gated(block, self.flow.dominators[block], states, facts)

    def guard_formula(self, block, facts: Facts) -> tuple:
        """The formula block runs under"""
        return self.within(self.layer.entry, block, facts)

    def set_guard(self, effect: Effect, block, facts: Facts):
        """The formula block runs under (no branch is compared on its own, so no arms by address)"""
        effect.guard_formula = self.guard_formula(block, facts)

    def mark_loops(self, effects_of: dict, facts: Facts):
        """Each loop's formulas (facts.loop_runs) and, for every effect, the loops it is inside and after (place)"""
        for header, body in self.flow.loop_bodies.items():
            name = self.header(header)
            if name is None:
                continue

            run = self.guard_formula(header, facts)
            ends = disjunction(self.exit_taken(block, successor, facts) for block, successor in self.exit_edges(body))
            copies = facts.loop_runs.get(name)      # HLIL may rebuild a loop: its copies share one stamp
            facts.loop_runs[name] = (run, ends) if copies is None else (disjunction([copies[0], run]),
                                                                        disjunction([copies[1], ends]))
            for block in body:
                self.inside_of.setdefault(block, set()).add(name)
            after, iteration_ends = self.after_loop(header, body)
            for block in after:
                self.after_of.setdefault(block, set()).add(name)
            for enclosing in iteration_ends:
                self.round_after.setdefault(enclosing, set()).add(name)

        for block in self.flow.order:
            for effect in effects_of[block]:
                self.place(effect, block)

    def exit_edges(self, body: set) -> list[tuple]:
        """(block, successor) of each edge leaving the loop's body"""
        return [(block, successor) for block in sorted(body, key=self.flow.position.__getitem__)
                for successor in dict.fromkeys(self.layer.successors(block)) if successor not in body]

    def after_loop(self, header, body: set) -> tuple[set, set]:
        """The blocks reached from the loop's exits within one iteration of the loops around it, and the headers of
        those loops reached: the iteration ends there, so a header is not passed, and only its loop's going round again
        is after the loop; what runs before the loop in the iteration, a header's own effects included, is not"""
        enclosing = {other for other, other_body in self.flow.loop_bodies.items()
                     if other is not header and header in other_body}
        reached = {successor for _, successor in self.exit_edges(body)}
        pending = list(reached)
        while pending:
            block = pending.pop()
            if block in enclosing or block in body:
                continue

            for successor in self.layer.successors(block):
                if successor not in reached:
                    reached.add(successor)
                    pending.append(successor)

        iteration_ends = reached & enclosing
        return reached - body - iteration_ends, iteration_ends

    def exit_taken(self, source, target, facts: Facts) -> tuple:
        """The formula the edge from source to target is taken under in some iteration"""
        branch = self.layer.branch(source)
        inside = self.guard_formula(source, facts)
        if branch is None or branch[1] is branch[2]:
            return inside

        return conjunction(inside, literal(facts.branches[branch[0]].condition, target is branch[1]))

    def place(self, effect: Effect, block, own=None):
        """Which loops effect, made in block, is inside and after; a loop's pseudo-effect (own: its name) is neither of
        its own loop"""
        effect.inside = frozenset(self.inside_of.get(block, ())) - {own}
        effect.after = frozenset(self.after_of.get(block, ())) - {own}

    def latches(self, header) -> list:
        position = self.flow.position
        return [predecessor for predecessor in self.layer.predecessors(header)
                if predecessor in position and position[predecessor] >= position[header]]

    def going_round(self, header, facts: Facts) -> tuple:
        """The formula a loop goes round again under: it runs, and an iteration ends on a back edge (gated from the
        header). The running part tells copies of a loop HLIL rebuilds on several paths (one stamp) apart"""
        again = disjunction(self.arrival(header, latch, header, facts) for latch in self.latches(header))
        return conjunction(self.guard_formula(header, facts), again)

    def loop_effects(self, header, facts: Facts) -> list[Effect]:
        """A loop's pseudo-effects, named by its header: 'loop' under the formula the loop runs under, 'loop continue'
        under the one it goes round again under"""
        name = self.header(header)
        runs = Effect(name, 'loop', None, (), guard_formula=self.guard_formula(header, facts))
        goes_round = Effect(name, 'loop continue', None, (), guard_formula=self.going_round(header, facts))
        for effect in (runs, goes_round):
            self.place(effect, header, own=name)
        goes_round.after |= frozenset(self.round_after.get(header, ()))    # the loops whose exits end its iteration

        return [runs, goes_round]

    def loop_values(self, header, keys: set, exit_states: dict, facts: Facts, fingerprints: Fingerprints):
        """The values the loop carries in under the formula it runs under, and round under the one it goes round again
        under: each copy of a loop HLIL rebuilds on several paths (one stamp) adds its own"""
        position = self.flow.position
        forward = [(predecessor, exit_states[predecessor]) for predecessor in self.layer.predecessors(header)
                   if predecessor in position and position[predecessor] < position[header]]
        back = [(latch, exit_states[latch]) for latch in self.latches(header)]
        groups = ((LOOP_ENTRY, self.guard_formula(header, facts), self.incoming(header, forward, facts)),
                  (LOOP_BACK, self.going_round(header, facts), self.gated(header, header, back, facts)))
        name = self.header(header)
        for key in keys:
            for edges, formula, incoming in groups:
                facts.loop_values.setdefault((name, key, edges), []).append(
                    (formula, merged_value(None, key, incoming, fingerprints)))
