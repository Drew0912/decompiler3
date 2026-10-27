"""The comparison of two layers' facts, the reference first and the layer checked second: every difference with its
category. LLIL against MLIL (compare_facts; the LLIL is the trust root) matches effects and branches by address and
guards by the branches they depend on; MLIL against HLIL (compare_gated), whose structure HLIL rebuilds, matches
effects by address and compares the formulas they run under"""

import hashlib
import reprlib
from typing import Callable, Hashable, NamedTuple

from .evaluation import RETURN_KEY, Effect, Facts
from .formulas import TRUE, DiagramOverflow, Diagrams, FormulaKeys, conjunction, disjunction
from .state import FINGERPRINT_BYTES, Fingerprints, gated_choice
from .trees import EQUALITIES, loop_leaves, truth

LIFTED_CHOICES = 256            # gated choices lifted into an occurrence's formulas, at most (lifted)
SHOWN = reprlib.Repr(maxlevel=8, maxtuple=6, maxstring=40, maxother=40)  # a gated detail's trees, cut (brief)

CATEGORIES = (
    'missing_effect',               # an effect of the reference absent, or fewer times (gated: absent)
    'added_effect',                 # an effect the reference lacks, or more times (gated: lacks)
    'target_differs',
    'argc_differs',
    'arg_differs',                  # an argument, or a local an argument points to
    'return_differs',               # the result, or another register, at a return
    'guard_differs',                # the branches an effect runs under, or their polarity (gated: its formula)
    'guard_unchecked',              # gated: formulas past a diagram node cap (formulas.DIAGRAM_*NODE_CAP), not compared
    'condition_differs',            # a branch's condition, or a branch on one side only
    'condition_ordering_inverted',  # equal once orderings are read as representative ones (`!(a < b)`, `a >= b`)
    'branch_targets_differ',
    'order_differs',                # the effects that can run next
    'loop_value_differs',           # a value a loop carries round a back edge
    'unstructured_jump',            # a reachable jump HLIL could not express
)


class Difference(NamedTuple):
    category: str
    key: Hashable                   # (address, effect kind), (address, 'branch') or (loop header, storage, edges)
    detail: object


class Namer:
    """A side's trees under neutral names, renamed once each: every storage key a leaf names in the layer's own way (a
    loop value, an address-taken local after a call) the way every layer names it, == and != operands in their
    fingerprints' order, a gated choice by its values and the function choosing each (state.gated_choice), with
    orderings read as representative ones where representative"""

    def __init__(self, facts: Facts, representative: bool = False):
        self.neutral_key = facts.neutral_key or (lambda key: key)   # a deep phi is cut to its fingerprint either way
        self.fingerprints = Fingerprints(self.neutral_key)
        self.keys = FormulaKeys(self.fingerprints, representative)
        self.memo = {}
        self.digests = {}

    def digest(self, renamed) -> bytes:
        """A renamed tree's digest, memoised by identity (a tree shares its parts): equal digests mean equal trees"""
        if not isinstance(renamed, tuple):
            return repr(renamed).encode()
        found = self.digests.get(id(renamed))
        if found is not None:
            return found[1]

        parts = repr([self.digest(item) for item in renamed]).encode()
        digest = hashlib.blake2b(parts, digest_size=FINGERPRINT_BYTES).digest()
        self.digests[id(renamed)] = (renamed, digest)
        return digest

    def __call__(self, tree):
        if not isinstance(tree, tuple) or not tree:
            return tree

        found = self.memo.get(id(tree))
        if found is not None:
            return found[1]

        tag = tree[0]
        if tag == 'loop':
            result = ('loop', tree[1], self.neutral_key(tree[2]))
        elif tag == 'slot_after':
            result = ('slot_after', self.neutral_key(tree[1]), tree[2])
        elif tag == 'deep_phi':
            result = tree[:4]       # the fingerprint is under neutral names; the kept leaves are the layer's own
        elif tag == 'op':
            operands = sorted(tree[2], key=self.fingerprints) if tree[1] in EQUALITIES else tree[2]
            result = ('op', tree[1], tuple(self(operand) for operand in operands))
        elif tag == 'phi':
            result = ('phi', tree[1], tuple((address, self(value)) for address, value in tree[2]))
        elif tag == 'gamma':
            choice = gated_choice(tree, self.fingerprints, self.keys)
            if len(choice) == 1:
                result = self(choice[0][1])
            else:
                result = ('gamma', tuple(sorted(((key, self(value)) for key, value in choice),
                                                key=lambda pair: repr(pair[0]))))
        elif tag in ('deref', 'reg', 'global'):
            result = (tag, *(self(item) for item in tree[1:]))
        else:
            result = tree
        self.memo[id(tree)] = (tree, result)    # the tree kept alive, so its id is not reused
        return result


def compare_facts(reference: Facts, checked: Facts) -> list[Difference]:
    differences = []
    namers = (Namer(reference), Namer(checked))
    compare_effects(reference, checked, namers, differences)
    compare_branches(reference, checked, namers, differences)
    compare_order(reference, checked, differences)
    compare_loop_values(reference, checked, namers, differences)
    return differences


def compare_order(reference: Facts, checked: Facts, differences: list):
    for key in sorted(reference.next_effects.keys() | checked.next_effects.keys(), key=repr):
        expected, found = reference.next_effects.get(key), checked.next_effects.get(key)
        if expected is not None and found is not None and expected != found:
            differences.append(Difference('order_differs', key, (sorted(expected, key=repr), sorted(found, key=repr))))


def compare_effects(reference: Facts, checked: Facts, namers: tuple[Namer, Namer], differences: list):
    name_a, name_b = namers
    for key in sorted(reference.effects.keys() | checked.effects.keys(), key=repr):
        expected, found = reference.effects.get(key, []), checked.effects.get(key, [])
        if len(expected) != len(found):
            category = 'missing_effect' if len(expected) > len(found) else 'added_effect'
            differences.append(Difference(category, key, (len(expected), len(found))))
        for a, b in zip(expected, found):
            if a.target != b.target:
                differences.append(Difference('target_differs', key, (a.target, b.target)))
            category = 'return_differs' if a.kind == 'return' else 'arg_differs'
            if len(a.args) != len(b.args):
                differences.append(Difference('argc_differs', key, (len(a.args), len(b.args))))
            else:
                for index, (x, y) in enumerate(zip(a.args, b.args)):
                    x, y = name_a(x), name_b(y)
                    if x != y:
                        differences.append(Difference(category, key, (index, x, y)))
            storage_a, storage_b = dict(a.storage), dict(b.storage)
            for storage in sorted(storage_a.keys() | storage_b.keys(), key=repr):
                x, y = name_a(storage_a.get(storage)), name_b(storage_b.get(storage))
                if x != y:
                    differences.append(Difference(category, key, (storage, x, y)))
            guard_a = {(address, canonical_polarity(reference, name_a, address, polarity))
                       for address, polarity in a.guard}
            guard_b = {(address, canonical_polarity(checked, name_b, address, polarity))
                       for address, polarity in b.guard}
            if guard_a != guard_b:
                differences.append(Difference('guard_differs', key, (sorted(guard_a), sorted(guard_b))))


def compare_branches(reference: Facts, checked: Facts, namers: tuple[Namer, Namer], differences: list):
    name_a, name_b = namers
    for address in sorted(reference.branches.keys() | checked.branches.keys()):
        a, b = reference.branches.get(address), checked.branches.get(address)
        key = (address, 'branch')
        if a is None or b is None:
            differences.append(Difference('condition_differs', key, 'a branch on one side only'))
            continue

        condition_a, condition_b = name_a(a.condition), name_b(b.condition)
        core_a, _ = truth(condition_a)
        core_b, _ = truth(condition_b)
        if core_a != core_b:
            if truth(condition_a, representative=True)[0] == truth(condition_b, representative=True)[0]:
                differences.append(Difference('condition_ordering_inverted', key, (core_a, core_b)))
            else:
                differences.append(Difference('condition_differs', key, (condition_a, condition_b)))

        # Where control goes when the condition's representative core holds: a negation dropped by swapping the
        # targets is none, an inverted ordering counted once (as the condition's difference)
        targets_a = canonical_targets(a, condition_a)
        targets_b = canonical_targets(b, condition_b)
        if targets_a != targets_b:
            differences.append(Difference('branch_targets_differ', key, (targets_a, targets_b)))


def canonical_targets(branch, condition: tuple) -> tuple[int, int]:
    if truth(condition, representative=True)[1]:
        return branch.false_target, branch.true_target

    return branch.true_target, branch.false_target


def canonical_polarity(facts: Facts, namer: Namer, address: int, polarity: str) -> str:
    """An arm's polarity relative to its branch condition's representative core (an arm of a negated condition
    flips)"""
    branch = facts.branches.get(address)
    if branch is None or not truth(namer(branch.condition), representative=True)[1]:
        return polarity

    return 'f' if polarity == 't' else 't'


def compare_loop_values(reference: Facts, checked: Facts, namers: tuple[Namer, Namer], differences: list):
    """The values loops carry into their headers, along every incoming edge, for each loop leaf the compared trees read
    (effects' arguments and storage, branch conditions, then the carried values in turn). A side's leaves are its own
    storage; the two sides' leaves of one header and neutral name are paired. A loop with copies is compared by
    compare_loop_copies"""
    sides = (reference, checked)
    reading = (set(), set())        # the loop leaves each side's trees read
    for side, facts in enumerate(sides):
        for effects in facts.effects.values():
            for effect in effects:
                reading[side].update(loop_leaves(effect.args))
                reading[side].update(loop_leaves(effect.storage))
        for branch in facts.branches.values():
            reading[side].update(loop_leaves(branch.condition))

    incoming = ({}, {})             # (header, own key) -> the terminal addresses of the edges into the header
    for side, facts in enumerate(sides):
        for header, key, address in facts.loop_values:
            incoming[side].setdefault((header, key), set()).add(address)

    compared = set()
    while True:
        groups = {}                 # (header, neutral key) -> each side's own keys
        for side, facts in enumerate(sides):
            for _, header, key in reading[side]:
                group = (header, key if facts.neutral_key is None else facts.neutral_key(key))
                if group not in compared:
                    groups.setdefault(group, (set(), set()))[side].add(key)
        if not groups:
            return

        for group, keys in sorted(groups.items(), key=repr):
            compared.add(group)
            header = group[0]
            if not (keys[0] and keys[1]):
                continue            # read on one side only: the reading trees differ already

            addresses = sorted(set().union(*(incoming[side].get((header, key), ())
                                             for side in (0, 1) for key in keys[side])))
            copies = ({}, {})       # own key -> along each incoming edge, each copy of the loop's (formula, value)
            for side, facts in enumerate(sides):
                for key in keys[side]:
                    copies[side][key] = tuple(facts.loop_values.get((header, key, address), [(TRUE, ('absent',))])
                                              for address in addresses)
                    for along in copies[side][key]:
                        for _, value in along:
                            reading[side].update(loop_leaves(value))
            if any(len(along) > 1 for side in copies for edges in side.values() for along in edges):
                compare_loop_copies(group, copies, namers, differences)
                continue

            carried = [{key: tuple(namers[side](along[0][1]) for along in edges) for key, edges in copies[side].items()}
                       for side in (0, 1)]  # own key -> its values along the incoming edges, under neutral names
            # Both ways: a checked split carrying a wrong value is not hidden by another split carrying the right one
            told = [{tuple(map(namers[side].digest, values)): values for values in carried[side].values()}
                    for side in (0, 1)]
            expected, found = told[0].keys(), told[1].keys()
            if expected != found:
                a = told[0][min(expected - found or expected)]
                b = told[1][min(found - expected or found)]
                detail = [(address, brief(x), brief(y)) for address, x, y in zip(addresses, a, b)
                          if namers[0].digest(x) != namers[1].digest(y)]
                differences.append(Difference('loop_value_differs', group, detail))


def compare_loop_copies(group: tuple, copies: tuple[dict, dict], namers: tuple[Namer, Namer], differences: list):
    """A loop HLIL rebuilds on several paths, its copies under one stamp: each own key's values along each incoming
    edge, lifted into the formulas the copies carry them under (lifted), so copies on exclusive paths compare with the
    reference's one loop; both ways, as compare_loop_values compares"""
    told = (set(), set())
    for side in (0, 1):
        for edges in copies[side].values():
            described = []
            for along in edges:
                carried = {digest: namers[side].keys(disjunction(formulas))
                           for digest, formulas in lifted(namers[side], along).items()}
                if None in carried.values():
                    differences.append(Difference('guard_unchecked', group, 'loop copies'))
                    return
                described.append(frozenset(carried.items()))
            told[side].add(tuple(described))
    if told[0] != told[1]:
        counts = [max(len(along) for edges in copies[side].values() for along in edges) for side in (0, 1)]
        differences.append(Difference('loop_value_differs', group, [('copies', *counts)]))


# === MLIL against HLIL ===

class GatedSide:
    """One side of a gated comparison: its facts, and its namers as written and with representative orderings"""

    def __init__(self, facts: Facts):
        self.facts = facts
        self.exact = Namer(facts)
        self.representative = Namer(facts, representative=True)


def compare_gated(reference: Facts, checked: Facts) -> list[Difference]:
    """MLIL against HLIL, both analyzed gated: each effect key's occurrences together, since HLIL may repeat an effect
    (a cloned region) or make two one (a common return), and an occurrence count is no finding - the formulas they run
    under joined (compare_formulas), the values they pass, each with the formula it is passed under; a loop's running
    and going round again, as its pseudo-effects; the effects that can run next; the loop values; every reachable
    unstructured jump. A difference that goes once orderings are read as representative ones
    (trees.representative_orderings) is condition_ordering_inverted"""
    differences = []
    sides = (GatedSide(reference), GatedSide(checked))
    for key in sorted(reference.effects.keys() | checked.effects.keys(), key=repr):
        expected, found = reference.effects.get(key, []), checked.effects.get(key, [])
        if not expected or not found:
            category = 'missing_effect' if expected else 'added_effect'
            differences.append(Difference(category, key, (len(expected), len(found))))
            continue

        targets = ({effect.target for effect in expected}, {effect.target for effect in found})
        if targets[0] != targets[1]:
            differences.append(Difference('target_differs', key, tuple(sorted(side, key=repr) for side in targets)))
        argcs = ({len(effect.args) for effect in expected}, {len(effect.args) for effect in found})
        if argcs[0] != argcs[1]:
            differences.append(Difference('argc_differs', key, (sorted(argcs[0]), sorted(argcs[1]))))
            continue

        formulas = (disjunction(effect.condition for effect in expected),
                    disjunction(effect.condition for effect in found))
        category = compare_formulas(sides, formulas)
        if category is not None:
            differences.append(Difference(category, key, tuple(render(formula) for formula in formulas)))
        compare_passed(sides, key, (expected, found), differences)

    compare_order(reference, checked, differences)
    exact = []
    compare_loop_values(reference, checked, (sides[0].exact, sides[1].exact), exact)
    if exact:
        representative = []
        compare_loop_values(reference, checked, (sides[0].representative, sides[1].representative), representative)
        kept = {difference.key for difference in representative}
        differences.extend(difference if difference.key in kept else
                           Difference('condition_ordering_inverted', difference.key, difference.detail)
                           for difference in exact)
    for jump in checked.unstructured:
        differences.append(Difference('unstructured_jump', (jump.address, 'unstructured'), jump.target))
    return differences


def compare_formulas(sides: tuple[GatedSide, GatedSide], formulas: tuple) -> str | None:
    """None when the two sides' formulas are one function, else the category of their difference"""
    if sides[0].exact.fingerprints(formulas[0]) == sides[1].exact.fingerprints(formulas[1]):
        return None

    try:
        if equivalent(sides, formulas, 'exact'):
            return None
        if equivalent(sides, formulas, 'representative'):
            return 'condition_ordering_inverted'
    except DiagramOverflow:
        return 'guard_unchecked'

    return 'guard_differs'


def equivalent(sides: tuple[GatedSide, GatedSide], formulas: tuple, namers: str) -> bool:
    """Whether the formulas are one function: by their truth tables, or, past ROW_CAP rows, by one decision diagram in
    the order the formulas meet their variables"""
    keys = (getattr(sides[0], namers).keys, getattr(sides[1], namers).keys)
    found = (keys[0].table_key(formulas[0]), keys[1].table_key(formulas[1]))
    if None not in found:
        return found[0] == found[1]

    return Diagrams().same(keys[0].structure(formulas[0], {}), keys[1].structure(formulas[1], {}))


def compare_passed(sides: tuple[GatedSide, GatedSide], key: tuple, occurrences: tuple, differences: list):
    """The values an effect's occurrences pass, each argument and storage key on its own: equal under neutral names,
    or, a gated choice lifted into the formula its value is passed under (HLIL may pass from one return what MLIL
    passes from two, merged at the join before it), the same values each under one formula"""
    category = 'return_differs' if key == RETURN_KEY else 'arg_differs'
    expected, found = occurrences
    single = len(expected) == len(found) == 1
    if single and not value_differences(sides, expected[0], found[0], 'exact'):
        return

    storage = sorted({storage for effects in occurrences for effect in effects for storage, _ in effect.storage},
                     key=repr)
    outcomes = {component: compare_component(sides, occurrences, component)
                for component in [*range(len(expected[0].args)), *storage]}
    differing = [component for component, outcome in outcomes.items() if outcome == category]
    unchecked = [component for component, outcome in outcomes.items() if outcome == 'guard_unchecked']
    if differing:
        details = (value_differences(sides, expected[0], found[0], 'exact') if single
                   else [('occurrences', len(expected), len(found), differing)])
        differences.append(Difference(category, key, details))
    elif unchecked:
        differences.append(Difference('guard_unchecked', key, unchecked))
    elif 'condition_ordering_inverted' in outcomes.values():
        differences.append(Difference('condition_ordering_inverted', key, [component for component, outcome
                                                                           in outcomes.items() if outcome]))


def compare_component(sides: tuple[GatedSide, GatedSide], occurrences: tuple, component) -> str | None:
    """None when both sides pass the same values for component (an argument's index or a storage key) under the same
    formulas, else the category: an equal choice once orderings are representative is condition_ordering_inverted"""
    category = 'return_differs' if occurrences[0][0].kind == 'return' else 'arg_differs'
    for namers in ('exact', 'representative'):
        passed = [passed_under(getattr(side, namers), effects, component) for side, effects in zip(sides, occurrences)]
        if passed[0].keys() != passed[1].keys():
            continue
        if len(passed[0]) == 1:
            outcomes = set()        # one value, passed wherever the effect runs: its formula compared already
        else:
            outcomes = {compare_formulas(sides, (disjunction(passed[0][value]), disjunction(passed[1][value])))
                        for value in passed[0]} - {None}
        if not outcomes:
            return None if namers == 'exact' else 'condition_ordering_inverted'
        if outcomes == {'condition_ordering_inverted'}:
            return 'condition_ordering_inverted'
        return 'guard_unchecked' if outcomes == {'guard_unchecked'} else category

    return category


def value_differences(sides: tuple[GatedSide, GatedSide], a: Effect, b: Effect, namers: str) -> list:
    """(index or storage key, a's value, b's value) of each argument and storage the two occurrences differ in"""
    name_a, name_b = getattr(sides[0], namers), getattr(sides[1], namers)
    pairs = list(enumerate(zip(a.args, b.args)))
    storage_a, storage_b = dict(a.storage), dict(b.storage)
    pairs += [(storage, (storage_a.get(storage), storage_b.get(storage)))
              for storage in sorted(storage_a.keys() | storage_b.keys(), key=repr)]
    details = []
    for component, (x, y) in pairs:
        x, y = name_a(x), name_b(y)
        if name_a.digest(x) != name_b.digest(y):
            details.append((component, brief(x), brief(y)))
    return details


def passed_under(namer: Namer, effects: list[Effect], component) -> dict:
    """What the occurrences pass as component, each value's digest under neutral names -> the formulas it is passed
    under (lifted)"""
    return lifted(namer, [(effect.condition, effect.args[component] if isinstance(component, int)
                           else dict(effect.storage).get(component)) for effect in effects])


def lifted(namer: Namer, held: list[tuple]) -> dict:
    """(formula, value) pairs as each value's digest under neutral names -> the formulas it holds under, a gated choice
    lifted into them (to LIFTED_CHOICES alternatives a pair)"""
    passed = {}
    for formula, value in held:
        alternatives, pending = [], [(formula, value)]
        while pending:
            condition, value = pending.pop()
            if (isinstance(value, tuple) and value and value[0] == 'gamma'
                    and len(alternatives) + len(pending) + len(value[1]) <= LIFTED_CHOICES):
                pending.extend((conjunction(condition, choice_formula), choice) for choice_formula, choice in value[1])
            else:
                alternatives.append((condition, value))
        for condition, value in alternatives:
            passed.setdefault(namer.digest(namer(value)), []).append(condition)
    return passed


def brief(tree) -> str:
    """tree as text, cut in depth and width: a tree shares its parts (a gated choice's formulas hold earlier ones) and
    may print exponentially"""
    return SHOWN.repr(tree)


def render(formula, budget: int = 400) -> str:
    """formula as text, cut at budget characters, its conditions brief"""
    parts, pending, length = [], [formula], 0
    while pending and length < budget:
        item = pending.pop()
        if isinstance(item, str):
            parts.append(item)
        elif item[0] == 'lit':
            parts.append(('' if item[2] else '!') + brief(item[1]))
        elif item[0] in ('and', 'or'):
            joiner = ' && ' if item[0] == 'and' else ' || '
            pending.append(')')
            for index, child in enumerate(reversed(item[1])):
                pending.append(child)
                if index + 1 < len(item[1]):
                    pending.append(joiner)
            pending.append('(')
        else:
            parts.append(item[0])
        if isinstance(item, str) or item[0] not in ('and', 'or'):
            length += len(parts[-1])
    text = ''.join(parts)
    return text if len(text) <= budget else text[:budget] + '...'
