"""The comparison of two layers' facts, the reference first and the layer checked second: every difference with its
category. LLIL against MLIL (compare_facts; the LLIL is the trust root) matches effects and branches by address and
guards by the branches they depend on; MLIL against HLIL is gated_comparison.py's; the effect order, the loop values
and the parts of an effect's values both modes compare are here"""

import reprlib
from typing import Hashable, NamedTuple

from .choice_lifting import lift_choices
from .facts import Effect, Facts
from .formulas import FALSE_KEY, TRUE, disjunction
from .neutral_names import Fingerprints, Reading
from .post_dominators import FALSE_ARM, TRUE_ARM
from .trees import loop_leaves, truth

SHOWN = reprlib.Repr(maxlevel=8, maxtuple=6, maxstring=40, maxother=40)  # a detail's trees, cut (brief)


class Difference(NamedTuple):
    category: str                   # docs/VALIDATOR_GUIDE.md, "Categories"
    key: Hashable                   # where it is: an effect's key (gated: RETURN_KEY for the returns), (address,
                                    # 'branch'), (loop header, neutral key) or (address, 'unstructured')
    detail: object


# === LLIL against MLIL ===

def compare_facts(reference: Facts, checked: Facts) -> list[Difference]:
    differences = []
    reading = (Fingerprints.of(reference), Fingerprints.of(checked))
    negated = (negated_branches(reference), negated_branches(checked))
    compare_effects(reference, checked, reading, negated, differences)
    compare_branches(reference, checked, reading, negated, differences)
    compare_order(reference, checked, differences)
    compare_loop_values(reference, checked, reading, differences)
    return differences


def compare_effects(reference: Facts, checked: Facts, reading: Reading, negated: tuple[set, set], differences: list):
    for key in sorted(reference.effects.keys() | checked.effects.keys(), key=repr):
        expected, found = reference.effects.get(key, []), checked.effects.get(key, [])
        if len(expected) != len(found):
            category = 'missing_effect' if len(expected) > len(found) else 'added_effect'
            differences.append(Difference(category, key, (len(expected), len(found))))
        for a, b in zip(expected, found):
            if a.target != b.target:
                differences.append(Difference('target_differs', key, (a.target, b.target)))
            if len(a.args) != len(b.args):
                differences.append(Difference('argc_differs', key, (len(a.args), len(b.args))))
            differences.extend(Difference(value_category(a), key, detail)
                               for detail in value_differences(reading, a, b))
            guard_a = {(address, canonical_polarity(negated[0], address, polarity)) for address, polarity in a.guard}
            guard_b = {(address, canonical_polarity(negated[1], address, polarity)) for address, polarity in b.guard}
            if guard_a != guard_b:
                differences.append(Difference('guard_differs', key, (sorted(guard_a), sorted(guard_b))))


def compare_branches(reference: Facts, checked: Facts, reading: Reading, negated: tuple[set, set], differences: list):
    for address in sorted(reference.branches.keys() | checked.branches.keys()):
        a, b = reference.branches.get(address), checked.branches.get(address)
        key = (address, 'branch')
        if a is None or b is None:
            differences.append(Difference('condition_differs', key, 'a branch on one side only'))
            continue

        cores = (truth(a.condition)[0], truth(b.condition)[0])
        if reading[0](cores[0]) != reading[1](cores[1]):
            representative = (truth(a.condition, representative=True)[0], truth(b.condition, representative=True)[0])
            if reading[0](representative[0]) == reading[1](representative[1]):
                differences.append(Difference('condition_ordering_inverted', key, cores))
            else:
                differences.append(Difference('condition_differs', key, (a.condition, b.condition)))

        # Where control goes when the condition's representative core holds: a negation dropped by swapping the
        # targets is none, an inverted ordering counted once (as the condition's difference)
        targets_a = canonical_targets(a, address in negated[0])
        targets_b = canonical_targets(b, address in negated[1])
        if targets_a != targets_b:
            differences.append(Difference('branch_targets_differ', key, (targets_a, targets_b)))


def negated_branches(facts: Facts) -> set:
    """The addresses of the branches whose condition's representative core is negated (truth): an arm of one flips,
    and so do its targets"""
    return {address for address, branch in facts.branches.items() if truth(branch.condition, representative=True)[1]}


def canonical_targets(branch, negated: bool) -> tuple[int, int]:
    return (branch.false_target, branch.true_target) if negated else (branch.true_target, branch.false_target)


def canonical_polarity(negated: set, address: int, polarity: str) -> str:
    """An arm's polarity relative to its branch condition's representative core (an arm of a negated condition
    flips)"""
    if address not in negated:
        return polarity

    return FALSE_ARM if polarity == TRUE_ARM else TRUE_ARM


# === Both modes ===

def compare_order(reference: Facts, checked: Facts, differences: list):
    for key in sorted(reference.next_effects.keys() | checked.next_effects.keys(), key=repr):
        expected, found = reference.next_effects.get(key), checked.next_effects.get(key)
        if expected is not None and found is not None and expected != found:
            differences.append(Difference('order_differs', key, (sorted(expected, key=repr), sorted(found, key=repr))))


def value_category(effect: Effect) -> str:
    """The category of a difference in what effect passes"""
    return 'return_differs' if effect.kind == 'return' else 'arg_differs'


def effect_components(effects: list[Effect]) -> list:
    """What effects pass, each part on its own: the argument indexes (as the first has them), then every storage
    key"""
    storage = sorted({key for effect in effects for key in effect.storage}, key=repr)
    return [*range(len(effects[0].args)), *storage]


def component_value(effect: Effect, component):
    """What effect passes as component, an argument's index or a storage key (None where it passes none)"""
    return effect.args[component] if isinstance(component, int) else effect.storage.get(component)


def value_differences(reading: Reading, a: Effect, b: Effect) -> list:
    """(index or storage key, a's value, b's value) of each argument and storage the two effects differ in; the
    arguments only where they pass as many"""
    components = effect_components([a, b])
    if len(a.args) != len(b.args):
        components = [component for component in components if not isinstance(component, int)]
    details = []
    for component in components:
        x, y = component_value(a, component), component_value(b, component)
        if reading[0](x) != reading[1](y):
            details.append((component, x, y))
    return details


def compare_loop_values(reference: Facts, checked: Facts, reading: Reading, differences: list):
    """The values loops carry into their headers, along every incoming edge, for each loop leaf the compared trees read
    (effects' arguments and storage, branch conditions, then the carried values in turn). A side's leaves are its own
    storage; the two sides' leaves of one header and neutral name are paired. A loop with copies is compared by
    compare_loop_copies"""
    sides = (reference, checked)
    leaves_read = tuple(loop_leaves_read(facts) for facts in sides)     # grows with the carried values compared
    edges_in = tuple(edges_into_headers(facts) for facts in sides)
    compared = set()
    while groups := loop_groups(sides, leaves_read, compared):
        for group, keys in sorted(groups.items(), key=repr):
            compared.add(group)
            if not (keys[0] and keys[1]):
                continue            # read on one side only: the reading trees differ already

            edges = incoming_edges(edges_in, group[0], keys)
            copies = carried_copies(sides, group[0], keys, edges, leaves_read)
            if any(len(edge_copies) > 1 for side in copies for per_edge in side.values() for edge_copies in per_edge):
                compare_loop_copies(group, copies, reading, differences)
            else:
                compare_carried_values(group, edges, copies, reading, differences)


def loop_leaves_read(facts: Facts) -> set:
    """The loop leaves facts' effects (arguments and storage) and branch conditions read, in one walk; none without
    loop values: a loop leaf is made only for a widened key (evaluation.walk_forward), and each naming's loop_values
    records a value for every widened key"""
    if not facts.loop_values:
        return set()

    read = [part for effects in facts.effects.values() for effect in effects
            for part in (effect.args, *effect.storage.values())]
    read += [branch.condition for branch in facts.branches.values()]
    return set(loop_leaves(tuple(read)))


def edges_into_headers(facts: Facts) -> dict:
    """(header, own key) -> the edges into the header its values are carried along"""
    edges_in = {}
    for header, key, edge in facts.loop_values:
        edges_in.setdefault((header, key), set()).add(edge)
    return edges_in


def loop_groups(sides: tuple[Facts, Facts], leaves_read: tuple[set, set], compared: set) -> dict:
    """(header, neutral key) -> each side's own keys, of the loop leaves read and not compared yet"""
    groups = {}
    for side, facts in enumerate(sides):
        for _, header, key in leaves_read[side]:
            group = (header, facts.neutral(key))
            if group not in compared:
                groups.setdefault(group, (set(), set()))[side].add(key)
    return groups


def incoming_edges(edges_in: tuple[dict, dict], header, keys: tuple[set, set]) -> list:
    """The edges into header any of either side's keys is carried along"""
    return sorted(set().union(*(edges_in[side].get((header, key), ()) for side in (0, 1) for key in keys[side])))


def carried_copies(sides: tuple[Facts, Facts], header, keys: tuple[set, set], edges: list,
                   leaves_read: tuple[set, set]) -> tuple[dict, dict]:
    """Each side's own key -> along each edge, each copy of the loop's (formula, value); the loop leaves those values
    read join leaves_read"""
    copies = ({}, {})
    for side, facts in enumerate(sides):
        for key in keys[side]:
            per_edge = tuple(facts.loop_values.get((header, key, edge), [(TRUE, ('absent',))]) for edge in edges)
            copies[side][key] = per_edge
            for edge_copies in per_edge:
                for _, value in edge_copies:
                    leaves_read[side].update(loop_leaves(value))
    return copies


def compare_carried_values(group: tuple, edges: list, copies: tuple[dict, dict], reading: Reading, differences: list):
    """A loop with one copy on each side: each own key's values along the edges under neutral names, compared both
    ways, so a checked split carrying a wrong value is not hidden by another split carrying the right one"""
    carried = [{key: tuple(edge_copies[0][1] for edge_copies in per_edge) for key, per_edge in copies[side].items()}
               for side in (0, 1)]
    by_digest = [{tuple(map(reading[side], values)): values for values in carried[side].values()} for side in (0, 1)]
    expected, found = by_digest[0].keys(), by_digest[1].keys()
    if expected != found:
        a = by_digest[0][min(expected - found or expected)]
        b = by_digest[1][min(found - expected or found)]
        detail = [(edge, brief(x), brief(y)) for edge, x, y in zip(edges, a, b) if reading[0](x) != reading[1](y)]
        differences.append(Difference('loop_value_differs', group, detail))


def compare_loop_copies(group: tuple, copies: tuple[dict, dict], reading: Reading, differences: list):
    """A loop HLIL rebuilds on several paths, its copies under one stamp: each own key's values along each incoming
    edge, lifted into the formulas the copies carry them under (lift_choices), so copies on exclusive paths compare with
    the reference's one loop; both ways, as compare_carried_values compares. A value carried under a formula that never
    holds (a copy's back edge it never takes) is left out. Where they differ, the choices inside the values are lifted
    too (lift_choices, inner), which only clears the difference: the layers build such a choice each its own way"""
    found = copy_descriptions(copies, reading, inner=False)
    if found is None:
        differences.append(Difference('guard_unchecked', group, 'loop copies'))
        return

    descriptions, capped = found
    if descriptions[0] == descriptions[1]:
        return
    lifted = copy_descriptions(copies, reading, inner=True)
    if lifted is not None and lifted[0][0] == lifted[0][1]:
        return
    counts = [max(len(edge_copies) for per_edge in copies[side].values() for edge_copies in per_edge)
              for side in (0, 1)]
    category = 'guard_unchecked' if capped else 'loop_value_differs'
    differences.append(Difference(category, group, [('copies', *counts)]))


def copy_descriptions(copies: tuple[dict, dict], reading: Reading, inner: bool) -> tuple | None:
    """Each side's descriptions of its copies' values (per edge, each value's digest with the key of the formulas it is
    carried under) and whether a choice was left whole; None where a formula has no key"""
    descriptions, capped = (set(), set()), False
    for side in (0, 1):
        for per_edge in copies[side].values():
            described = []
            for edge_copies in per_edge:
                values, cut = lift_choices(reading[side], edge_copies, inner)
                capped = capped or cut
                carried = {digest: reading[side].formula_keys(disjunction(formulas))
                           for digest, formulas in values.items()}
                if None in carried.values():
                    return None
                described.append(frozenset((digest, key) for digest, key in carried.items() if key != FALSE_KEY))
            descriptions[side].add(tuple(described))
    return descriptions, capped


def brief(tree) -> str:
    """tree as text, cut in depth and width: a tree shares its parts (a gated choice's formulas hold earlier ones) and
    may print exponentially"""
    return SHOWN.repr(tree)
