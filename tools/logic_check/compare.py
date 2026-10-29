"""The comparison of two layers' facts, the reference first and the layer checked second: every difference with its
category. LLIL against MLIL (compare_facts; the LLIL is the trust root) matches effects and branches by address and
guards by the branches they depend on; MLIL against HLIL is gated_comparison.py's; the effect order, the loop values
and the parts of an effect's values both modes compare are here"""

import reprlib
from typing import Hashable, NamedTuple

from .facts import Effect, Facts
from .formulas import FALSE_KEY, TRUE, conjunction, disjunction
from .neutral_names import Namer
from .post_dominators import FALSE_ARM, TRUE_ARM
from .trees import loop_leaves, truth

LIFTED_CHOICES = 1024           # gated choices lifted into an occurrence's formulas, at most (lift_choices)
SHOWN = reprlib.Repr(maxlevel=8, maxtuple=6, maxstring=40, maxother=40)  # a gated detail's trees, cut (brief)


class Difference(NamedTuple):
    category: str                   # docs/VALIDATOR_GUIDE.md, "Categories"
    key: Hashable                   # (address, effect kind), (address, 'branch') or (loop header, storage, edges)
    detail: object


# === LLIL against MLIL ===

def compare_facts(reference: Facts, checked: Facts) -> list[Difference]:
    differences = []
    namers = (Namer(reference), Namer(checked))
    compare_effects(reference, checked, namers, differences)
    compare_branches(reference, checked, namers, differences)
    compare_order(reference, checked, differences)
    compare_loop_values(reference, checked, namers, differences)
    return differences


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
            category = value_category(a)
            components = effect_components([a, b])
            if len(a.args) != len(b.args):
                differences.append(Difference('argc_differs', key, (len(a.args), len(b.args))))
                components = [component for component in components if not isinstance(component, int)]
            for component in components:
                x, y = name_a(component_value(a, component)), name_b(component_value(b, component))
                # By digest: trees share subtrees, and compared as trees they may not
                if name_a.renamed_digest(x) != name_b.renamed_digest(y):
                    differences.append(Difference(category, key, (component, x, y)))
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
            representative_a, _ = truth(condition_a, representative=True)
            representative_b, _ = truth(condition_b, representative=True)
            if representative_a == representative_b:
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
    _, negated = truth(condition, representative=True)
    if negated:
        return branch.false_target, branch.true_target

    return branch.true_target, branch.false_target


def canonical_polarity(facts: Facts, namer: Namer, address: int, polarity: str) -> str:
    """An arm's polarity relative to its branch condition's representative core (an arm of a negated condition
    flips)"""
    branch = facts.branches.get(address)
    if branch is None or not truth(namer(branch.condition), representative=True)[1]:
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
    storage = sorted({key for effect in effects for key, _ in effect.storage}, key=repr)
    return [*range(len(effects[0].args)), *storage]


def component_value(effect: Effect, component):
    """What effect passes as component, an argument's index or a storage key (None where it passes none)"""
    return effect.args[component] if isinstance(component, int) else dict(effect.storage).get(component)


def compare_loop_values(reference: Facts, checked: Facts, namers: tuple[Namer, Namer], differences: list):
    """The values loops carry into their headers, along every incoming edge, for each loop leaf the compared trees read
    (effects' arguments and storage, branch conditions, then the carried values in turn). A side's leaves are its own
    storage; the two sides' leaves of one header and neutral name are paired. A loop with copies is compared by
    compare_loop_copies"""
    sides = (reference, checked)
    reading = tuple(loop_leaves_read(facts) for facts in sides)     # grows with the carried values compared
    edges_in = tuple(edges_into_headers(facts) for facts in sides)
    compared = set()
    while groups := loop_groups(sides, reading, compared):
        for group, keys in sorted(groups.items(), key=repr):
            compared.add(group)
            if not (keys[0] and keys[1]):
                continue            # read on one side only: the reading trees differ already

            edges = incoming_edges(edges_in, group[0], keys)
            copies = carried_copies(sides, group[0], keys, edges, reading)
            if any(len(edge_copies) > 1 for side in copies for per_edge in side.values() for edge_copies in per_edge):
                compare_loop_copies(group, copies, namers, differences)
            else:
                compare_carried_values(group, edges, copies, namers, differences)


def loop_leaves_read(facts: Facts) -> set:
    """The loop leaves facts' effects (arguments and storage) and branch conditions read"""
    reading = set()
    for effects in facts.effects.values():
        for effect in effects:
            reading.update(loop_leaves(effect.args))
            reading.update(loop_leaves(effect.storage))
    for branch in facts.branches.values():
        reading.update(loop_leaves(branch.condition))
    return reading


def edges_into_headers(facts: Facts) -> dict:
    """(header, own key) -> the edges into the header its values are carried along"""
    edges_in = {}
    for header, key, edge in facts.loop_values:
        edges_in.setdefault((header, key), set()).add(edge)
    return edges_in


def loop_groups(sides: tuple[Facts, Facts], reading: tuple[set, set], compared: set) -> dict:
    """(header, neutral key) -> each side's own keys, of the loop leaves read and not compared yet"""
    groups = {}
    for side, facts in enumerate(sides):
        for _, header, key in reading[side]:
            group = (header, facts.neutral(key))
            if group not in compared:
                groups.setdefault(group, (set(), set()))[side].add(key)
    return groups


def incoming_edges(edges_in: tuple[dict, dict], header, keys: tuple[set, set]) -> list:
    """The edges into header any of either side's keys is carried along"""
    return sorted(set().union(*(edges_in[side].get((header, key), ()) for side in (0, 1) for key in keys[side])))


def carried_copies(sides: tuple[Facts, Facts], header, keys: tuple[set, set], edges: list,
                   reading: tuple[set, set]) -> tuple[dict, dict]:
    """Each side's own key -> along each edge, each copy of the loop's (formula, value); the loop leaves those values
    read join reading"""
    copies = ({}, {})
    for side, facts in enumerate(sides):
        for key in keys[side]:
            per_edge = tuple(facts.loop_values.get((header, key, edge), [(TRUE, ('absent',))]) for edge in edges)
            copies[side][key] = per_edge
            for edge_copies in per_edge:
                for _, value in edge_copies:
                    reading[side].update(loop_leaves(value))
    return copies


def compare_carried_values(group: tuple, edges: list, copies: tuple[dict, dict], namers: tuple[Namer, Namer],
                           differences: list):
    """A loop with one copy on each side: each own key's values along the edges under neutral names, compared both
    ways, so a checked split carrying a wrong value is not hidden by another split carrying the right one"""
    carried = [{key: tuple(namers[side](edge_copies[0][1]) for edge_copies in per_edge)
                for key, per_edge in copies[side].items()} for side in (0, 1)]
    by_digest = [{tuple(map(namers[side].renamed_digest, values)): values for values in carried[side].values()}
                 for side in (0, 1)]
    expected, found = by_digest[0].keys(), by_digest[1].keys()
    if expected != found:
        a = by_digest[0][min(expected - found or expected)]
        b = by_digest[1][min(found - expected or found)]
        detail = [(edge, brief(x), brief(y)) for edge, x, y in zip(edges, a, b)
                  if namers[0].renamed_digest(x) != namers[1].renamed_digest(y)]
        differences.append(Difference('loop_value_differs', group, detail))


def compare_loop_copies(group: tuple, copies: tuple[dict, dict], namers: tuple[Namer, Namer], differences: list):
    """A loop HLIL rebuilds on several paths, its copies under one stamp: each own key's values along each incoming
    edge, lifted into the formulas the copies carry them under (lift_choices), so copies on exclusive paths compare with
    the reference's one loop; both ways, as compare_carried_values compares. A value carried under a formula that never
    holds (a copy's back edge it never takes) is left out. Where they differ, the choices inside the values are lifted
    too (lift_choices, inner), which only clears the difference: the layers build such a choice each its own way"""
    found = copy_descriptions(copies, namers, inner=False)
    if found is None:
        differences.append(Difference('guard_unchecked', group, 'loop copies'))
        return

    descriptions, capped = found
    if descriptions[0] == descriptions[1]:
        return
    lifted = copy_descriptions(copies, namers, inner=True)
    if lifted is not None and lifted[0][0] == lifted[0][1]:
        return
    counts = [max(len(edge_copies) for per_edge in copies[side].values() for edge_copies in per_edge)
              for side in (0, 1)]
    category = 'guard_unchecked' if capped else 'loop_value_differs'
    differences.append(Difference(category, group, [('copies', *counts)]))


def copy_descriptions(copies: tuple[dict, dict], namers: tuple[Namer, Namer], inner: bool) -> tuple | None:
    """Each side's descriptions of its copies' values (per edge, each value's digest with the key of the formulas it is
    carried under) and whether a choice was left whole; None where a formula has no key"""
    descriptions, capped = (set(), set()), False
    for side in (0, 1):
        for per_edge in copies[side].values():
            described = []
            for edge_copies in per_edge:
                values, cut = lift_choices(namers[side], edge_copies, inner)
                capped = capped or cut
                carried = {digest: namers[side].formula_keys(disjunction(formulas))
                           for digest, formulas in values.items()}
                if None in carried.values():
                    return None
                described.append(frozenset((digest, key) for digest, key in carried.items() if key != FALSE_KEY))
            descriptions[side].add(tuple(described))
    return descriptions, capped


def lift_choices(namer: Namer, formula_values: list[tuple], inner: bool = False) -> tuple[dict, bool]:
    """(formula, value) pairs as each value's digest under neutral names -> the formulas it holds under, a gated choice
    lifted into them (choice_alternatives); and whether a choice was left whole past LIFTED_CHOICES, so that a mismatch
    is unchecked, not a difference. inner: the choices inside a value too"""
    formulas_by_digest, capped = {}, False
    for formula, value in formula_values:
        alternatives, cut = choice_alternatives(namer, formula, value, inner)
        capped = capped or cut
        for condition, value in alternatives:
            formulas_by_digest.setdefault(namer.renamed_digest(namer(value)), []).append(condition)
    return formulas_by_digest, capped


def choice_alternatives(namer: Namer, formula, tree, inner: bool) -> tuple[list, bool]:
    """(formula, tree) as (formula, tree with no choice) alternatives: a choice's values, each under its formulas joined
    (distinct_values), in the choice's place, under formula and the value's formula; and whether a choice was left whole
    past LIFTED_CHOICES alternatives. inner: a choice anywhere in the tree (an operand, a leaf's write epoch) and a
    merge cut at the phi depth (Namer.opened), not only the tree that is one"""
    alternatives, pending, capped = [], [((formula,), tree)], False
    while pending:
        conditions, tree = pending.pop()
        found = inner_choice(namer, tree, set()) if inner else whole_choice(tree)
        if found is not None:
            target, gamma = found
            values = distinct_values(namer, gamma)
            if len(alternatives) + len(pending) + len(values) <= LIFTED_CHOICES:
                pending.extend(((*conditions, value_formula), substitute(tree, target, value, {}))
                               for value_formula, value in values)
                continue
            capped = True
        alternatives.append((conjunction(*conditions), tree))
    return alternatives, capped


def whole_choice(tree) -> tuple | None:
    """(tree, tree) where tree is a gated choice"""
    return (tree, tree) if isinstance(tree, tuple) and tree and tree[0] == 'gamma' else None


def inner_choice(namer: Namer, tree, seen: set) -> tuple | None:
    """(the subtree to replace, its gamma) of the first gated choice in tree, a merge cut at the phi depth opened"""
    if not isinstance(tree, tuple) or not tree or id(tree) in seen:
        return None
    seen.add(id(tree))
    if tree[0] == 'gamma':
        return tree, tree
    if tree[0] == 'deep_phi':
        opened = namer.opened(tree)
        return None if opened is tree else (tree, opened)

    for item in tree:
        found = inner_choice(namer, item, seen)
        if found is not None:
            return found
    return None


def distinct_values(namer: Namer, gamma: tuple) -> list[tuple]:
    """A choice's (formula, value) pairs one per value, by digest (as gated_choice tells them apart), the formulas each
    arrives under joined: a choice has an alternative per incoming edge, often many for few values"""
    formulas, values = {}, {}
    for formula, value in gamma[1]:
        digest = namer.fingerprints(value)
        formulas.setdefault(digest, []).append(formula)
        values.setdefault(digest, value)
    return [(disjunction(formulas[digest]), value) for digest, value in values.items()]


def substitute(tree, target, replacement, memo: dict):
    """tree with every occurrence of target (by identity) replaced, inside other choices' formulas too: one value on
    one path; a part with none kept as it is"""
    if tree is target:
        return replacement
    if not isinstance(tree, tuple):
        return tree
    found = memo.get(id(tree))
    if found is not None:
        return found[1]

    items = tuple(substitute(item, target, replacement, memo) for item in tree)
    result = tree if all(new is old for new, old in zip(items, tree)) else items
    memo[id(tree)] = (tree, result)     # the tree kept alive, so its id is not reused
    return result


def brief(tree) -> str:
    """tree as text, cut in depth and width: a tree shares its parts (a gated choice's formulas hold earlier ones) and
    may print exponentially"""
    return SHOWN.repr(tree)
