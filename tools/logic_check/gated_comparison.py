"""MLIL against HLIL (compare_gated), whose structure HLIL rebuilds: effects matched by address and the formulas they
run under compared, the values they pass each under its formula; the effect order and the loop values as compare.py
compares them for both modes"""

from typing import NamedTuple

from .compare import (
    Difference, brief, compare_loop_values, compare_order, component_value, effect_components, lift_choices,
    value_category,
)
from .decision_diagrams import DiagramOverflow, Diagrams
from .facts import Effect, Facts
from .formulas import TRUE, conjunction, disjunction, negation
from .neutral_names import Namer

RENDERED_FORMULA_CHARACTERS = 400   # a gated detail's formula, cut (render)


class Namings(NamedTuple):
    """A gated comparison's namers, a pair (reference, checked) as written and one with representative orderings"""
    exact: tuple[Namer, Namer]
    representative: tuple[Namer, Namer]


def compare_gated(reference: Facts, checked: Facts) -> list[Difference]:
    """MLIL against HLIL, both analyzed gated: the effects, the effects that can run next, the loop values, every
    reachable unstructured jump"""
    differences = []
    namings = Namings((Namer(reference), Namer(checked)),
                      (Namer(reference, representative=True), Namer(checked, representative=True)))
    compare_gated_effects(reference, checked, namings, differences)
    compare_order(reference, checked, differences)
    compare_gated_loop_values(reference, checked, namings, differences)
    compare_unstructured(checked, differences)
    return differences


def compare_gated_effects(reference: Facts, checked: Facts, namings: Namings, differences: list):
    """Each effect key's occurrences together, since HLIL may repeat an effect (a cloned region) or make two one (a
    common return), and an occurrence count is no finding: the formulas they run under joined (compare_formulas), the
    values they pass, each with the formula it is passed under (compare_passed); a loop's running and going round
    again, as its pseudo-effects"""
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

        formulas = (disjunction(effect.guard_formula for effect in expected),
                    disjunction(effect.guard_formula for effect in found))
        premises = termination_premises(reference, checked, [*expected, *found])
        category = compare_under(namings, formulas, premises)
        if category is not None:
            differences.append(Difference(category, key, tuple(render(formula) for formula in formulas)))
        compare_passed(namings, key, (expected, found), differences, premises)


def compare_gated_loop_values(reference: Facts, checked: Facts, namings: Namings, differences: list):
    """The loop values (compare_loop_values) as written; a difference that goes once orderings are read as
    representative ones (trees.representative_orderings) is condition_ordering_inverted"""
    exact = []
    compare_loop_values(reference, checked, namings.exact, exact)
    if exact:
        representative = []
        compare_loop_values(reference, checked, namings.representative, representative)
        kept = {difference.key for difference in representative}
        differences.extend(difference if difference.key in kept else
                           Difference('condition_ordering_inverted', difference.key, difference.detail)
                           for difference in exact)


def compare_unstructured(checked: Facts, differences: list):
    """Every reachable jump HLIL could not express"""
    for jump in checked.unstructured:
        differences.append(Difference('unstructured_jump', (jump.address, 'unstructured'), jump.target))


def termination_premises(reference: Facts, checked: Facts, occurrences: list[Effect]) -> tuple:
    """Each side's premise that the loops before an effect end: a loop that runs ends through one of its exits, since an
    iteration that goes round is never the last, and the atoms of a formula stand for no iteration in particular. The
    loops are those some occurrence is after and none, on either side, is inside: an effect inside a loop runs in the
    iterations that go round"""
    after = set().union(*(effect.after for effect in occurrences))
    inside = set().union(*(effect.inside for effect in occurrences))
    names = sorted(after - inside, key=repr)
    return tuple(conjunction(*(disjunction([negation(run), ends]) for run, ends in
                               (facts.loop_runs[name] for name in names if name in facts.loop_runs)))
                 for facts in (reference, checked))


def compare_under(namings: Namings, formulas: tuple, premises: tuple) -> str | None:
    """compare_formulas, and where it finds a difference, again with each side's formula under its premise: that
    answer is the answer"""
    category = compare_formulas(namings, formulas)
    if category in (None, 'guard_unchecked') or premises == (TRUE, TRUE):
        return category

    under = tuple(conjunction(formula, premise) for formula, premise in zip(formulas, premises))
    return compare_formulas(namings, under)


def compare_formulas(namings: Namings, formulas: tuple) -> str | None:
    """None when the two sides' formulas are one function, else the category of their difference"""
    exact = namings.exact
    if exact[0].fingerprints(formulas[0]) == exact[1].fingerprints(formulas[1]):
        return None

    try:
        if equivalent(exact, formulas):
            return None
        if equivalent(namings.representative, formulas):
            return 'condition_ordering_inverted'
    except DiagramOverflow:
        return 'guard_unchecked'

    return 'guard_differs'


def equivalent(namers: tuple[Namer, Namer], formulas: tuple) -> bool:
    """Whether the formulas are one function: by their truth tables, or, past ROW_CAP rows, by one decision diagram in
    the order the formulas meet their variables"""
    keys = (namers[0].formula_keys, namers[1].formula_keys)
    found = (keys[0].table_key(formulas[0]), keys[1].table_key(formulas[1]))
    if None not in found:
        return found[0] == found[1]

    return Diagrams().same(keys[0].structure(formulas[0], {}), keys[1].structure(formulas[1], {}))


def compare_passed(namings: Namings, key: tuple, occurrences: tuple, differences: list, premises: tuple):
    """The values an effect's occurrences pass, each argument and storage key on its own: equal under neutral names,
    or, a gated choice lifted into the formula its value is passed under (HLIL may pass from one return what MLIL
    passes from two, merged at the join before it), the same values each under one formula (compare_component, which
    opens a merge cut at the phi depth)"""
    expected, found = occurrences
    category = value_category(expected[0])
    single = len(expected) == len(found) == 1
    if single and not value_differences(namings.exact, expected[0], found[0]):
        return

    outcomes = {component: compare_component(namings, occurrences, component, premises)
                for component in effect_components([*expected, *found])}
    differing = [component for component, outcome in outcomes.items() if outcome == category]
    unchecked = [component for component, outcome in outcomes.items() if outcome == 'guard_unchecked']
    if differing:
        details = (value_differences(namings.exact, expected[0], found[0]) if single
                   else [('occurrences', len(expected), len(found), differing)])
        differences.append(Difference(category, key, details))
    elif unchecked:
        differences.append(Difference('guard_unchecked', key, unchecked))
    elif 'condition_ordering_inverted' in outcomes.values():
        differences.append(Difference('condition_ordering_inverted', key, [component for component, outcome
                                                                           in outcomes.items() if outcome]))


def compare_component(namings: Namings, occurrences: tuple, component, premises: tuple) -> str | None:
    """compare_lifted with the merges cut at the phi depth kept whole, and where that finds a difference, opened (the
    layers cut at different depths): the opened answer is taken only if it clears the difference or finds an inverted
    ordering, so a choice opened past LIFTED_CHOICES leaves the first answer"""
    closed = compare_lifted(namings, occurrences, component, premises, open_cuts=False)
    if closed is None:
        return None

    opened = compare_lifted(namings, occurrences, component, premises, open_cuts=True)
    return opened if opened in (None, 'condition_ordering_inverted') else closed


def compare_lifted(namings: Namings, occurrences: tuple, component, premises: tuple, open_cuts: bool) -> str | None:
    """None when both sides pass the same values for component (an argument's index or a storage key) under the same
    formulas, else the category: an equal choice once orderings are representative is condition_ordering_inverted"""
    category = value_category(occurrences[0][0])
    capped = False                  # a choice left whole past LIFTED_CHOICES: a mismatch is unchecked
    for namers in namings:
        lifts = [passed_under(namer, effects, component, open_cuts) for namer, effects in zip(namers, occurrences)]
        passed = [found for found, _ in lifts]
        capped = capped or any(cut for _, cut in lifts)
        if passed[0].keys() != passed[1].keys():
            continue
        if len(passed[0]) == 1:
            outcomes = set()        # one value, passed wherever the effect runs: its formula compared already
        else:
            outcomes = {compare_under(namings, (disjunction(passed[0][value]), disjunction(passed[1][value])), premises)
                        for value in passed[0]} - {None}
        if not outcomes:
            return None if namers is namings.exact else 'condition_ordering_inverted'
        if outcomes == {'condition_ordering_inverted'}:
            return 'condition_ordering_inverted'
        return 'guard_unchecked' if capped or outcomes == {'guard_unchecked'} else category

    return 'guard_unchecked' if capped else category


def value_differences(namers: tuple[Namer, Namer], a: Effect, b: Effect) -> list:
    """(index or storage key, a's value, b's value) of each argument and storage the two occurrences differ in"""
    name_a, name_b = namers
    details = []
    for component in effect_components([a, b]):
        x, y = name_a(component_value(a, component)), name_b(component_value(b, component))
        if name_a.renamed_digest(x) != name_b.renamed_digest(y):
            details.append((component, brief(x), brief(y)))
    return details


def passed_under(namer: Namer, effects: list[Effect], component, open_cuts: bool) -> tuple[dict, bool]:
    """What the occurrences pass as component, each value's digest under neutral names -> the formulas it is passed
    under, and whether a choice was left whole (lift_choices)"""
    return lift_choices(namer, [(effect.guard_formula, component_value(effect, component)) for effect in effects],
                        open_cuts)


def render(formula) -> str:
    """formula as text, cut at RENDERED_FORMULA_CHARACTERS, its conditions brief"""
    parts, pending, length = [], [formula], 0
    while pending and length < RENDERED_FORMULA_CHARACTERS:
        item = pending.pop()
        if isinstance(item, tuple) and item[0] in ('and', 'or'):
            joiner = ' && ' if item[0] == 'and' else ' || '
            spaced = [part for child in item[1] for part in (joiner, child)][1:]
            pending.extend(reversed(['(', *spaced, ')']))
            continue

        if isinstance(item, str):
            part = item
        elif item[0] == 'lit':
            part = ('' if item[2] else '!') + brief(item[1])
        else:
            part = item[0]
        parts.append(part)
        length += len(part)
    text = ''.join(parts)
    return text if len(text) <= RENDERED_FORMULA_CHARACTERS else text[:RENDERED_FORMULA_CHARACTERS] + '...'
