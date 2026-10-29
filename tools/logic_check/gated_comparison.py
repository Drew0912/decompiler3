"""MLIL against HLIL (compare_gated), whose structure HLIL rebuilds: effects matched by address and the formulas they
run under compared, the values they pass each under its formula; the effect order and the loop values as compare.py
compares them for both modes. Each is compared as written and, where it differs, with orderings read as one
representative, which decides (decided, reconciled)"""

from typing import Callable, NamedTuple

from .compare import (
    Difference, brief, choice_alternatives, compare_loop_values, compare_order, component_value, effect_components,
    inner_choice, lift_choices, value_category, value_differences,
)
from .decision_diagrams import DiagramOverflow, Diagrams
from .facts import Effect, Facts
from .formulas import TRUE, conjunction, disjunction, literal, negation
from .neutral_names import Fingerprints, Reading
from .trees import SHORT_LOGIC, negation_normal_form

RENDERED_FORMULA_CHARACTERS = 400   # a gated detail's formula, cut (render)


class GatedReading(NamedTuple):
    """The two sides' trees under one reading (Fingerprints: as written, or with representative orderings) and
    compare_formulas' answers under it, by the formulas' digests"""
    sides: Reading
    compared: dict


def compare_gated(reference: Facts, checked: Facts) -> list[Difference]:
    """MLIL against HLIL, both analyzed gated: the effects, the effects that can run next, the loop values, every
    reachable unstructured jump"""
    differences = []
    readings = tuple(GatedReading(tuple(Fingerprints.of(facts, representative) for facts in (reference, checked)), {})
                     for representative in (False, True))       # as written, then with representative orderings
    compare_gated_effects(reference, checked, readings, differences)
    compare_order(reference, checked, differences)
    compare_gated_loop_values(reference, checked, readings, differences)
    compare_unstructured(checked, differences)
    return differences


def compare_gated_effects(reference: Facts, checked: Facts, readings: tuple[GatedReading, GatedReading],
                          differences: list):
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
        category = decided(compare_under, readings, formulas, premises)
        if category is not None:
            differences.append(Difference(category, key, tuple(render(formula) for formula in formulas)))
        compare_passed(readings, key, (expected, found), differences, premises)


def compare_gated_loop_values(reference: Facts, checked: Facts, readings: tuple[GatedReading, GatedReading],
                              differences: list):
    """The loop values (compare_loop_values) as written; where a group differs, its outcome under representative
    orderings decides (reconciled). A run gives at most one difference per group, keyed by it, and the groups do not
    depend on the reading, so the two runs pair by key; a group only the representative run finds differing is clean
    as written"""
    exact = []
    compare_loop_values(reference, checked, readings[0].sides, exact)
    if exact:
        representative = []
        compare_loop_values(reference, checked, readings[1].sides, representative)
        found = {difference.key: difference.category for difference in representative}
        differences.extend(Difference(reconciled(found.get(difference.key)), difference.key, difference.detail)
                           for difference in exact)


def decided(compare: Callable, readings: tuple[GatedReading, GatedReading], *arguments) -> str | None:
    """A slot's outcome, compare(reading, *arguments) comparing it under one reading (an effect's guard:
    compare_under; one value component: compare_component): clean as written is clean, else reconciled with its
    outcome under representative orderings"""
    if compare(readings[0], *arguments) is None:
        return None

    return reconciled(compare(readings[1], *arguments))


def reconciled(representative: str | None) -> str:
    """The outcome of a slot that differs as written (a difference, or guard_unchecked), from its outcome under
    representative orderings: clean there is condition_ordering_inverted, else that outcome. A representative
    difference is a real one: the reading only merges ordering atoms (FormulaKeys.condition_structure), so formulas
    equal as written are equal under it"""
    return 'condition_ordering_inverted' if representative is None else representative


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


def compare_under(reading: GatedReading, formulas: tuple, premises: tuple) -> str | None:
    """compare_formulas; where it finds a difference, again with each side's formula under its premise, whose answer
    is the answer; where that still differs, again with the choices in the formulas' conditions lifted
    (lifted_formula), whose answer is taken only if clean: the layers build such a choice each its own way. An
    unchecked answer stays unchecked"""
    category = compare_formulas(reading, formulas)
    if category in (None, 'guard_unchecked'):
        return category
    if premises != (TRUE, TRUE):
        formulas = tuple(conjunction(formula, premise) for formula, premise in zip(formulas, premises))
        category = compare_formulas(reading, formulas)
        if category in (None, 'guard_unchecked'):
            return category

    lifted = tuple(lifted_formula(fingerprints, formula, {}) for fingerprints, formula in zip(reading.sides, formulas))
    if all(new is old for new, old in zip(lifted, formulas)):
        return category
    return None if compare_formulas(reading, lifted) is None else category


def lifted_formula(fingerprints: Fingerprints, formula, memo: dict) -> tuple:
    """formula with each literal whose condition holds a gated choice lifted: the condition split at its && and ||
    (short_logic_formula), each part's choices lifted (lifted_atom); a formula with none is the same object"""
    found = memo.get(id(formula))
    if found is not None:
        return found[1]

    tag = formula[0]
    if tag == 'lit' and inner_choice(fingerprints, formula[1], set()) is not None:
        split = short_logic_formula(negation_normal_form(formula[1]))     # the condition holding
        holds = (lifted_atom(fingerprints, split, memo) if split[0] == 'lit'
                 else lifted_formula(fingerprints, split, memo))
        result = holds if formula[2] else negation(holds)
    elif tag in ('and', 'or'):
        items = [lifted_formula(fingerprints, item, memo) for item in formula[1]]
        if all(new is old for new, old in zip(items, formula[1])):
            result = formula
        else:
            result = conjunction(*items) if tag == 'and' else disjunction(items)
    else:
        result = formula
    memo[id(formula)] = (formula, result)       # the formula kept alive, so its id is not reused
    return result


def lifted_atom(fingerprints: Fingerprints, atom: tuple, memo: dict) -> tuple:
    """atom, a literal on a condition with no && or ||, as its choices' values each under its formula
    (choice_alternatives, inner): c(G) holds where the value G takes makes c hold. A value's formula may test an earlier
    choice (a flag tested to set a flag), so it is lifted in turn; atom as it is past LIFTED_CHOICES"""
    alternatives, capped = choice_alternatives(fingerprints, TRUE, atom[1], inner=True)
    if capped:
        return atom

    return disjunction([conjunction(lifted_formula(fingerprints, condition, memo), literal(core, atom[2]))
                        for condition, core in alternatives])


def short_logic_formula(normal: tuple) -> tuple:
    """A condition in negation normal form as a formula over its parts at && and ||, as FormulaKeys.split_short_logic
    reads it"""
    if normal[0] == 'not':
        return negation(short_logic_formula(normal[1]))
    if normal[0] == 'op' and normal[1] in SHORT_LOGIC:
        items = [short_logic_formula(item) for item in normal[2]]
        return conjunction(*items) if normal[1] == 'LOGICAL_AND' else disjunction(items)

    return literal(normal, True)


def compare_formulas(reading: GatedReading, formulas: tuple) -> str | None:
    """None when the two sides' formulas are one function under reading, else guard_differs, or guard_unchecked past
    the caps; remembered by their digests under reading, in its own memo, so of two pairs of one digest each the first
    compared decides an overflow"""
    digests = (reading.sides[0](formulas[0]), reading.sides[1](formulas[1]))
    if digests[0] == digests[1]:
        return None
    if digests not in reading.compared:
        reading.compared[digests] = formulas_difference(reading.sides, formulas)
    return reading.compared[digests]


def formulas_difference(sides: Reading, formulas: tuple) -> str | None:
    """compare_formulas past the digests"""
    try:
        return None if equivalent(sides, formulas) else 'guard_differs'
    except DiagramOverflow:
        return 'guard_unchecked'


def equivalent(sides: Reading, formulas: tuple) -> bool:
    """Whether the formulas are one function: by their truth tables, or, past ROW_CAP rows, by one decision diagram in
    the order the formulas meet their variables"""
    keys = (sides[0].formula_keys, sides[1].formula_keys)
    found = (keys[0].table_key(formulas[0]), keys[1].table_key(formulas[1]))
    if None not in found:
        return found[0] == found[1]

    return Diagrams().same(keys[0].structure(formulas[0]), keys[1].structure(formulas[1]))


def compare_passed(readings: tuple[GatedReading, GatedReading], key: tuple, occurrences: tuple, differences: list,
                   premises: tuple):
    """The values an effect's occurrences pass, each argument and storage key on its own (decided): equal under
    neutral names, or, a gated choice lifted into the formula its value is passed under (HLIL may pass from one return
    what MLIL passes from two, merged at the join before it), the same values each under one formula
    (compare_component, which lifts the choices inside a value too). The components' outcomes give one difference, the
    strongest: a difference, then unchecked, then condition_ordering_inverted"""
    expected, found = occurrences
    category = value_category(expected[0])
    single = len(expected) == len(found) == 1
    exact = readings[0].sides
    if single and not value_differences(exact, expected[0], found[0]):
        return

    outcomes = {component: decided(compare_component, readings, occurrences, component, premises)
                for component in effect_components([*expected, *found])}
    differing = [component for component, outcome in outcomes.items() if outcome == category]
    unchecked = [component for component, outcome in outcomes.items() if outcome == 'guard_unchecked']
    if differing:
        details = ([(component, brief(x), brief(y))
                    for component, x, y in value_differences(exact, expected[0], found[0])] if single
                   else [('occurrences', len(expected), len(found), differing)])
        differences.append(Difference(category, key, details))
    elif unchecked:
        differences.append(Difference('guard_unchecked', key, unchecked))
    elif 'condition_ordering_inverted' in outcomes.values():
        differences.append(Difference('condition_ordering_inverted', key, [component for component, outcome
                                                                           in outcomes.items() if outcome]))


def compare_component(reading: GatedReading, occurrences: tuple, component, premises: tuple) -> str | None:
    """compare_lifted with a value's choice lifted only where it is the whole value, and where that finds a difference,
    with the choices inside it too, merges cut at the phi depth opened (the layers build such a choice each its own way,
    and cut at different depths): that answer is taken only if it clears the difference, so a choice left whole past
    LIFTED_CHOICES leaves the first answer"""
    whole = compare_lifted(reading, occurrences, component, premises, inner=False)
    if whole is None:
        return None

    inner = compare_lifted(reading, occurrences, component, premises, inner=True)
    return None if inner is None else whole


def compare_lifted(reading: GatedReading, occurrences: tuple, component, premises: tuple, inner: bool) -> str | None:
    """None when both sides pass the same values for component (an argument's index or a storage key) under the same
    formulas, under reading; else the value category where some value's formulas differ, else guard_unchecked"""
    category = value_category(occurrences[0][0])
    lifts = [passed_under(fingerprints, effects, component, inner)
             for fingerprints, effects in zip(reading.sides, occurrences)]
    passed = [found for found, _ in lifts]
    capped = any(cut for _, cut in lifts)       # a choice left whole past LIFTED_CHOICES: a mismatch is unchecked
    if passed[0].keys() != passed[1].keys():
        return 'guard_unchecked' if capped else category
    if len(passed[0]) == 1:
        return None                 # one value, passed wherever the effect runs: its formula compared already

    outcomes = {compare_under(reading, (disjunction(passed[0][value]), disjunction(passed[1][value])), premises)
                for value in passed[0]} - {None}
    if not outcomes:
        return None
    return category if 'guard_differs' in outcomes and not capped else 'guard_unchecked'


def passed_under(fingerprints: Fingerprints, effects: list[Effect], component, inner: bool) -> tuple[dict, bool]:
    """What the occurrences pass as component, each value's digest under neutral names -> the formulas it is passed
    under, and whether a choice was left whole (lift_choices)"""
    return lift_choices(fingerprints,
                        [(effect.guard_formula, component_value(effect, component)) for effect in effects], inner)


def render(formula) -> str:
    """formula as text, cut at RENDERED_FORMULA_CHARACTERS, its conditions brief"""
    parts, pending, length = [], [formula], 0
    while pending and length <= RENDERED_FORMULA_CHARACTERS:
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
