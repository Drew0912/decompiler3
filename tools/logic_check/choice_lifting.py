"""Gated choices lifted out of what holds them, so a value is compared under the formula it holds under: in a value
(lift_choices, choice_alternatives) and in a formula's conditions (lifted_formula); past LIFTED_CHOICES alternatives a
choice is left whole, and a mismatch it leaves is unchecked"""

from .formulas import TRUE, conjunction, disjunction, literal, negation, short_logic_formula
from .neutral_names import Fingerprints
from .trees import negation_normal_form

LIFTED_CHOICES = 1024           # gated choices lifted into an occurrence's formulas, at most (lift_choices)


def lift_choices(fingerprints: Fingerprints, formula_values: list[tuple], inner: bool = False) -> tuple[dict, bool]:
    """(formula, value) pairs as each value's digest under neutral names -> the formulas it holds under, a gated choice
    lifted into them (choice_alternatives); and whether a choice was left whole past LIFTED_CHOICES, so that a mismatch
    is unchecked, not a difference. inner: the choices inside a value too"""
    formulas_by_digest, capped = {}, False
    for formula, value in formula_values:
        alternatives, cut = choice_alternatives(fingerprints, formula, value, inner)
        capped = capped or cut
        for condition, value in alternatives:
            formulas_by_digest.setdefault(fingerprints(value), []).append(condition)
    return formulas_by_digest, capped


def choice_alternatives(fingerprints: Fingerprints, formula, tree, inner: bool) -> tuple[list, bool]:
    """(formula, tree) as (formula, tree with no choice) alternatives: a choice's values, each under its formulas joined
    (distinct_values), in the choice's place, under formula and the value's formula; and whether a choice was left whole
    past LIFTED_CHOICES alternatives. inner: a choice anywhere in the tree (an operand, a leaf's write epoch), not only
    the tree that is one"""
    alternatives, pending, capped = [], [((formula,), tree)], False
    while pending:
        conditions, tree = pending.pop()
        gamma = inner_choice(tree, set()) if inner else whole_choice(tree)
        if gamma is not None:
            values = distinct_values(fingerprints, gamma)
            if len(alternatives) + len(pending) + len(values) <= LIFTED_CHOICES:
                pending.extend(((*conditions, value_formula), substitute(tree, gamma, value, {}))
                               for value_formula, value in values)
                continue
            capped = True
        alternatives.append((conjunction(*conditions), tree))
    return alternatives, capped


def whole_choice(tree) -> tuple | None:
    """tree where it is a gated choice"""
    return tree if isinstance(tree, tuple) and tree and tree[0] == 'gamma' else None


def inner_choice(tree, seen: set) -> tuple | None:
    """The first gated choice in tree"""
    if not isinstance(tree, tuple) or not tree or id(tree) in seen:
        return None
    seen.add(id(tree))
    if tree[0] == 'gamma':
        return tree

    for item in tree:
        found = inner_choice(item, seen)
        if found is not None:
            return found
    return None


def distinct_values(fingerprints: Fingerprints, gamma: tuple) -> list[tuple]:
    """A choice's (formula, value) pairs one per value, by digest (as gated_choice tells them apart), the formulas each
    arrives under joined: a choice has an alternative per incoming edge, often many for few values"""
    formulas, values = {}, {}
    for formula, value in gamma[1]:
        digest = fingerprints(value)
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


def lifted_formula(fingerprints: Fingerprints, formula, memo: dict) -> tuple:
    """formula with each literal whose condition holds a gated choice lifted: the condition split at its && and ||
    (short_logic_formula), each part's choices lifted (lifted_atom); a formula with none is the same object"""
    found = memo.get(id(formula))
    if found is not None:
        return found[1]

    tag = formula[0]
    if tag == 'lit' and inner_choice(formula[1], set()) is not None:
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
