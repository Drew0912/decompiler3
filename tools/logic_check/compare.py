"""The comparison of two layers' facts, the reference first (LLIL, the trust root) and the layer checked second: every
difference with its category"""

from typing import Callable, Hashable, NamedTuple

from .evaluation import Facts
from .trees import EQUALITIES, invert_negated_orderings, loop_leaves, negation_normal_form, op, truth

CATEGORIES = (
    'missing_effect',               # an effect of the reference absent, or fewer times
    'added_effect',                 # an effect the reference lacks, or more times
    'target_differs',
    'argc_differs',
    'arg_differs',                  # an argument, or a local an argument points to
    'return_differs',               # the result, or another register, at a return
    'guard_differs',                # the branches an effect runs under, or their polarity
    'condition_differs',            # a branch's condition, or a branch on one side only
    'condition_ordering_inverted',  # equal once negated orderings are inverted (`!(a < b)` against `a >= b`)
    'branch_targets_differ',
    'order_differs',                # the effects that can run next
    'loop_value_differs',           # a value a loop carries round a back edge
)


class Difference(NamedTuple):
    category: str
    key: Hashable                   # (address, effect kind), (address, 'branch') or (loop header, storage, address)
    detail: object


def renamed(tree, neutral_key: Callable[[tuple], tuple], memo: dict):
    """tree with every storage key a leaf names in the layer's own way (a loop value, an address-taken local after a
    call) renamed the way every layer names it"""
    if not isinstance(tree, tuple) or not tree:
        return tree

    found = memo.get(id(tree))
    if found is not None:
        return found[1]

    tag = tree[0]
    if tag == 'loop':
        result = ('loop', tree[1], neutral_key(tree[2]))
    elif tag == 'slot_after':
        result = ('slot_after', neutral_key(tree[1]), tree[2])
    elif tag == 'deep_phi':
        result = tree[:4]       # the fingerprint is under neutral names; the kept leaves are the layer's own
    elif tag == 'op':
        operands = tuple(renamed(operand, neutral_key, memo) for operand in tree[2])
        result = op(tree[1], operands) if tree[1] in EQUALITIES else ('op', tree[1], operands)
    elif tag == 'phi':
        result = ('phi', tree[1], tuple((address, renamed(value, neutral_key, memo)) for address, value in tree[2]))
    elif tag in ('deref', 'reg', 'global'):
        result = (tag, *(renamed(item, neutral_key, memo) for item in tree[1:]))
    else:
        result = tree
    memo[id(tree)] = (tree, result)     # the tree kept alive, so its id is not reused
    return result


class Namer:
    """A side's trees under neutral names, renamed once each"""

    def __init__(self, facts: Facts):
        self.neutral_key = facts.neutral_key or (lambda key: key)   # a deep phi is cut to its fingerprint either way
        self.memo = {}

    def __call__(self, tree):
        return renamed(tree, self.neutral_key, self.memo)


def compare_facts(reference: Facts, checked: Facts) -> list[Difference]:
    differences = []
    namers = (Namer(reference), Namer(checked))
    compare_effects(reference, checked, namers, differences)
    compare_branches(reference, checked, namers, differences)
    for key in sorted(reference.next_effects.keys() | checked.next_effects.keys(), key=repr):
        expected, found = reference.next_effects.get(key), checked.next_effects.get(key)
        if expected is not None and found is not None and expected != found:
            differences.append(Difference('order_differs', key, (sorted(expected, key=repr), sorted(found, key=repr))))
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
            if invert_negated_orderings(negation_normal_form(condition_a)) == \
                    invert_negated_orderings(negation_normal_form(condition_b)):
                differences.append(Difference('condition_ordering_inverted', key, (core_a, core_b)))
            else:
                differences.append(Difference('condition_differs', key, (condition_a, condition_b)))

        # Where control goes when the condition's core holds, an inverted ordering's polarity included
        targets_a = canonical_targets(a, condition_a)
        targets_b = canonical_targets(b, condition_b)
        if targets_a != targets_b:
            differences.append(Difference('branch_targets_differ', key, (targets_a, targets_b)))


def canonical_targets(branch, condition: tuple) -> tuple[int, int]:
    if truth(condition, invert_orderings=True)[1]:
        return branch.false_target, branch.true_target

    return branch.true_target, branch.false_target


def canonical_polarity(facts: Facts, namer: Namer, address: int, polarity: str) -> str:
    """An arm's polarity relative to its branch condition's core (an arm of a negated condition flips)"""
    branch = facts.branches.get(address)
    if branch is None or not truth(namer(branch.condition), invert_orderings=True)[1]:
        return polarity

    return 'f' if polarity == 't' else 't'


def compare_loop_values(reference: Facts, checked: Facts, namers: tuple[Namer, Namer], differences: list):
    """The values loops carry into their headers, along every incoming edge, for each loop leaf the compared trees read
    (effects' arguments and storage, branch conditions, then the carried values in turn). A side's leaves are its own
    storage; the two sides' leaves of one header and neutral name are paired"""
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
            carried = ({}, {})      # own key -> its values along the incoming edges, under neutral names
            for side, facts in enumerate(sides):
                for key in keys[side]:
                    values = [facts.loop_values.get((header, key, address), ('absent',)) for address in addresses]
                    carried[side][key] = tuple(namers[side](value) for value in values)
                    for value in values:
                        reading[side].update(loop_leaves(value))

            # Both ways: a checked split carrying a wrong value is not hidden by another split carrying the right one
            expected, found = set(carried[0].values()), set(carried[1].values())
            if expected != found:
                a = min(expected - found or expected, key=repr)
                b = min(found - expected or found, key=repr)
                detail = [(address, x, y) for address, x, y in zip(addresses, a, b) if x != y]
                differences.append(Difference('loop_value_differs', group, detail))
