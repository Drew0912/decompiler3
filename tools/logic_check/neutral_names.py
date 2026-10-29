"""Trees and formulas digested under neutral names (Fingerprints): a layer's own storage named the way every layer
names it (neutral_leaf); a gated choice told apart by its values and the function choosing each (gated_choice)"""

import hashlib

from .facts import Facts
from .formulas import FALSE_KEY, FormulaKeys, disjunction
from .trees import EQUALITIES

FINGERPRINT_BYTES = 16


def neutral_leaf(tree: tuple, neutral_key) -> tuple | None:
    """A leaf naming a layer's own storage under neutral names - a loop value, an address-taken local after a call -
    or a deep phi's leaf as its fingerprint stands for it (its kept leaves are the layer's own); None for any other
    tree"""
    tag = tree[0] if tree else None
    if tag == 'loop':
        return ('loop', tree[1], neutral_key(tree[2]))
    if tag == 'slot_after':
        return ('slot_after', neutral_key(tree[1]), tree[2])
    if tag == 'deep_phi':
        return tree[:4]

    return None


class Fingerprints:
    """A layer's value trees and formulas digested the way the comparison sees them: a layer's own storage keys under
    neutral names, == and != operands and those of a formula's and / or in any order, a gated choice by its values
    and the function choosing each (gated_choice), with orderings read as representative ones where representative;
    equal digests mean equal trees. Memoised by identity, so a subtree shared by many trees is digested once. It
    recurses through plain methods (digest, FormulaKeys.key) in list comprehensions: a call through __call__, or a
    generator a C function consumes, takes C stack at each level, which a deep tree runs out of first"""

    def __init__(self, neutral_key, representative: bool = False):
        self.neutral_key = neutral_key
        self.memo = {}
        self.formula_keys = FormulaKeys(self.digest, representative)

    @classmethod
    def of(cls, facts: Facts, representative: bool = False) -> Fingerprints:
        """A side's fingerprints for the comparison: its facts' neutral names"""
        return cls(facts.neutral, representative)

    def digest(self, tree) -> bytes:
        if not isinstance(tree, tuple):
            return repr(tree).encode()

        found = self.memo.get(id(tree))
        if found is not None:
            return found[1]

        tag = tree[0] if tree else None
        leaf = neutral_leaf(tree, self.neutral_key)
        if leaf is not None:
            parts = list(leaf)
        elif tag == 'op' and tree[1] in EQUALITIES:
            parts = [tag, tree[1], *sorted([self.digest(operand) for operand in tree[2]])]
        elif tag in ('and', 'or'):
            parts = [tag, *sorted([self.digest(item) for item in tree[1]])]
        elif tag == 'gamma':
            choice = gated_choice(tree, self.digest, self.formula_keys)
            parts = [tag, *sorted([(key, self.digest(value)) for key, value in choice], key=repr)]
        else:
            parts = [self.digest(item) for item in tree]
        if tag == 'gamma' and len(parts) == 2:
            digest = parts[1][1]        # one value wherever the join is reached
        else:
            digest = hashlib.blake2b(repr(parts).encode(), digest_size=FINGERPRINT_BYTES).digest()
        self.memo[id(tree)] = (tree, digest)    # the tree kept alive, so its id is not reused
        return digest

    __call__ = digest


Reading = tuple[Fingerprints, Fingerprints]     # the two sides (reference, checked) under one reading


def gated_choice(gamma: tuple, digest, keys: FormulaKeys) -> list[tuple]:
    """A gated merge's (key, value) pairs: its values told apart by digest, each with the key (FormulaKeys) of the
    formulas it arrives under joined, one that never arrives left out; one pair is that value wherever the join is
    reached. A formula past ROW_CAP rows is keyed by its own digest: equal only to one built the same way"""
    formulas, values = {}, {}
    for formula, value in gamma[1]:
        found = digest(value)
        formulas.setdefault(found, []).append(formula)
        values[found] = value
    choice = []
    for found, arriving in formulas.items():
        joined = disjunction(arriving)
        key = keys.key(joined)
        if key is None:
            key = ('unchecked', digest(joined))
        if key != FALSE_KEY:
            choice.append((key, values[found]))
    return choice
