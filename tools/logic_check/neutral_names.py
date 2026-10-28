"""Trees and formulas under neutral names: a layer's own storage named the way every layer names it, digested
(Fingerprints) or renamed (Namer), both by neutral_leaf; a gated choice told apart by its values and the function
choosing each (gated_choice)"""

import hashlib

from .facts import Facts
from .formulas import FALSE_KEY, FormulaKeys, disjunction
from .trees import EQUALITIES

FINGERPRINT_BYTES = 16


def neutral_leaf(tree: tuple, neutral_key) -> tuple | None:
    """A leaf naming a layer's own storage under neutral names - a loop value, an address-taken local after a call -
    or a deep phi's leaf as its fingerprint stands for it (its kept leaves are the layer's own); None for any other
    tree. Fingerprints and Namer both rename by it, so a digest and a renamed tree agree"""
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
    and the function choosing each (gated_choice); equal digests mean equal trees. Memoised by identity, so a subtree
    shared by many trees is digested once. The evaluation's instance (evaluation.analyze) also keeps the choice of each
    gated merge cut at the phi depth under its fingerprint (state.merged_value), for the facts"""

    def __init__(self, neutral_key):
        self.neutral_key = neutral_key
        self.memo = {}
        self.deep_choices = {}      # a cut gated merge's fingerprint -> its gamma
        self.formula_keys = FormulaKeys(self)

    def __call__(self, tree) -> bytes:
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
            parts = [tag, tree[1], *sorted(self(operand) for operand in tree[2])]
        elif tag in ('and', 'or'):
            parts = [tag, *sorted(self(item) for item in tree[1])]
        elif tag == 'gamma':
            choice = gated_choice(tree, self, self.formula_keys)
            parts = [tag, *sorted(((key, self(value)) for key, value in choice), key=repr)]
        else:
            parts = [self(item) for item in tree]
        if tag == 'gamma' and len(parts) == 2:
            digest = parts[1][1]        # one value wherever the join is reached
        else:
            digest = hashlib.blake2b(repr(parts).encode(), digest_size=FINGERPRINT_BYTES).digest()
        self.memo[id(tree)] = (tree, digest)    # the tree kept alive, so its id is not reused
        return digest


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
        key = keys(joined)
        if key is None:
            key = ('unchecked', digest(joined))
        if key != FALSE_KEY:
            choice.append((key, values[found]))
    return choice


class Namer:
    """A side's trees under neutral names, renamed once each: every storage key a leaf names in the layer's own way (a
    loop value, an address-taken local after a call) the way every layer names it, == and != operands in their
    fingerprints' order, a gated choice by its values and the function choosing each (gated_choice), with
    orderings read as representative ones where representative"""

    def __init__(self, facts: Facts, representative: bool = False):
        self.neutral_key = facts.neutral      # a deep phi is cut to its fingerprint either way
        self.deep_choices = facts.deep_choices      # where opened finds a cut gated merge's gamma
        self.fingerprints = Fingerprints(self.neutral_key)
        self.formula_keys = FormulaKeys(self.fingerprints, representative)
        self.memo = {}
        self.digests = {}

    def opened(self, tree):
        """A gated merge cut at the phi depth as the gamma it was cut from (state.merged_value keeps only those, not a
        phi's); any other tree as it is"""
        if not (isinstance(tree, tuple) and tree and tree[0] == 'deep_phi'):
            return tree

        _, _, _, fingerprint, _ = tree
        return self.deep_choices.get(fingerprint, tree)

    def renamed_digest(self, renamed) -> bytes:
        """A renamed tree's digest, memoised by identity (a tree shares its parts): equal digests mean equal trees"""
        if not isinstance(renamed, tuple):
            return repr(renamed).encode()
        found = self.digests.get(id(renamed))
        if found is not None:
            return found[1]

        parts = repr([self.renamed_digest(item) for item in renamed]).encode()
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
        leaf = neutral_leaf(tree, self.neutral_key)
        if leaf is not None:
            result = leaf
        elif tag == 'op':
            operands = sorted(tree[2], key=self.fingerprints) if tree[1] in EQUALITIES else tree[2]
            result = ('op', tree[1], tuple(self(operand) for operand in operands))
        elif tag == 'phi':
            result = ('phi', tree[1], tuple((address, self(value)) for address, value in tree[2]))
        elif tag == 'gamma':
            choice = gated_choice(tree, self.fingerprints, self.formula_keys)
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
