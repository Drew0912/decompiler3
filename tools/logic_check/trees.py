"""Value trees - the nested tuples every layer's expressions evaluate to - and the normal form conditions compare in

A tree is ('const', type name, value), ('op', operation name, operands), or a leaf naming what was read:
('param', n); ('call', address), a call's result; ('reg', n, after), ('global', n, after), ('deref', pointer, after),
a read after a given write (`ENTRY` for none); ('slot_after', key, address), an address-taken local after a call;
('phi', join, ((terminal address, value), ...)), or gated ('gamma', ((path condition, value), ...)), past a depth
('deep_phi', join, key, fingerprint, kept leaves) (state.merge); ('loop', header, key), a value at a loop header;
('undef', key); ('absent', key), storage a predecessor of a join never wrote; ('address', key); ('frame',), a call
setup constant. Leaves name a layer's own storage only where the comparison renames them (compare.Namer), so equal
trees mean the same value on every layer"""

from typing import Iterator

ENTRY = 'entry'                 # no write since the function started
ORDERING_REPRESENTATIVES = {'GE': 'LT', 'GT': 'LE'}  # a >= b read as !(a < b), a > b as !(a <= b): inexact for NaN
EQUALITIES = ('EQ', 'NE')
SHORT_LOGIC = ('LOGICAL_AND', 'LOGICAL_OR')
TRUTH_TESTS = ('TEST_ZERO', 'LOGICAL_NOT')     # LLIL's EZ; MLIL's TestZero and LogicalNot
ZERO_TYPES = ('int', 'bool')


def const(value) -> tuple:
    """A float by its bits (float.hex keeps the sign of zero), whatever its class or spelling: a SourceFloat's spelling
    is the output's, the game sees the bits"""
    if isinstance(value, float):
        return ('const', 'float', value.hex())

    return ('const', type(value).__name__, value)


def op(name: str, operands) -> tuple:
    """An operation's tree; `!c`, `EZ c` and `c == 0` are one value (HLIL writes the first two as the third). == and
    != are commutative: the comparison orders their operands (state.Fingerprints, compare.Namer)"""
    operands = tuple(operands)
    if name in TRUTH_TESTS:
        name, operands = 'EQ', (operands[0], const(0))

    return ('op', name, operands)


def is_zero(tree: tuple) -> bool:
    return tree[0] == 'const' and tree[1] in ZERO_TYPES and tree[2] == 0


def tagged_leaves(tree, tag: str) -> Iterator[tuple]:
    """Every leaf of the given tag in tree, a subtree it shares walked once"""
    pending, seen = [tree], set()
    while pending:
        node = pending.pop()
        if not isinstance(node, tuple) or id(node) in seen:
            continue
        seen.add(id(node))
        if node and node[0] == tag:
            yield node
        else:
            pending.extend(node)


def loop_leaves(tree) -> Iterator[tuple]:
    return tagged_leaves(tree, 'loop')


# === Condition normal form ===

def strip_truth_tests(tree: tuple) -> tuple[tuple, bool]:
    """(core, negated): the truth-test spellings stripped - `c == 0` (also `EZ c` and `!c`, as op writes them)
    negates, `c != 0` does not"""
    negated = False
    while tree[0] == 'op' and tree[1] in EQUALITIES and any(is_zero(operand) for operand in tree[2]):
        operands = tree[2]
        others = [operand for operand in operands if not is_zero(operand)]
        negated ^= tree[1] == 'EQ'
        tree = others[0] if others else operands[0]     # `0 == 0` tests the constant 0 too

    return tree, negated


def negation_normal_form(tree: tuple, negated: bool = False) -> tuple:
    """Negations pushed through && and || (De Morgan), `a != b` as the negation of `a == b`; a negation reaching
    anything else stays as ('not', x). An ordering is never inverted: `!(a < b)` is not `a >= b` for NaN"""
    core, stripped = strip_truth_tests(tree)
    negated ^= stripped
    if core[0] == 'op' and core[1] in SHORT_LOGIC:
        name = core[1]
        if negated:
            name = 'LOGICAL_OR' if name == 'LOGICAL_AND' else 'LOGICAL_AND'
        return ('op', name, tuple(negation_normal_form(operand, negated) for operand in core[2]))

    if core[0] == 'op' and core[1] == 'NE':
        core = op('EQ', core[2])
        negated = not negated

    return ('not', core) if negated else core


def representative_orderings(tree: tuple, memo: dict | None = None) -> tuple:
    """Every ordering as the one of its inverse pair in ORDERING_REPRESENTATIVES' values, negated where it was the other
    (`a >= b` as `!(a < b)`, inexact for NaN): two conditions equal only after this differ by an ordering inversion.
    Memoised by identity: a tree shares its subtrees"""
    memo = {} if memo is None else memo
    found = memo.get(id(tree))
    if found is not None:
        return found

    if tree[0] == 'not':
        inner = representative_orderings(tree[1], memo)
        result = inner[1] if inner[0] == 'not' else ('not', inner)
    elif tree[0] == 'op':
        operands = tuple(representative_orderings(operand, memo) for operand in tree[2])
        if tree[1] in ORDERING_REPRESENTATIVES:
            result = ('not', ('op', ORDERING_REPRESENTATIVES[tree[1]], operands))
        else:
            result = ('op', tree[1], operands)
    else:
        result = tree
    memo[id(tree)] = result
    return result


CONSTANT_COMPARISONS = {
    'EQ' : lambda a, b: a == b,
    'NE' : lambda a, b: a != b,
    'LT' : lambda a, b: a < b,
    'LE' : lambda a, b: a <= b,
    'GT' : lambda a, b: a > b,
    'GE' : lambda a, b: a >= b,
}


def constant_truth(tree: tuple) -> bool | None:
    """The value a condition always has - an int constant, a comparison of two, or !, && and || over such conditions
    (ir/hlil's constant_truth on trees) - else None"""
    if tree[0] == 'const':
        return bool(tree[2]) if tree[1] in ZERO_TYPES else None
    if tree[0] != 'op':
        return None

    name, operands = tree[1], tree[2]
    if name in CONSTANT_COMPARISONS:
        if all(operand[0] == 'const' and operand[1] in ZERO_TYPES for operand in operands):
            return CONSTANT_COMPARISONS[name](operands[0][2], operands[1][2])
        if name == 'EQ' and is_zero(operands[1]):  # `!c`, as op writes it
            inner = constant_truth(operands[0])
            return None if inner is None else not inner
        return None
    if name in SHORT_LOGIC:
        decisive = name == 'LOGICAL_OR'     # true decides ||, false decides &&
        sides = [constant_truth(operand) for operand in operands]
        if decisive in sides:
            return decisive
        return (not decisive) if all(side == (not decisive) for side in sides) else None

    return None


def truth(tree: tuple, *, representative: bool = False) -> tuple[tuple, bool]:
    """(core, negated) of a branch condition in normal form, its top-level negation the polarity; with representative,
    its orderings as representative_orderings gives them, so an inversion counts once (as the condition's difference),
    not again as a polarity or target difference, and a negation dropped by swapping the targets is no difference"""
    normal = negation_normal_form(tree)
    if representative:
        normal = representative_orderings(normal)
    if normal[0] == 'not':
        return normal[1], True

    return normal, False
