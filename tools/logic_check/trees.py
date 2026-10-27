"""Value trees - the nested tuples every layer's expressions evaluate to - and the normal form conditions compare in

A tree is ('const', type name, value[, spelling]), ('op', operation name, operands), or a leaf naming what was read:
('param', n); ('call', address), a call's result; ('reg', n, after), ('global', n, after), ('deref', pointer, after),
a read after a given write (`ENTRY` for none); ('slot_after', key, address), an address-taken local after a call;
('phi', join, ((terminal address, value), ...)), past a depth ('deep_phi', join, key); ('loop', header, key), a value
at a loop header; ('undef', key); ('absent', key), storage a predecessor of a join never wrote; ('address', key);
('frame',), a call setup constant. Leaves never name a layer's own variables, so equal trees mean the
same value on every layer"""

from typing import Iterator

ENTRY = 'entry'                 # no write since the function started
ORDERING_INVERSES = {'LT': 'GE', 'LE': 'GT', 'GT': 'LE', 'GE': 'LT'}
EQUALITIES = ('EQ', 'NE')
SHORT_LOGIC = ('LOGICAL_AND', 'LOGICAL_OR')
TRUTH_TESTS = ('TEST_ZERO', 'LOGICAL_NOT')     # LLIL's EZ; MLIL's TestZero and LogicalNot
ZERO_TYPES = ('int', 'bool')


def const(value) -> tuple:
    if isinstance(value, float):
        return ('const', type(value).__name__, value.hex(), str(value))

    return ('const', type(value).__name__, value)


def op(name: str, operands) -> tuple:
    """An operation's tree; == and != are commutative, so their operands come in one order"""
    operands = tuple(operands)
    if name in EQUALITIES:
        operands = tuple(sorted(operands, key=repr))

    return ('op', name, operands)


def is_zero(tree: tuple) -> bool:
    return tree[0] == 'const' and tree[1] in ZERO_TYPES and tree[2] == 0


def tagged_leaves(tree, tag: str) -> Iterator[tuple]:
    """Every leaf of the given tag in tree"""
    pending = [tree]
    while pending:
        node = pending.pop()
        if not isinstance(node, tuple):
            continue
        if node and node[0] == tag:
            yield node
        else:
            pending.extend(node)


def loop_leaves(tree) -> Iterator[tuple]:
    return tagged_leaves(tree, 'loop')


# === Condition normal form ===

def strip_truth_tests(tree: tuple) -> tuple[tuple, bool]:
    """(core, negated): the truth-test spellings stripped - `c == 0`, `EZ c` and `!c` negate, `c != 0` does not"""
    negated = False
    while tree[0] == 'op':
        name, operands = tree[1], tree[2]
        if name in EQUALITIES and any(is_zero(operand) for operand in operands):
            others = [operand for operand in operands if not is_zero(operand)]
            tree = others[0] if others else operands[0]     # `0 == 0` tests the constant 0 too
            negated ^= name == 'EQ'
        elif name in TRUTH_TESTS:
            tree = operands[0]
            negated = not negated
        else:
            break

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


def invert_negated_orderings(tree: tuple) -> tuple:
    """Every negated ordering inverted (`!(a < b)` to `a >= b`, inexact for NaN): two conditions equal only after this
    differ by an ordering inversion"""
    if tree[0] == 'not' and tree[1][0] == 'op' and tree[1][1] in ORDERING_INVERSES:
        inner = tree[1]
        return ('op', ORDERING_INVERSES[inner[1]], tuple(invert_negated_orderings(operand) for operand in inner[2]))
    if tree[0] == 'not':
        return ('not', invert_negated_orderings(tree[1]))
    if tree[0] == 'op':
        return ('op', tree[1], tuple(invert_negated_orderings(operand) for operand in tree[2]))

    return tree


def truth(tree: tuple, *, invert_orderings: bool = False) -> tuple[tuple, bool]:
    """(core, negated) of a branch condition in normal form, its top-level negation the polarity; with
    invert_orderings, negated orderings inverted first, so an inversion counts once (as the condition's difference),
    not again as a polarity or target difference"""
    normal = negation_normal_form(tree)
    if invert_orderings:
        normal = invert_negated_orderings(normal)
    if normal[0] == 'not':
        return normal[1], True

    return normal, False
