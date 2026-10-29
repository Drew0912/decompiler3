"""Boolean formulas over branch conditions - the condition an effect runs under, the choice a gated merge makes
(state.merge) - and their canonical keys, compared across layers

A formula is TRUE, FALSE, ('lit', condition, polarity), ('and', formulas) or ('or', formulas), over a layer's own
condition trees (a condition in its normal form's core, trees.truth). FormulaKeys gives a formula's key: its truth table
over the atoms it depends on, each atom named by its digest (neutral_names.Fingerprints), so equal keys mean equal
functions on every layer. An atom is a condition's core once the normal form is split at && / || and negation; the
equality tests of one value against constants are one atom of many values, the value's truth test among them, so tests
that exclude each other (an if chain and the switch made of it) are not read as independent; a test against a float
constant is an atom of its own (OVERLAPPING_CONSTANT_TYPES). Past ROW_CAP rows a key is a decision diagram's, and
decision_diagrams.Diagrams compares two formulas exactly"""

from .decision_diagrams import DiagramOverflow, Diagrams, collect_variables
from .trees import SHORT_LOGIC, const, constant_truth, negation_normal_form, representative_orderings, truth

TRUE = ('true',)
FALSE = ('false',)
OVERLAPPING_CONSTANT_TYPES = ('float',)  # two of its constants may compare equal (0.0, -0.0): float == unverified
ROW_CAP = 1 << 16
ZERO = const(0)
FALSE_KEY = ((), b'')           # FormulaKeys' key of a formula that never holds


def literal(condition: tuple, polarity: bool) -> tuple:
    """condition holding (polarity True) or not, its normal form's negation moved into the polarity"""
    core, negated = truth(condition)
    return ('lit', core, polarity != negated)


def conjunction(*formulas) -> tuple:
    items = []
    for formula in formulas:
        if formula == FALSE:
            return FALSE
        if formula != TRUE:
            items.append(formula)
    if not items:
        return TRUE

    return items[0] if len(items) == 1 else ('and', tuple(items))


def disjunction(formulas) -> tuple:
    items = []
    for formula in formulas:
        if formula == TRUE:
            return TRUE
        if formula != FALSE:
            items.append(formula)
    if not items:
        return FALSE

    return items[0] if len(items) == 1 else ('or', tuple(items))


def negation(formula, memo: dict | None = None) -> tuple:
    """formula's negation, moved to its literals (De Morgan's)"""
    memo = {} if memo is None else memo
    found = memo.get(id(formula))
    if found is not None:
        return found[1]

    if formula == TRUE:
        result = FALSE
    elif formula == FALSE:
        result = TRUE
    elif formula[0] == 'lit':
        result = ('lit', formula[1], not formula[2])
    else:
        negated = [negation(item, memo) for item in formula[1]]
        result = disjunction(negated) if formula[0] == 'and' else conjunction(*negated)
    memo[id(formula)] = (formula, result)       # the formula kept alive, so its id is not reused
    return result


class FormulaKeys:
    """One side's formulas' keys: (variables, table), the table a bit per row of the variables' values, the first
    variable the fastest, as little-endian bytes; a variable is ('eq', value digest, constant digests), whose values are
    its constants in order, then any other. Past ROW_CAP rows the variables the formula depends on are found first
    (Diagrams.relevant) and the key is their table's, or past ROW_CAP rows again their decision diagram's
    (Diagrams.key), None past DIAGRAM_KEY_NODE_CAP nodes. Keys are remembered by the formula's digest: equal digests are
    one function. representative reads orderings as trees.representative_orderings does"""

    def __init__(self, digest, representative: bool = False):
        self.digest = digest
        self.representative = representative
        self.atoms = {}             # id(core) -> (core, its structure over atoms)
        self.structures = {}        # id(formula) -> (formula, its structure over atoms)
        self.keys = {}              # a formula's digest -> its key

    def key(self, formula) -> tuple | None:
        digest = self.digest(formula)
        if digest not in self.keys:
            self.keys[digest] = self.computed_key(formula)
        return self.keys[digest]

    __call__ = key      # a digest's recursion calls key itself (Fingerprints: C stack)

    def computed_key(self, formula) -> tuple | None:
        structure, variables = self.structure_and_variables(formula)
        key = self.reduced_table_key(structure, variables)
        if key is not None:
            return key

        try:
            variables = Diagrams.relevant(structure, self.canonical_variables(formula))
        except DiagramOverflow:
            pass                    # the sorted order may still fit: Diagrams.key finds them in it
        else:
            key = self.reduced_table_key(structure, variables)
            if key is not None:
                return key
        try:
            variables, key = Diagrams.key(structure, variables)
        except DiagramOverflow:
            return None
        # A formula with few variables once those it does not depend on are left out has its table's key, whichever
        # way it was written
        return self.reduced_table_key(structure, variables) or key

    def table_key(self, formula) -> tuple | None:
        """formula's key by truth table, None past ROW_CAP rows"""
        return self.reduced_table_key(*self.structure_and_variables(formula))

    def structure_and_variables(self, formula) -> tuple:
        """(formula's structure over atoms, its variables: ('eq', value digest) -> {constant digest})"""
        structure = self.structure(formula)
        variables = {}
        collect_variables(structure, variables, set())
        return structure, variables

    def canonical_variables(self, formula) -> dict:
        """formula's variables in the order a walk meets them with each and / or's items in digest order: one order for
        all formulas of one digest, so their key's diagrams overflow alike, on every layer"""
        variables, seen = {}, set()

        def walk(part):
            if id(part) in seen:
                return
            seen.add(id(part))
            if part[0] in ('and', 'or'):
                for item in sorted(part[1], key=self.digest):
                    walk(item)
            else:
                collect_variables(self.structure(part), variables, set())

        walk(formula)
        return variables

    def reduced_table_key(self, structure, variables: dict) -> tuple | None:
        key = self.truth_table(structure, variables)
        if key is None:
            return None

        # Left out: a value the table does not depend on, a constant the table reads as any other value
        described, table = self.truth_table(structure, dict(self.relevant_variables(key, variables)))
        return described, table.to_bytes((table.bit_length() + 7) // 8, 'little')

    # === Atoms ===

    def structure(self, formula):
        """formula over atoms: ('not', s), ('and', ss), ('or', ss), TRUE, FALSE or ('eq', value digest, constant
        digest)"""
        found = self.structures.get(id(formula))
        if found is not None:
            return found[1]

        tag = formula[0]
        if tag == 'lit':
            result = self.condition_structure(formula[1])
            if not formula[2]:
                result = ('not', result)
        elif tag in ('and', 'or'):
            result = (tag, tuple(self.structure(item) for item in formula[1]))
        else:
            result = formula
        self.structures[id(formula)] = (formula, result)   # the formula kept alive, so its id is not reused
        return result

    def condition_structure(self, core: tuple):
        found = self.atoms.get(id(core))
        if found is not None:
            return found[1]

        normal = negation_normal_form(core)
        if self.representative:
            normal = representative_orderings(normal)
        result = self.split_short_logic(normal)
        self.atoms[id(core)] = (core, result)  # the core kept alive, so its id is not reused
        return result

    def split_short_logic(self, normal: tuple):
        """normal's structure over atoms at its && and || (gated_comparison.short_logic_formula splits a condition
        alike, into a formula)"""
        if normal[0] == 'not':
            return ('not', self.split_short_logic(normal[1]))
        if normal[0] == 'op' and normal[1] in SHORT_LOGIC:
            return ('and' if normal[1] == 'LOGICAL_AND' else 'or',
                    tuple(self.split_short_logic(item) for item in normal[2]))

        return self.atom(normal)

    def atom(self, core: tuple):
        decided = constant_truth(core)
        if decided is not None:
            return TRUE if decided else FALSE
        if core[0] == 'op' and core[1] == 'EQ':
            constants = [operand for operand in core[2] if operand[0] == 'const']
            if len(constants) == 1 and constants[0][1] not in OVERLAPPING_CONSTANT_TYPES:
                value = next(operand for operand in core[2] if operand[0] != 'const')
                return ('eq', self.digest(value), self.digest(constants[0]))

        # A value tested for truth: one of the values its equalities range over. A test against a float constant, or
        # of two constants constant_truth leaves open, is such a value of its own
        return ('not', ('eq', self.digest(core), self.digest(ZERO)))


    # === Truth tables ===

    @classmethod
    def layout(cls, variables: dict) -> tuple[list, int] | None:
        """(each variable with its sorted constants, stride and domain size; the row count), None past ROW_CAP"""
        layout, rows = [], 1
        for variable in sorted(variables):
            constants = tuple(sorted(variables[variable]))
            size = len(constants) + 1
            layout.append((variable, constants, rows, size))
            rows *= size
            if rows > ROW_CAP:
                return None

        return layout, rows

    @classmethod
    def column(cls, stride: int, size: int, value: int, rows: int) -> int:
        """The rows where a variable of this stride and domain size has value"""
        period = stride * size
        unit = ((1 << stride) - 1) << (value * stride)
        return unit * (((1 << rows) - 1) // ((1 << period) - 1))

    def truth_table(self, structure, variables: dict) -> tuple | None:
        """(variables, table) over variables; an equality with a constant they leave out reads as false (the value is
        any other)"""
        found = self.layout(variables)
        if found is None:
            return None

        layout, rows = found
        everything = (1 << rows) - 1
        columns = {}
        for variable, constants, stride, size in layout:
            for index, constant in enumerate(constants):
                columns[(*variable, constant)] = self.column(stride, size, index, rows)

        values = {}

        def evaluate(node) -> int:
            found = values.get(id(node))
            if found is not None:
                return found
            tag = node[0]
            if tag == 'true':
                result = everything
            elif tag == 'false':
                result = 0
            elif tag == 'eq':
                result = columns.get(node, 0)
            elif tag == 'not':
                result = everything ^ evaluate(node[1])
            elif tag == 'and':
                result = everything
                for item in node[1]:
                    result &= evaluate(item)
            else:
                result = 0
                for item in node[1]:
                    result |= evaluate(item)
            values[id(node)] = result
            return result

        return tuple((*variable, constants) for variable, constants, _, _ in layout), evaluate(structure)

    def relevant_variables(self, key: tuple, variables: dict):
        """(variable, constants) of each value key's table depends on, with the constants it tells from any other"""
        layout, rows = self.layout(variables)
        _, table = key
        for variable, constants, stride, size in layout:
            def cofactor(value: int) -> int:
                return (table & self.column(stride, size, value, rows)) >> (value * stride)

            other = cofactor(size - 1)
            kept = {constant for index, constant in enumerate(constants) if cofactor(index) != other}
            if kept:
                yield variable, kept
