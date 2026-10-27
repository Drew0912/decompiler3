"""Boolean formulas over branch conditions - the condition an effect runs under, the choice a gated merge makes
(state.merge) - and their canonical keys, compared across layers

A formula is TRUE, FALSE, ('lit', condition, polarity), ('and', formulas) or ('or', formulas), over a layer's own
condition trees (a condition in its normal form's core, trees.truth). FormulaKeys gives a formula's key: its truth table
over the atoms it depends on, each atom named by its digest (state.Fingerprints), so equal keys mean equal functions on
every layer. An atom is a condition's core once the normal form is split at && / || and negation; the equality tests of
one value against constants are one atom of many values, the value's truth test among them, so tests that exclude each
other (an if chain and the switch made of it) are not read as independent; a test against a float constant is an atom of
its own (OVERLAPPING_CONSTANT_TYPES). Past ROW_CAP rows a formula has no key; Diagrams then compares two exactly"""

from .trees import SHORT_LOGIC, const, constant_truth, negation_normal_form, representative_orderings, truth

TRUE = ('true',)
FALSE = ('false',)
OVERLAPPING_CONSTANT_TYPES = ('float',)  # two of its constants may compare equal (0.0, -0.0): float == unverified
ROW_CAP = 1 << 16
ZERO = const(0)
FALSE_KEY = ((), b'')           # FormulaKeys' key of a formula that never holds
FALSE_NODE, TRUE_NODE = 0, 1    # Diagrams' terminals
DIAGRAM_NODE_CAP = 200_000      # a pairwise comparison's diagram (Diagrams.same)
DIAGRAM_KEY_NODE_CAP = 20_000   # a key's, in a sorted variable order (Diagrams.key)


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


class FormulaKeys:
    """One side's formulas' keys: (variables, table), the table a bit per row of the variables' values, the first
    variable the fastest, as little-endian bytes; a variable is ('eq', value digest, constant digests), whose values are
    its constants in order, then any other. Past ROW_CAP rows the key is a decision diagram's (Diagrams.key), None past
    DIAGRAM_KEY_NODE_CAP nodes. representative reads orderings as trees.representative_orderings does"""

    def __init__(self, digest, representative: bool = False):
        self.digest = digest
        self.representative = representative
        self.atoms = {}             # id(core) -> (core, its structure over atoms)

    def __call__(self, formula) -> tuple | None:
        structure, variables = self.structure_and_variables(formula)
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
        structure = self.structure(formula, {})
        variables = {}
        self.collect_variables(structure, variables, set())
        return structure, variables

    def reduced_table_key(self, structure, variables: dict) -> tuple | None:
        key = self.truth_table(structure, variables)
        if key is None:
            return None

        # Left out: a value the table does not depend on, a constant the table reads as any other value
        described, table = self.truth_table(structure, dict(self.relevant_variables(key, variables)))
        return described, table.to_bytes((table.bit_length() + 7) // 8, 'little')

    # === Atoms ===

    def structure(self, formula, memo: dict):
        """formula over atoms: ('not', s), ('and', ss), ('or', ss), TRUE, FALSE or ('eq', value digest, constant
        digest)"""
        found = memo.get(id(formula))
        if found is not None:
            return found

        tag = formula[0]
        if tag == 'lit':
            result = self.condition_structure(formula[1])
            if not formula[2]:
                result = ('not', result)
        elif tag in ('and', 'or'):
            result = (tag, tuple(self.structure(item, memo) for item in formula[1]))
        else:
            result = formula
        memo[id(formula)] = result
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

    @classmethod
    def collect_variables(cls, structure, variables: dict, seen: set):
        if id(structure) in seen:
            return
        seen.add(id(structure))
        tag = structure[0]
        if tag == 'eq':
            variables.setdefault(('eq', structure[1]), set()).add(structure[2])
        elif tag == 'not':
            cls.collect_variables(structure[1], variables, seen)
        elif tag in ('and', 'or'):
            for item in structure[1]:
                cls.collect_variables(item, variables, seen)

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


class DiagramOverflow(Exception):
    """A decision diagram past DIAGRAM_NODE_CAP nodes: the formulas stay unchecked"""


class Diagrams:
    """Reduced ordered binary decision diagrams (Bryant, 1986) for the exact comparison of formulas past ROW_CAP rows:
    the structures (FormulaKeys.structure) of both sides over one variable order, so equal functions are one node.
    An equality variable takes bits enough for its constants and any other value, each constant a code"""

    def __init__(self, cap: int | None = None):
        self.cap = DIAGRAM_NODE_CAP if cap is None else cap
        self.nodes = [None, None]   # FALSE_NODE, TRUE_NODE; then (level, low, high)
        self.unique = {}
        self.cache = {}
        self.codes = {}             # ('eq', value digest) -> (first level, bits, {constant digest: code})

    def assign_levels(self, variables: list[tuple]):
        """Each variable's levels, in the order given: (variable, its constants)"""
        level = 0
        for variable, constants in variables:
            bits = max(1, len(constants).bit_length())     # codes 0..len(constants), the last for any other
            self.codes[variable] = (level, bits, {constant: code for code, constant in enumerate(sorted(constants))})
            level += bits

    def same(self, a, b) -> bool:
        """Whether structures a and b are one function, its variables in the order the structures meet them"""
        variables = {}
        for structure in (a, b):
            FormulaKeys.collect_variables(structure, variables, set())
        self.assign_levels(list(variables.items()))
        memo = {}
        return self.build(a, memo) == self.build(b, memo)

    @classmethod
    def key(cls, structure, variables: dict) -> tuple:
        """(the variables structure depends on, its key on every layer): its diagram over them in sorted order, a
        constant an equality does not tell from any other value left out, its nodes numbered as a depth-first walk meets
        them"""
        while True:
            diagrams = cls(DIAGRAM_KEY_NODE_CAP)
            diagrams.assign_levels(sorted(variables.items()))
            root = diagrams.build(structure, {})
            relevant = diagrams.relevant_variables(root, variables)
            if relevant == variables:
                break
            variables = relevant

        described = tuple((*variable, tuple(sorted(constants))) for variable, constants in sorted(variables.items()))
        return variables, (described, ('diagram', *diagrams.numbered_nodes(root)))

    def relevant_variables(self, root: int, variables: dict) -> dict:
        """variable -> the constants root tells from any other value, of each variable root depends on"""
        relevant = {}
        for variable, constants in variables.items():
            other = self.restrict(root, variable, len(constants), {})
            kept = {constant for constant, code in self.codes[variable][2].items()
                    if self.restrict(root, variable, code, {}) != other}
            if kept:
                relevant[variable] = kept
        return relevant

    def numbered_nodes(self, root: int) -> tuple[tuple, int]:
        """(root's nodes as (level, low, high), numbered as a depth-first walk meets them; root's number)"""
        numbers, nodes, pending = {FALSE_NODE: FALSE_NODE, TRUE_NODE: TRUE_NODE}, [], [root]
        while pending:
            node = pending[-1]
            if node in numbers:
                pending.pop()
                continue
            level, low, high = self.nodes[node]
            if low in numbers and high in numbers:
                pending.pop()
                numbers[node] = len(nodes) + 2
                nodes.append((level, numbers[low], numbers[high]))
            else:
                pending.extend(child for child in (high, low) if child not in numbers)
        return tuple(nodes), numbers[root]

    def restrict(self, node: int, variable: tuple, code: int, memo: dict) -> int:
        """node with variable's value the one of code"""
        if node in (FALSE_NODE, TRUE_NODE):
            return node
        found = memo.get(node)
        if found is not None:
            return found

        first, bits, _ = self.codes[variable]
        level, low, high = self.nodes[node]
        if level < first:
            result = self.node(level, self.restrict(low, variable, code, memo),
                               self.restrict(high, variable, code, memo))
        elif level < first + bits:
            result = self.restrict(high if code >> (level - first) & 1 else low, variable, code, memo)
        else:
            result = node
        memo[node] = result
        return result

    def node(self, level: int, low: int, high: int) -> int:
        if low == high:
            return low
        key = (level, low, high)
        found = self.unique.get(key)
        if found is None:
            if len(self.nodes) >= self.cap:
                raise DiagramOverflow()
            found = self.unique[key] = len(self.nodes)
            self.nodes.append(key)
        return found

    def apply(self, operation: str, a: int, b: int) -> int:
        if operation == 'and':
            if a == FALSE_NODE or b == FALSE_NODE:
                return FALSE_NODE
            if a == TRUE_NODE or a == b:
                return b
            if b == TRUE_NODE:
                return a
        else:
            if a == TRUE_NODE or b == TRUE_NODE:
                return TRUE_NODE
            if a == FALSE_NODE or a == b:
                return b
            if b == FALSE_NODE:
                return a
        key = (operation, min(a, b), max(a, b))
        found = self.cache.get(key)
        if found is not None:
            return found

        level_a, level_b = self.nodes[a][0], self.nodes[b][0]
        level = min(level_a, level_b)
        low_a, high_a = self.nodes[a][1:] if level_a == level else (a, a)
        low_b, high_b = self.nodes[b][1:] if level_b == level else (b, b)
        result = self.node(level, self.apply(operation, low_a, low_b), self.apply(operation, high_a, high_b))
        self.cache[key] = result
        return result

    def negate(self, a: int) -> int:
        if a in (FALSE_NODE, TRUE_NODE):
            return TRUE_NODE - a
        key = ('not', a)
        found = self.cache.get(key)
        if found is None:
            level, low, high = self.nodes[a]
            found = self.cache[key] = self.node(level, self.negate(low), self.negate(high))
        return found

    def build(self, structure, memo: dict) -> int:
        found = memo.get(id(structure))
        if found is not None:
            return found[1]

        tag = structure[0]
        if tag == 'true':
            result = TRUE_NODE
        elif tag == 'false':
            result = FALSE_NODE
        elif tag == 'eq':
            first, bits, codes = self.codes.get(('eq', structure[1]), (0, 0, {}))
            code = codes.get(structure[2])
            result = TRUE_NODE if code is not None else FALSE_NODE  # a constant left out: the value is any other
            for bit in reversed(range(bits if code is not None else 0)):    # the code's bits, the lowest level first
                result = self.node(first + bit, *((FALSE_NODE, result) if code >> bit & 1 else (result, FALSE_NODE)))
        elif tag == 'not':
            result = self.negate(self.build(structure[1], memo))
        else:
            result = TRUE_NODE if tag == 'and' else FALSE_NODE
            for item in structure[1]:
                result = self.apply(tag, result, self.build(item, memo))
        memo[id(structure)] = (structure, result)
        return result
