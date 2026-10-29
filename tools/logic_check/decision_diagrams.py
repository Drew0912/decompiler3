"""Reduced ordered binary decision diagrams (Bryant, 1986) for the exact comparison of formulas past formulas.ROW_CAP
rows, over their structures (formulas.FormulaKeys.structure)"""

FALSE_NODE, TRUE_NODE = 0, 1    # Diagrams' terminals
DIAGRAM_NODE_CAP = 1_000_000    # a pairwise comparison's diagram (Diagrams.same)
DIAGRAM_KEY_NODE_CAP = 20_000   # a key's (Diagrams.key) and the one finding its variables (Diagrams.relevant)


def collect_variables(structure, variables: dict, seen: set):
    """Each variable structure tests (FormulaKeys.structure), with the constants it tests it against, into
    variables"""
    if id(structure) in seen:
        return
    seen.add(id(structure))
    tag = structure[0]
    if tag == 'eq':
        variables.setdefault(('eq', structure[1]), set()).add(structure[2])
    elif tag == 'not':
        collect_variables(structure[1], variables, seen)
    elif tag in ('and', 'or'):
        for item in structure[1]:
            collect_variables(item, variables, seen)


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
            collect_variables(structure, variables, set())
        self.assign_levels(list(variables.items()))
        memo = {}
        return self.build(a, memo) == self.build(b, memo)

    @classmethod
    def relevant(cls, structure, variables: dict) -> dict:
        """variable -> the constants structure tells from any other value, of each variable it depends on: its diagram
        over variables in the order given, which the answer does not depend on"""
        diagrams = cls(DIAGRAM_KEY_NODE_CAP)
        diagrams.assign_levels(list(variables.items()))
        return diagrams.relevant_variables(diagrams.build(structure, {}), variables)

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
