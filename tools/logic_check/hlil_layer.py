"""The HLIL side of the evaluation: the statement tree as a control-flow graph with real edges - statement to statement,
an if's arms and their join, a loop's header, body, back and exit edges, a switch's tests in case order, break,
continue and return - with one test per operand of a condition's && and ||, as the .ts evaluates them. Storage is
named through the MLIL function the HLIL came from, whose variable names HLIL keeps; evaluated gated
(evaluation.GatedNaming), a loop header named by its loop's stamp"""

from ir.hlil.hlil import (
    BinaryOp, HighLevelILFunction, HLILAddressOf, HLILAssign, HLILBinaryOp, HLILBlock, HLILBreak, HLILCall,
    HLILComment, HLILConst, HLILContinue, HLILDeref, HLILDoWhile, HLILExprStmt, HLILExternCall, HLILIf, HLILReturn,
    HLILSwitch, HLILSyscall, HLILUnaryOp, HLILUnstructured, HLILVar, HLILVariable, HLILWhile, UnaryOp, VariableKind,
    iter_tree, resolve_exit_target, unwrap_address_taken_var,
)
from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILSetVar, MLILVar, MLILVariable, walk,
)
from .evaluation import Branch, Effect, Facts
from .mlil_layer import MLILLayer
from .state import MEMORY_EPOCH, RESULT_REGISTER, State
from .trees import ENTRY, const, constant_truth, op

BINARY_OPERATIONS = {           # the trees' operation names, MLIL's
    BinaryOp.ADD     : 'ADD',
    BinaryOp.SUB     : 'SUB',
    BinaryOp.MUL     : 'MUL',
    BinaryOp.DIV     : 'DIV',
    BinaryOp.MOD     : 'MOD',
    BinaryOp.EQ      : 'EQ',
    BinaryOp.NE      : 'NE',
    BinaryOp.LT      : 'LT',
    BinaryOp.LE      : 'LE',
    BinaryOp.GT      : 'GT',
    BinaryOp.GE      : 'GE',
    BinaryOp.AND     : 'LOGICAL_AND',
    BinaryOp.OR      : 'LOGICAL_OR',
    BinaryOp.BIT_AND : 'AND',
    BinaryOp.BIT_OR  : 'OR',
    BinaryOp.BIT_XOR : 'XOR',
    BinaryOp.SHL     : 'SHL',
    BinaryOp.SHR     : 'SHR',
}
UNARY_OPERATIONS = {
    UnaryOp.NEG     : 'NEG',
    UnaryOp.NOT     : 'LOGICAL_NOT',
    UnaryOp.BIT_NOT : 'BITWISE_NOT',
}
SHORT_CIRCUIT = (BinaryOp.AND, BinaryOp.OR)
CALLS = (HLILCall, HLILSyscall, HLILExternCall)
CONSTANT_EXPRESSIONS = (HLILConst, HLILBinaryOp, HLILUnaryOp)


class Node:
    """A node of the graph: its steps, its edges, and the stamp naming its loop where it is a loop's header"""

    __slots__ = ('index', 'instructions', 'outgoing_edges', 'incoming_edges', 'loop')

    def __init__(self, index: int):
        self.index = index
        self.instructions = []
        self.outgoing_edges: list[Node] = []
        self.incoming_edges: list[Node] = []
        self.loop: int | None = None

    def __repr__(self) -> str:
        return f'Node({self.index})'


class Test:
    """A node's last step: condition decides between two nodes"""

    __slots__ = ('branch', 'condition', 'true_node', 'false_node')

    def __init__(self, branch: int, condition, true_node: Node, false_node: Node):
        self.branch, self.condition, self.true_node, self.false_node = branch, condition, true_node, false_node


class Scrutinee:
    """A switch's scrutinee, evaluated once into ('switch', switch) for its case tests"""

    __slots__ = ('switch', 'expr')

    def __init__(self, switch: int, expr):
        self.switch, self.expr = switch, expr


class CaseTest(Test):
    """A switch's test of one case label, a node's last step"""

    __slots__ = ('switch',)

    def __init__(self, branch: int, switch: int, value, true_node: Node, false_node: Node):
        super().__init__(branch, value, true_node, false_node)
        self.switch = switch


class ExitTarget:
    """A loop or switch a break (for a loop, also a continue) leaves, and where each goes"""

    def __init__(self, stmt, after: Node, cont: Node | None):
        self.label = getattr(stmt, 'label', None)
        self.is_switch = isinstance(stmt, HLILSwitch)
        self.after = after
        self.cont = cont


class HLILLayer:
    OWN_STORAGE_NAMES = True        # MLIL's split ranges and minted locals, kept by HLIL

    def __init__(self, func: HighLevelILFunction, mlil: MediumLevelILFunction):
        self.func = func
        self.naming = MLILLayer(mlil)
        self.variables = {var.name: var for var in [*mlil.parameters, *mlil.locals.values(),
                                                    *mlil.register_vars.values()] if var is not None}
        self.calls = {}             # MLIL instruction index -> its call: whether the call clobbers
        for inst in mlil.iter_instructions():
            if isinstance(inst, MediumLevelILCall):
                self.calls[inst.inst_index] = inst
            for node in walk(inst):
                if isinstance(node, MLILVar):
                    self.variables.setdefault(node.var.name, node.var)
            written = inst.var if isinstance(inst, MLILSetVar) else getattr(inst, 'output', None)
            if isinstance(written, MLILVariable):
                self.variables.setdefault(written.name, written)

        self.address_taken = {self.key(node.operand.var) for node in iter_tree(func.body)
                              if isinstance(node, HLILAddressOf) and isinstance(node.operand, HLILVar)}
        self.nodes: list[Node] = []
        self.counts = {'branch': 0, 'switch': 0}
        end = self.node()           # falling off the end of the body
        self.entry = self.node(successors=[self.block(func.body.statements, end, [])])   # never a loop header

    # === The graph ===

    def node(self, instructions=(), successors=()) -> Node:
        node = Node(len(self.nodes))
        node.instructions.extend(instructions)
        self.nodes.append(node)
        for successor in successors:
            self.edge(node, successor)
        return node

    @classmethod
    def edge(cls, source: Node, target: Node):
        if target not in source.outgoing_edges:
            source.outgoing_edges.append(target)
            target.incoming_edges.append(source)

    def count(self, kind: str) -> int:
        number = self.counts[kind]
        self.counts[kind] += 1
        return number

    def block(self, statements: list, follow: Node, targets: list) -> Node:
        """The node statements start at, follow after them"""
        entry = follow
        for stmt in reversed(statements):
            entry = self.statement(stmt, entry, targets)
        return entry

    def statement(self, stmt, follow: Node, targets: list) -> Node:
        if isinstance(stmt, HLILComment):
            return follow
        if isinstance(stmt, (HLILAssign, HLILExprStmt)):
            return self.node([stmt], [follow])
        if isinstance(stmt, (HLILReturn, HLILUnstructured)):
            return self.node([stmt])
        if isinstance(stmt, (HLILBreak, HLILContinue)):
            target = resolve_exit_target(targets, stmt.label, loop_only=isinstance(stmt, HLILContinue))
            if target is None:
                raise RuntimeError(f'{stmt} leaves no loop or switch')
            return target.after if isinstance(stmt, HLILBreak) else target.cont
        if isinstance(stmt, HLILIf):
            true_entry = self.block(stmt.true_block.statements, follow, targets)
            false_entry = self.block(stmt.false_block.statements, follow, targets) if stmt.false_block else follow
            return self.condition(stmt.condition, true_entry, false_entry)
        if isinstance(stmt, HLILWhile):
            header = self.loop_header(stmt)
            body = self.block(stmt.body.statements, header, targets + [ExitTarget(stmt, follow, header)])
            self.edge(header, self.condition(stmt.condition, body, follow))
            return header
        if isinstance(stmt, HLILDoWhile):
            header = self.loop_header(stmt)
            test = self.condition(stmt.condition, header, follow)
            self.edge(header, self.block(stmt.body.statements, test, targets + [ExitTarget(stmt, follow, test)]))
            return header
        if isinstance(stmt, HLILSwitch):
            return self.switch(stmt, follow, targets)
        if isinstance(stmt, HLILBlock):
            return self.block(stmt.statements, follow, targets)

        raise RuntimeError(f'no HLIL graph rule for {type(stmt).__name__}')

    def loop_header(self, loop) -> Node:
        node = self.node()
        node.loop = loop.address
        return node

    def condition(self, expr, true_node: Node, false_node: Node) -> Node:
        """The tests deciding expr, one per operand of && and ||, entered at the first; a constant one is none, its arm
        taken (as MLILLayer follows a constant branch)"""
        expr, negated = self.truth_test(expr)
        if negated:
            true_node, false_node = false_node, true_node
        if isinstance(expr, HLILBinaryOp) and expr.op == BinaryOp.AND:
            return self.condition(expr.lhs, self.condition(expr.rhs, true_node, false_node), false_node)
        if isinstance(expr, HLILBinaryOp) and expr.op == BinaryOp.OR:
            return self.condition(expr.lhs, true_node, self.condition(expr.rhs, true_node, false_node))
        if all(isinstance(node, CONSTANT_EXPRESSIONS) for node in iter_tree(expr)):
            always = constant_truth(self.evaluate(expr, State(), []))
            if always is not None:
                return true_node if always else false_node

        return self.node([Test(self.count('branch'), expr, true_node, false_node)], [true_node, false_node])

    @classmethod
    def truth_test(cls, expr) -> tuple:
        """(expr, negated) with `x == 0`, `x != 0` and `!x` stripped, so a && or || under them is split too"""
        negated = False
        while True:
            if isinstance(expr, HLILUnaryOp) and expr.op == UnaryOp.NOT:
                expr, negated = expr.operand, not negated
            elif (isinstance(expr, HLILBinaryOp) and expr.op in (BinaryOp.EQ, BinaryOp.NE)
                  and cls.is_zero(expr.rhs)):
                expr, negated = expr.lhs, negated ^ (expr.op == BinaryOp.EQ)
            else:
                return expr, negated

    @classmethod
    def is_zero(cls, expr) -> bool:
        return isinstance(expr, HLILConst) and isinstance(expr.value, int) and expr.value == 0

    def switch(self, stmt: HLILSwitch, follow: Node, targets: list) -> Node:
        """The scrutinee, then each label's test in case order, the default case after the last"""
        switch = self.count('switch')
        inner = targets + [ExitTarget(stmt, follow, None)]
        chain = follow
        for case in stmt.cases:
            if case.is_default():
                chain = self.block(case.body.statements, follow, inner)
        for case in reversed([case for case in stmt.cases if not case.is_default()]):
            body = self.block(case.body.statements, follow, inner)
            for value in reversed(case.values):
                chain = self.node([CaseTest(self.count('branch'), switch, value, body, chain)], [body, chain])
        return self.node([Scrutinee(switch, stmt.scrutinee)], [chain])

    # === The adapter ===

    @classmethod
    def successors(cls, node: Node) -> list:
        return node.outgoing_edges

    @classmethod
    def predecessors(cls, node: Node) -> list:
        return node.incoming_edges

    @classmethod
    def branch(cls, node: Node) -> tuple | None:
        last = node.instructions[-1] if node.instructions else None
        if isinstance(last, Test):
            return last.branch, last.true_node, last.false_node

        return None

    @classmethod
    def header_name(cls, node: Node) -> int | None:
        return node.loop

    def neutral_key(self, key: tuple) -> tuple:
        return self.naming.neutral_key(key)

    def key(self, var: HLILVariable) -> tuple:
        if var.kind == VariableKind.REG:
            return ('reg', var.index)
        if var.kind == VariableKind.GLOBAL:
            return ('global', var.index)

        return self.naming.key(self.variables.get(var.name) or MLILVariable(var.name))

    def read(self, var: HLILVariable, state: State) -> tuple:
        if var.kind == VariableKind.REG:
            return state.register(var.index)
        if var.kind == VariableKind.GLOBAL:
            return state.global_value(var.index)

        return self.naming.read(self.variables.get(var.name) or MLILVariable(var.name), state)

    def step(self, inst, state: State, facts: Facts) -> list[Effect]:
        effects = []
        if isinstance(inst, CaseTest):
            condition = op('EQ', [state.get(('switch', inst.switch), None),
                                  self.evaluate(inst.condition, state, effects)])
            facts.branches[inst.branch] = Branch(inst.branch, condition, inst.true_node.index, inst.false_node.index)
        elif isinstance(inst, Test):
            facts.branches[inst.branch] = Branch(inst.branch, self.evaluate(inst.condition, state, effects),
                                                 inst.true_node.index, inst.false_node.index)
        elif isinstance(inst, Scrutinee):
            state.set(('switch', inst.switch), self.evaluate(inst.expr, state, effects))
        elif isinstance(inst, HLILAssign):
            self.assign(inst, state, effects)
        elif isinstance(inst, HLILExprStmt):
            self.evaluate(inst.expr, state, effects)
        elif isinstance(inst, HLILReturn):
            value = state.register(RESULT_REGISTER) if inst.value is None else self.evaluate(inst.value, state, effects)
            effects.append(Effect(inst.address, 'return', None, (value,), storage=state.return_registers()))
        elif isinstance(inst, HLILUnstructured):
            facts.unstructured.append(inst)
        else:
            raise RuntimeError(f'no HLIL rule for {type(inst).__name__}')

        return effects

    def assign(self, inst: HLILAssign, state: State, effects: list):
        dest = inst.dest
        local = unwrap_address_taken_var(dest)
        if local is not None:           # the memory form of a local's write, *(&v) = x
            state.set(self.key(local.var), self.evaluate(inst.src, state, effects))
        elif isinstance(dest, HLILDeref):
            pointer = self.evaluate(dest.operand, state, effects)
            value = self.evaluate(inst.src, state, effects)
            effects.append(Effect(inst.address, 'store deref', None, (pointer, value)))
            state.escape(value, self.address_taken, self.neutral_key)
            state.store_through_pointer(inst.address)
        elif isinstance(dest, HLILVar):
            value = self.evaluate(inst.src, state, effects)
            key = self.key(dest.var)
            if self.neutral_key(key)[0] in ('reg', 'global'):   # a de-SSA split of a register too
                state.escape(value, self.address_taken, self.neutral_key)
            if key[0] == 'global':
                effects.append(Effect(inst.address, 'store global', key[1], (value,)))
            state.set(key, value)
        else:
            raise RuntimeError(f'no HLIL rule for an assignment to {type(dest).__name__}')

    def evaluate(self, expr, state: State, effects: list) -> tuple:
        """expr's tree; the calls it makes appended to effects in evaluation order"""
        if isinstance(expr, HLILConst):
            return const(expr.value)
        if isinstance(expr, HLILVar):
            return self.read(expr.var, state)
        if isinstance(expr, HLILBinaryOp):
            if expr.op in SHORT_CIRCUIT and any(isinstance(node, CALLS) for node in iter_tree(expr.rhs)):
                raise RuntimeError(f'a call under the right operand of {expr.op.name} outside a condition')
            lhs = self.evaluate(expr.lhs, state, effects)
            return op(BINARY_OPERATIONS[expr.op], [lhs, self.evaluate(expr.rhs, state, effects)])
        if isinstance(expr, HLILUnaryOp):
            return op(UNARY_OPERATIONS[expr.op], [self.evaluate(expr.operand, state, effects)])
        if isinstance(expr, HLILAddressOf):
            if isinstance(expr.operand, HLILVar):
                return ('address', self.neutral_key(self.key(expr.operand.var)))
            return ('address', self.evaluate(expr.operand, state, effects))
        if isinstance(expr, HLILDeref):
            local = unwrap_address_taken_var(expr)     # the memory form of a local's read, *(&v)
            if local is not None:
                return self.read(local.var, state)
            return ('deref', self.evaluate(expr.operand, state, effects), state.get(MEMORY_EPOCH, ENTRY))
        if isinstance(expr, CALLS):
            return self.call(expr, state, effects)

        raise RuntimeError(f'no HLIL rule for {type(expr).__name__}')

    def call(self, expr, state: State, effects: list) -> tuple:
        args = tuple(self.evaluate(arg, state, effects) for arg in expr.args)
        if isinstance(expr, HLILSyscall):
            kind, target = 'syscall', (expr.subsystem, expr.cmd)
        elif isinstance(expr, HLILExternCall):
            kind, target = 'script call', '.'.join(expr.target.split(':', 1))
        else:
            kind, target = 'call', expr.func_name

        effect = Effect(expr.address, kind, target, args)
        source = self.calls.get(expr.mlil_index)
        if source is None or source.clobbers_registers:
            pointed = state.reachable_locals(args, self.address_taken, self.neutral_key)
            effect.storage = state.local_values(pointed, self.neutral_key)
            state.clobber(expr.address, pointed)
            state.set(('reg', RESULT_REGISTER), ('call', expr.address))
        effects.append(effect)
        return ('call', expr.address)
