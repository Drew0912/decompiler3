"""The HLIL side of the evaluation: the statement tree as a control-flow graph with real edges - statement to statement,
an if's arms and their join, a loop's header, body, back and exit edges, a switch's tests in case order, break,
continue and return - with one test per operand of an && or || recovered from jumps, the VM's eager ones one test
whole, both operands evaluated, as the bytecode has them. Storage is named through the MLIL function the HLIL came
from, whose variable names HLIL keeps; evaluated gated (naming.GatedNaming), a loop header named by its loop's stamp"""

from dataclasses import dataclass
from itertools import count

from ir.core.il_literals import is_int_zero
from ir.hlil.hlil import (
    BinaryOp, HighLevelILFunction, HLILAddressOf, HLILAssign, HLILBinaryOp, HLILBlock, HLILBreak, HLILCall,
    HLILComment, HLILConst, HLILContinue, HLILDeref, HLILDoWhile, HLILExprStmt, HLILExternCall, HLILIf,
    HLILIntrinsic, HLILReturn, HLILSwitch, HLILSyscall, HLILUnaryOp, HLILUnstructured, HLILVar, HLILVariable,
    HLILWhile, UnaryOp, VariableKind,
    iter_tree, resolve_exit_target, unwrap_address_taken_var,
)
from ir.mlil.mlil import MediumLevelILFunction, MLILSetVar, MLILVar, MLILVariable, walk
from .facts import Branch, Effect, Facts
from .mlil_layer import MLILStorage
from .state import MEMORY_EPOCH, State
from .trees import ENTRY, const, constant_truth, op
from .vm_effects import VMEffects

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
CALLS = (HLILCall, HLILSyscall, HLILExternCall)
CONSTANT_EXPRESSIONS = (HLILConst, HLILBinaryOp, HLILUnaryOp)


class Node:
    """A node of the graph: its steps, its edges, and the stamp naming its loop where it is a loop's header"""

    __slots__ = ('index', 'instructions', 'outgoing_edges', 'incoming_edges', 'loop_stamp')

    def __init__(self, index: int):
        self.index = index
        self.instructions = []
        self.outgoing_edges: list[Node] = []
        self.incoming_edges: list[Node] = []
        self.loop_stamp: int | None = None

    def __repr__(self) -> str:
        return f'Node({self.index})'


@dataclass(slots=True, eq=False)
class Test:
    """A node's last step: condition decides between two nodes"""
    branch_number: int
    condition: object
    true_node: Node
    false_node: Node


@dataclass(slots=True, eq=False)
class Scrutinee:
    """A switch's scrutinee, evaluated once into ('switch', switch) for its case tests"""
    switch: int
    expr: object


@dataclass(slots=True, eq=False)
class CaseTest(Test):
    """A switch's test of one case label (its condition), a node's last step"""
    switch: int


class ExitTarget:
    """A loop or switch a break (for a loop, also a continue) leaves, and where each goes"""

    def __init__(self, stmt, break_node: Node, continue_node: Node | None):
        self.label = getattr(stmt, 'label', None)
        self.is_switch = isinstance(stmt, HLILSwitch)
        self.break_node = break_node
        self.continue_node = continue_node


def mlil_variables_by_name(mlil: MediumLevelILFunction) -> dict[str, MLILVariable]:
    """Every variable of the MLIL function by name: its parameters, locals and register variables, and any other an
    instruction reads or writes"""
    variables = {var.name: var for var in [*mlil.parameters, *mlil.locals.values(), *mlil.register_vars.values()]
                 if var is not None}
    for inst in mlil.iter_instructions():
        for node in walk(inst):
            if isinstance(node, MLILVar):
                variables.setdefault(node.var.name, node.var)
        written = inst.var if isinstance(inst, MLILSetVar) else getattr(inst, 'output', None)
        if isinstance(written, MLILVariable):
            variables.setdefault(written.name, written)
    return variables


class HLILLayer:
    OWN_STORAGE_NAMES = True        # MLIL's own storage (split ranges, ...), kept by HLIL
    VM_EFFECTS        = VMEffects   # the effects of its engine's VM

    def __init__(self, func: HighLevelILFunction, mlil: MediumLevelILFunction):
        self.mlil_storage = MLILStorage(mlil)
        self.variables = mlil_variables_by_name(mlil)
        self.vm = self.VM_EFFECTS(self.neutral_key)     # before anything evaluates
        self.nodes: list[Node] = []
        self.branch_numbers, self.switch_numbers = count(), count()
        end = self.new_node()           # falling off the end of the body
        self.entry = self.new_node(successors=[self.build_block(func.body.statements, end, [])])   # never a loop header

    # === The graph ===

    def new_node(self, instructions=(), successors=()) -> Node:
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

    def build_block(self, statements: list, follow: Node, exit_targets: list) -> Node:
        """The node statements start at, follow after them"""
        entry = follow
        for stmt in reversed(statements):
            entry = self.build_statement(stmt, entry, exit_targets)
        return entry

    def build_statement(self, stmt, follow: Node, exit_targets: list) -> Node:
        if isinstance(stmt, HLILComment):
            return follow
        if isinstance(stmt, (HLILAssign, HLILExprStmt, HLILIntrinsic)):
            return self.new_node([stmt], [follow])
        if isinstance(stmt, (HLILReturn, HLILUnstructured)):
            return self.new_node([stmt])
        if isinstance(stmt, (HLILBreak, HLILContinue)):
            target = resolve_exit_target(exit_targets, stmt.label, loop_only=isinstance(stmt, HLILContinue))
            if target is None:
                raise RuntimeError(f'{stmt} leaves no loop or switch')
            return target.break_node if isinstance(stmt, HLILBreak) else target.continue_node
        if isinstance(stmt, HLILIf):
            true_entry = self.build_block(stmt.true_block.statements, follow, exit_targets)
            false_entry = (self.build_block(stmt.false_block.statements, follow, exit_targets) if stmt.false_block
                           else follow)
            return self.build_condition(stmt.condition, true_entry, false_entry)
        if isinstance(stmt, HLILWhile):
            header = self.new_loop_header(stmt)
            body = self.build_block(stmt.body.statements, header, exit_targets + [ExitTarget(stmt, follow, header)])
            self.edge(header, self.build_condition(stmt.condition, body, follow))
            return header
        if isinstance(stmt, HLILDoWhile):
            header = self.new_loop_header(stmt)
            test = self.build_condition(stmt.condition, header, follow)
            self.edge(header, self.build_block(stmt.body.statements, test,
                                               exit_targets + [ExitTarget(stmt, follow, test)]))
            return header
        if isinstance(stmt, HLILSwitch):
            return self.build_switch(stmt, follow, exit_targets)
        if isinstance(stmt, HLILBlock):
            return self.build_block(stmt.statements, follow, exit_targets)

        raise RuntimeError(f'no HLIL graph rule for {type(stmt).__name__}')

    def new_loop_header(self, loop) -> Node:
        node = self.new_node()
        node.loop_stamp = loop.address
        return node

    def build_condition(self, expr, true_node: Node, false_node: Node) -> Node:
        """The tests deciding expr, one per operand of a recovered && or ||, an eager one whole, entered at the first; a
        constant one is none, its arm taken (as MLILLayer follows a constant branch)"""
        expr, negated = self.strip_truth_tests(expr)
        if negated:
            true_node, false_node = false_node, true_node
        if isinstance(expr, HLILBinaryOp) and expr.op == BinaryOp.AND_THEN:
            return self.build_condition(expr.lhs, self.build_condition(expr.rhs, true_node, false_node), false_node)
        if isinstance(expr, HLILBinaryOp) and expr.op == BinaryOp.OR_ELSE:
            return self.build_condition(expr.lhs, true_node, self.build_condition(expr.rhs, true_node, false_node))
        if all(isinstance(node, CONSTANT_EXPRESSIONS) for node in iter_tree(expr)):
            always = constant_truth(self.evaluate(expr, State(), []))
            if always is not None:
                return true_node if always else false_node

        return self.new_node([Test(next(self.branch_numbers), expr, true_node, false_node)], [true_node, false_node])

    @classmethod
    def strip_truth_tests(cls, expr) -> tuple:
        """(expr, negated) with `x == 0`, `x != 0` and `!x` stripped, so a recovered && or || under them is split too"""
        negated = False
        while True:
            if isinstance(expr, HLILUnaryOp) and expr.op == UnaryOp.NOT:
                expr, negated = expr.operand, not negated
            elif (isinstance(expr, HLILBinaryOp) and expr.op in (BinaryOp.EQ, BinaryOp.NE)
                  and isinstance(expr.rhs, HLILConst) and is_int_zero(expr.rhs.value)):
                expr, negated = expr.lhs, negated ^ (expr.op == BinaryOp.EQ)
            else:
                return expr, negated

    def build_switch(self, stmt: HLILSwitch, follow: Node, exit_targets: list) -> Node:
        """The scrutinee, then each label's test in case order, the default case after the last"""
        switch = next(self.switch_numbers)
        inner = exit_targets + [ExitTarget(stmt, follow, None)]
        chain = follow
        for case in stmt.cases:
            if case.is_default():
                chain = self.build_block(case.body.statements, follow, inner)
        for case in reversed([case for case in stmt.cases if not case.is_default()]):
            body = self.build_block(case.body.statements, follow, inner)
            for value in reversed(case.values):
                chain = self.new_node([CaseTest(next(self.branch_numbers), value, body, chain, switch)], [body, chain])
        return self.new_node([Scrutinee(switch, stmt.scrutinee)], [chain])

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
            return last.branch_number, last.true_node, last.false_node

        return None

    @classmethod
    def header_name(cls, node: Node) -> int | None:
        return node.loop_stamp

    def neutral_key(self, key: tuple) -> tuple:
        return self.mlil_storage.neutral_key(key)

    def key(self, var: HLILVariable) -> tuple:
        if var.kind == VariableKind.REG:
            return ('reg', var.index)
        if var.kind == VariableKind.GLOBAL:
            return ('global', var.index)

        return self.mlil_storage.key(self.mlil_variable(var))

    def read(self, var: HLILVariable, state: State) -> tuple:
        if var.kind == VariableKind.REG:
            return state.register(var.index)
        if var.kind == VariableKind.GLOBAL:
            return state.global_value(var.index)

        return self.mlil_storage.read(self.mlil_variable(var), state)

    def mlil_variable(self, var: HLILVariable) -> MLILVariable:
        """The MLIL variable var names, whose storage it is"""
        return self.variables.get(var.name) or MLILVariable(var.name)

    def step(self, inst, state: State, facts: Facts) -> list[Effect]:
        effects = []
        if isinstance(inst, CaseTest):
            condition = op('EQ', [state.get(('switch', inst.switch), None),
                                  self.evaluate(inst.condition, state, effects)])
            facts.branches[inst.branch_number] = Branch(inst.branch_number, condition, inst.true_node.index,
                                                        inst.false_node.index)
        elif isinstance(inst, Test):
            facts.branches[inst.branch_number] = Branch(inst.branch_number,
                                                        self.evaluate(inst.condition, state, effects),
                                                        inst.true_node.index, inst.false_node.index)
        elif isinstance(inst, Scrutinee):
            state.set(('switch', inst.switch), self.evaluate(inst.expr, state, effects))
        elif isinstance(inst, HLILAssign):
            self.assign(inst, state, effects)
        elif isinstance(inst, HLILExprStmt):
            self.evaluate(inst.expr, state, effects)
        elif isinstance(inst, HLILIntrinsic):
            # Its args first: a call folded into them is an effect of its own, before the print
            args = tuple(self.evaluate(arg, state, effects) for arg in inst.args)
            effects.append(self.vm.print(inst.address, inst.name, args))
        elif isinstance(inst, HLILReturn):
            value = None if inst.value is None else self.evaluate(inst.value, state, effects)
            effects.append(self.vm.ret(state, inst.address, value))
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
            effects.append(self.vm.store_deref(state, inst.address, pointer, value))
        elif isinstance(dest, HLILVar):
            value = self.evaluate(inst.src, state, effects)
            key = self.key(dest.var)
            if key[0] == 'global':
                effects.append(self.vm.store_global(state, inst.address, key[1], value))
            else:
                self.vm.write(state, key, value)
        else:
            raise RuntimeError(f'no HLIL rule for an assignment to {type(dest).__name__}')

    def evaluate(self, expr, state: State, effects: list) -> tuple:
        """expr's tree; the calls it makes appended to effects in evaluation order"""
        if isinstance(expr, HLILConst):
            return const(expr.value)
        if isinstance(expr, HLILVar):
            return self.read(expr.var, state)
        if isinstance(expr, HLILBinaryOp):
            lhs = self.evaluate(expr.lhs, state, effects)
            return op(BINARY_OPERATIONS[expr.op], [lhs, self.evaluate(expr.rhs, state, effects)])
        if isinstance(expr, HLILUnaryOp):
            return op(UNARY_OPERATIONS[expr.op], [self.evaluate(expr.operand, state, effects)])
        if isinstance(expr, HLILAddressOf):
            if isinstance(expr.operand, HLILVar):
                return self.vm.address_of(self.key(expr.operand.var))
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
        """The call's value, which reaches the result register only by an assignment to it (reg0 = f())"""
        args = tuple(self.evaluate(arg, state, effects) for arg in expr.args)
        if isinstance(expr, HLILSyscall):
            kind, target = 'syscall', (expr.subsystem, expr.cmd)
        elif isinstance(expr, HLILExternCall):
            kind, target = 'script call', expr.target.replace(':', '.', 1)    # MLILLayer's `module.func`
        else:
            kind, target = 'call', expr.func_name

        effects.append(self.vm.call(state, expr.address, kind, target, args, delivers_result=False))
        return ('call', expr.address)
