"""The MLIL side of the evaluation: a variable is the storage it stands for - a register variable the register, a
parameter the parameter, a stack variable its slot; a live range de-SSA split off (`{base}_v{n}`) or a minted local is
storage of its own, named like its base where a loop value needs a name on every layer"""

import re

from ir.core import reverse_post_order
from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILAddressOf, MLILBinaryOp, MLILCallScript, MLILConst, MLILDebug,
    MLILDeref, MLILGoto, MLILIf, MLILLoadGlobal, MLILLoadReg, MLILNop, MLILRet, MLILSetVar, MLILStoreDeref,
    MLILStoreGlobal, MLILStoreReg, MLILSyscall, MLILUnaryOp, MLILUndef, MLILVar, MLILVariable,
    UNASSIGNED_SLOT_INDEX, walk,
)
from .evaluation import Branch, Effect, Facts
from .state import MEMORY_EPOCH, RESULT_REGISTER, State
from .trees import ENTRY, const, constant_truth, op

SPLIT_SUFFIX = re.compile(r'_v\d+$')
PARAMETER_NAME = re.compile(r'^arg(\d+)$')
STACK_NAME = re.compile(r'^var_s(\d+)$')
IGNORED = (MLILGoto, MLILDebug, MLILNop)
COPIES = (MLILSetVar, *IGNORED)
CONSTANT_EXPRESSIONS = (MLILConst, MLILBinaryOp, MLILUnaryOp)


class MLILLayer:
    """The MLIL's graph as written, or with hlil_view as HLIL structures it (against HLIL): a branch on a constant
    condition is a jump to the target it always takes (HLIL folds a loop's constant test), and a block holding only
    jumps, line markers and nops, a loop's header aside, passes control on to where it leads (the converter skips such
    a block, so HLIL joins arms where they lead)"""

    OWN_STORAGE_NAMES = True        # a split range or a minted local

    def __init__(self, func: MediumLevelILFunction, *, hlil_view: bool = False):
        self.func = func
        self.entry = func.basic_blocks[0]
        self.edges = {block: list(block.outgoing_edges) for block in func.basic_blocks}
        self.targets = {block: (block.instructions[-1].true_target, block.instructions[-1].false_target)
                        for block in func.basic_blocks if isinstance(block.instructions[-1], MLILIf)}
        if hlil_view:
            self.follow_constant_branches()
            self.pass_empty_blocks()
        self.incoming = {block: [] for block in func.basic_blocks}
        for block, successors in self.edges.items():
            for successor in successors:
                self.incoming[successor].append(block)

        self.register_of = {var.name: index for index, var in func.register_vars.items()}
        self.parameter_of = {var.name: position for position, var in enumerate(func.parameters, 1) if var is not None}
        self.neutral_of: dict[str, tuple] = {}
        self.address_taken = set()
        for inst in func.iter_instructions():
            for node in walk(inst):
                if isinstance(node, MLILAddressOf) and isinstance(node.operand, MLILVar):
                    self.address_taken.add(self.key(node.operand.var))

    def follow_constant_branches(self):
        for block in list(self.targets):
            target = self.constant_target(block)
            if target is not None:
                self.edges[block] = [target]
                del self.targets[block]

    def pass_empty_blocks(self):
        order = reverse_post_order(self.entry, self.edges.__getitem__)
        position = {block: index for index, block in enumerate(order)}
        headers = {target for source in order for target in self.edges[source] if position[target] <= position[source]}
        passed = {block for block in order if block is not self.entry and block not in headers
                  and len(self.edges[block]) == 1 and all(isinstance(inst, IGNORED) for inst in block.instructions)}

        def through(block):
            seen = set()
            while block in passed and block not in seen:
                seen.add(block)
                block = self.edges[block][0]
            return block

        for block in order:
            if block in passed:
                self.edges[block] = []
            else:
                self.edges[block] = list(dict.fromkeys(map(through, self.edges[block])))
                if block in self.targets:
                    self.targets[block] = tuple(map(through, self.targets[block]))

    def successors(self, block) -> list:
        return self.edges[block]

    def predecessors(self, block) -> list:
        return self.incoming[block]

    @classmethod
    def terminal_address(cls, block) -> int:
        return block.instructions[-1].address

    @classmethod
    def header_name(cls, block) -> int:
        """A loop header's terminal address, the stamp HLIL's loop built from it carries"""
        return cls.terminal_address(block)

    def branch(self, block) -> tuple | None:
        targets = self.targets.get(block)
        if targets is not None:
            return block.instructions[-1].address, *targets

        return None

    def constant_target(self, block):
        """The target a branch on a constant condition always takes, or None"""
        terminal = block.instructions[-1]
        if not all(isinstance(node, CONSTANT_EXPRESSIONS) for node in walk(terminal.condition)):
            return None

        always = constant_truth(self.evaluate(terminal.condition, State()))
        if always is None:
            return None

        return terminal.true_target if always else terminal.false_target

    @classmethod
    def only_copies(cls, block) -> bool:
        return all(isinstance(inst, COPIES) or cls.local_memory_write(inst) for inst in block.instructions)

    @classmethod
    def local_memory_write(cls, inst) -> bool:
        """The memory form of a variable's write, *(&v) = x"""
        return (isinstance(inst, MLILStoreDeref) and isinstance(inst.dest, MLILAddressOf)
                and isinstance(inst.dest.operand, MLILVar))

    def neutral_key(self, key: tuple) -> tuple:
        return self.neutral_of.get(key[1], key) if key[0] == 'name' else key

    def key(self, var: MLILVariable) -> tuple:
        name = var.name
        if name in self.register_of:
            return ('reg', self.register_of[name])
        if name in self.parameter_of:
            return ('param', self.parameter_of[name])

        split = SPLIT_SUFFIX.search(name)
        if split is not None:
            if name not in self.neutral_of:
                self.neutral_of[name] = self.key(MLILVariable(name[:split.start()], var.slot_index))
            return ('name', name)

        match = PARAMETER_NAME.match(name)
        if match is not None:
            return ('param', int(match.group(1)))
        if var.slot_index != UNASSIGNED_SLOT_INDEX:
            return ('stack', var.slot_index)
        match = STACK_NAME.match(name)
        if match is not None:
            return ('stack', int(match.group(1)))

        return ('name', name)       # a local minted by a pass

    def read(self, var: MLILVariable, state: State) -> tuple:
        key = self.key(var)
        if key[0] == 'param':
            return state.get(key, key)
        if key[0] == 'reg':
            return state.register(key[1])

        return state.get(key, ('undef', self.neutral_key(key)))

    def evaluate(self, expr, state: State) -> tuple:
        if isinstance(expr, MLILConst):
            return const(expr.value)
        if isinstance(expr, MLILVar):
            return self.read(expr.var, state)
        if isinstance(expr, MLILLoadReg):
            return state.register(expr.index)
        if isinstance(expr, MLILLoadGlobal):
            return state.global_value(expr.index)
        if isinstance(expr, MLILDeref):
            # The memory form of a variable's read, *(&v), reads v
            if isinstance(expr.operand, MLILAddressOf) and isinstance(expr.operand.operand, MLILVar):
                return self.read(expr.operand.operand.var, state)
            return ('deref', self.evaluate(expr.operand, state), state.get(MEMORY_EPOCH, ENTRY))
        if isinstance(expr, MLILAddressOf):
            if isinstance(expr.operand, MLILVar):
                return ('address', self.neutral_key(self.key(expr.operand.var)))
            return ('address', self.evaluate(expr.operand, state))
        if isinstance(expr, MLILUndef):
            return ('undef', None)
        if isinstance(expr, MLILBinaryOp):
            return op(expr.operation_name, [self.evaluate(expr.lhs, state), self.evaluate(expr.rhs, state)])
        if isinstance(expr, MLILUnaryOp):
            return op(expr.operation_name, [self.evaluate(expr.operand, state)])

        raise RuntimeError(f'no MLIL rule for {type(expr).__name__}')

    def step(self, inst, state: State, facts: Facts) -> list[Effect]:
        address = inst.address
        if isinstance(inst, MLILSetVar):
            key, value = self.key(inst.var), self.evaluate(inst.value, state)
            if key[0] == 'reg':
                state.escape(value, self.address_taken, self.neutral_key)
            state.set(key, value)
        elif isinstance(inst, MLILStoreReg):
            value = self.evaluate(inst.value, state)
            state.escape(value, self.address_taken, self.neutral_key)
            state.set(('reg', inst.index), value)
        elif isinstance(inst, MLILStoreGlobal):
            value = self.evaluate(inst.value, state)
            state.escape(value, self.address_taken, self.neutral_key)
            state.set(('global', inst.index), value)
            return [Effect(address, 'store global', inst.index, (value,))]
        elif isinstance(inst, MLILStoreDeref):
            if self.local_memory_write(inst):
                state.set(self.key(inst.dest.operand.var), self.evaluate(inst.value, state))
                return []
            value = self.evaluate(inst.value, state)
            effect = Effect(address, 'store deref', None, (self.evaluate(inst.dest, state), value))
            state.escape(value, self.address_taken, self.neutral_key)
            state.store_through_pointer(address)
            return [effect]
        elif isinstance(inst, MediumLevelILCall):
            return [self.call(inst, state)]
        elif isinstance(inst, MLILIf):
            facts.branches[address] = Branch(address, self.evaluate(inst.condition, state), inst.true_target.start,
                                             inst.false_target.start)
        elif isinstance(inst, MLILRet):
            value = state.register(RESULT_REGISTER) if inst.value is None else self.evaluate(inst.value, state)
            return [Effect(address, 'return', None, (value,), storage=state.return_registers())]
        elif not isinstance(inst, IGNORED):
            raise RuntimeError(f'no MLIL rule for {type(inst).__name__}')

        return []

    def call(self, inst: MediumLevelILCall, state: State) -> Effect:
        if isinstance(inst, MLILSyscall):
            kind, target = 'syscall', (inst.subsystem, inst.cmd)
        elif isinstance(inst, MLILCallScript):
            kind, target = 'script call', f'{inst.module}.{inst.func}'
        else:
            kind, target = 'call', inst.target

        effect = Effect(inst.address, kind, target, tuple(self.evaluate(arg, state) for arg in inst.args))
        if inst.clobbers_registers:
            pointed = state.reachable_locals(effect.args, self.address_taken, self.neutral_key)
            effect.storage = state.local_values(pointed, self.neutral_key)
            state.clobber(inst.address, pointed)
            state.set(('reg', RESULT_REGISTER), ('call', inst.address))
        if inst.output is not None:
            state.set(self.key(inst.output), ('call', inst.address))
        return effect
