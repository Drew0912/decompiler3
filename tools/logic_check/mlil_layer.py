"""The MLIL side of the evaluation: a variable is the storage it stands for - a register variable the register, a
parameter the parameter, a stack variable its slot; a live range de-SSA split off (`{base}_v{n}`), a variable named
apart within its slot (a sibling scope's local, a box) or a minted local is storage of its own, named like its base
where a loop value needs a name on every layer. A call puts its result in the result register only through its
output, so a read of the register where the MLIL never stored the result differs from the LLIL's"""

import re

from ir.core import reverse_post_order
from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILAddressOf, MLILBinaryOp, MLILCallScript, MLILConst, MLILDebug,
    MLILDeref, MLILGoto, MLILIf, MLILLoadGlobal, MLILLoadReg, MLILNop, MLILRet, MLILSetVar, MLILStoreDeref,
    MLILStoreGlobal, MLILStoreReg, MLILSyscall, MLILUnaryOp, MLILUndef, MLILVar, MLILVariable,
    UNASSIGNED_SLOT_INDEX, mlil_stack_var_name,
)
from .facts import Branch, Effect, Facts
from .post_dominators import back_edges
from .state import MEMORY_EPOCH, State
from .trees import ENTRY, const, constant_truth, op
from .vm_effects import VMEffects

SPLIT_SUFFIX = re.compile(r'_v\d+$')
PARAMETER_NAME = re.compile(r'^arg(\d+)$')
STACK_NAME = re.compile(r'^var_s(\d+)$')
IGNORED = (MLILGoto, MLILDebug, MLILNop)
COPIES = (MLILSetVar, MLILStoreReg, *IGNORED)


class MLILStorage:
    """The storage an MLIL function's variables stand for (the module docstring), which HLIL names through too"""

    def __init__(self, func: MediumLevelILFunction):
        self.register_of = {var.name: index for index, var in func.register_vars.items()}
        self.parameter_of = {var.name: position for position, var in enumerate(func.parameters, 1) if var is not None}
        self.base_key: dict[str, tuple] = {}    # own storage's name -> its base's key, filled as key() meets it

    def neutral_key(self, key: tuple) -> tuple:
        return self.base_key.get(key[1], key) if key[0] == 'name' else key

    def key(self, var: MLILVariable) -> tuple:
        name = var.name
        if name in self.register_of:
            return ('reg', self.register_of[name])
        if name in self.parameter_of:
            return ('param', self.parameter_of[name])

        split = SPLIT_SUFFIX.search(name)
        if split is not None:
            if name not in self.base_key:
                self.base_key[name] = self.key(MLILVariable(name[:split.start()], var.slot_index))
            return ('name', name)

        match = PARAMETER_NAME.match(name)
        if match is not None:
            return ('param', int(match.group(1)))
        if var.slot_index != UNASSIGNED_SLOT_INDEX:
            if name != mlil_stack_var_name(var.slot_index):    # named apart within its slot
                self.base_key.setdefault(name, ('stack', var.slot_index))
                return ('name', name)
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


class MLILLayer(MLILStorage):
    """The MLIL's graph as written, or with hlil_view as HLIL structures it (against HLIL): a branch on a decided
    condition is a jump to the target it always takes (HLIL folds a loop's constant test, and the constant operand of a
    split && or ||, so the arm it never reaches is dead), and a block holding only
    jumps, line markers and nops, a loop's header aside, passes control on to where it leads (the converter skips such
    a block, so HLIL joins arms where they lead)"""

    OWN_STORAGE_NAMES = True        # a split range, a variable named apart within its slot or a minted local
    VM_EFFECTS        = VMEffects   # the effects of its engine's VM

    def __init__(self, func: MediumLevelILFunction, *, hlil_view: bool = False):
        super().__init__(func)
        self.vm = self.VM_EFFECTS(self.neutral_key)     # before follow_constant_branches evaluates a condition
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

    def follow_constant_branches(self):
        for block in list(self.targets):
            target = self.constant_target(block)
            if target is not None:
                self.edges[block] = [target]
                del self.targets[block]

    def pass_empty_blocks(self):
        order = reverse_post_order(self.entry, self.edges.__getitem__)
        headers = {header for _, header in back_edges(order, self.edges.__getitem__)}
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
        """The target a branch whose condition is decided always takes, or None: a constant, or an && / || with a
        decisive constant operand (`x && 0`), as HLIL folds each operand of a split condition"""
        terminal = block.instructions[-1]
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
        return isinstance(inst, MLILStoreDeref) and cls.memory_form_variable(inst.dest) is not None

    @classmethod
    def memory_form_variable(cls, pointer) -> MLILVariable | None:
        """v of a pointer &v, the memory form's: *(&v) reads v, *(&v) = x writes it"""
        if isinstance(pointer, MLILAddressOf) and isinstance(pointer.operand, MLILVar):
            return pointer.operand.var

        return None

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
            var = self.memory_form_variable(expr.operand)
            if var is not None:
                return self.read(var, state)
            return ('deref', self.evaluate(expr.operand, state), state.get(MEMORY_EPOCH, ENTRY))
        if isinstance(expr, MLILAddressOf):
            if isinstance(expr.operand, MLILVar):
                return self.vm.address_of(self.key(expr.operand.var))
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
            self.vm.write(state, self.key(inst.var), self.evaluate(inst.value, state))
        elif isinstance(inst, MLILStoreReg):
            self.vm.write(state, ('reg', inst.index), self.evaluate(inst.value, state))
        elif isinstance(inst, MLILStoreGlobal):
            return [self.vm.store_global(state, address, inst.index, self.evaluate(inst.value, state))]
        elif isinstance(inst, MLILStoreDeref):
            if self.local_memory_write(inst):
                state.set(self.key(self.memory_form_variable(inst.dest)), self.evaluate(inst.value, state))
                return []
            value = self.evaluate(inst.value, state)
            return [self.vm.store_deref(state, address, self.evaluate(inst.dest, state), value)]
        elif isinstance(inst, MediumLevelILCall):
            return [self.call(inst, state)]
        elif isinstance(inst, MLILIf):
            facts.branches[address] = Branch(address, self.evaluate(inst.condition, state), inst.true_target.start,
                                             inst.false_target.start)
        elif isinstance(inst, MLILRet):
            return [self.vm.ret(state, address, None if inst.value is None else self.evaluate(inst.value, state))]
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

        delivers = inst.output is not None and self.key(inst.output) == ('reg', self.vm.RESULT_REGISTER)
        effect = self.vm.call(state, inst.address, kind, target, tuple(self.evaluate(arg, state) for arg in inst.args),
                              clobbers=inst.clobbers_registers, delivers_result=delivers)
        if inst.output is not None:
            state.set(self.key(inst.output), ('call', inst.address))
        return effect
