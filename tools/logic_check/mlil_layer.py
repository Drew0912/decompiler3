"""The MLIL side of the evaluation: a variable is the storage it stands for - a register variable the register, a
parameter the parameter, a stack variable its slot; a live range de-SSA split off (`{base}_v{n}`) or a minted local is
storage of its own, named like its base where a loop value needs a name on every layer"""

import re

from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILAddressOf, MLILBinaryOp, MLILCallScript, MLILConst, MLILDebug,
    MLILDeref, MLILGoto, MLILIf, MLILLoadGlobal, MLILLoadReg, MLILNop, MLILRet, MLILSetVar, MLILStoreDeref,
    MLILStoreGlobal, MLILStoreReg, MLILSyscall, MLILUnaryOp, MLILUndef, MLILVar, MLILVariable,
    UNASSIGNED_SLOT_INDEX, walk,
)
from .evaluation import Branch, Effect, Facts
from .state import MEMORY_EPOCH, RESULT_REGISTER, State
from .trees import ENTRY, const, op

SPLIT_SUFFIX = re.compile(r'_v\d+$')
PARAMETER_NAME = re.compile(r'^arg(\d+)$')
STACK_NAME = re.compile(r'^var_s(\d+)$')
IGNORED = (MLILGoto, MLILDebug, MLILNop)


class MLILLayer:
    OWN_STORAGE_NAMES = True        # a split range or a minted local

    def __init__(self, func: MediumLevelILFunction):
        self.func = func
        self.entry = func.basic_blocks[0]
        self.register_of = {var.name: index for index, var in func.register_vars.items()}
        self.parameter_of = {var.name: position for position, var in enumerate(func.parameters, 1) if var is not None}
        self.neutral_of: dict[str, tuple] = {}
        self.address_taken = set()
        for inst in func.iter_instructions():
            for node in walk(inst):
                if isinstance(node, MLILAddressOf) and isinstance(node.operand, MLILVar):
                    self.address_taken.add(self.key(node.operand.var))

    @classmethod
    def successors(cls, block) -> list:
        return block.outgoing_edges

    @classmethod
    def predecessors(cls, block) -> list:
        return block.incoming_edges

    @classmethod
    def terminal_address(cls, block) -> int:
        return block.instructions[-1].address

    @classmethod
    def branch(cls, block) -> tuple | None:
        terminal = block.instructions[-1]
        if isinstance(terminal, MLILIf):
            return terminal.address, terminal.true_target, terminal.false_target

        return None

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
            state.set(self.key(inst.var), self.evaluate(inst.value, state))
        elif isinstance(inst, MLILStoreReg):
            state.set(('reg', inst.index), self.evaluate(inst.value, state))
        elif isinstance(inst, MLILStoreGlobal):
            value = self.evaluate(inst.value, state)
            state.set(('global', inst.index), value)
            return [Effect(address, 'store global', inst.index, (value,))]
        elif isinstance(inst, MLILStoreDeref):
            # The memory form of a variable's write, *(&v) = x, writes v
            if isinstance(inst.dest, MLILAddressOf) and isinstance(inst.dest.operand, MLILVar):
                state.set(self.key(inst.dest.operand.var), self.evaluate(inst.value, state))
                return []
            effect = Effect(address, 'store deref', None,
                            (self.evaluate(inst.dest, state), self.evaluate(inst.value, state)))
            state.clobber(address, self.address_taken, registers=False, globals_=False)
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
            effect.storage = state.pointee_values(effect.args, self.address_taken, self.neutral_key)
            state.clobber(inst.address, self.address_taken)
            state.set(('reg', RESULT_REGISTER), ('call', inst.address))
        if inst.output is not None:
            state.set(self.key(inst.output), ('call', inst.address))
        return effect
