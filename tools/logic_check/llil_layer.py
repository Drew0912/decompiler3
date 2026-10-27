"""The LLIL side of the evaluation, the trust root: storage is the stack slot, the parameter, the register and the
global; every push, pop and store is followed as written"""

from falcom.ed9.ir.llil.constants import (
    LowLevelILConstFuncId, LowLevelILConstRetAddrBlock, LowLevelILConstScript, LowLevelILConstScriptName,
)
from falcom.ed9.ir.llil.llil_ext import (
    LowLevelILCallScript, LowLevelILCallScriptNoReturn, LowLevelILDebugLog, LowLevelILGlobalLoad,
    LowLevelILGlobalStore,
)
from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.llil.llil import (
    LowLevelILBinaryOp, LowLevelILCall, LowLevelILConst, LowLevelILDebug, LowLevelILFrameAddr, LowLevelILFrameLoad,
    LowLevelILFrameStore, LowLevelILFunction, LowLevelILIf, LowLevelILJmp, LowLevelILLoad, LowLevelILRegLoad,
    LowLevelILRegStore, LowLevelILRet, LowLevelILSpAdd, LowLevelILStackAddr, LowLevelILStackLoad, LowLevelILStackStore,
    LowLevelILStore, LowLevelILSyscall, LowLevelILUnaryOp, WORD_SIZE, walk,
)
from .evaluation import Branch, Effect, Facts
from .state import MEMORY_EPOCH, RESULT_REGISTER, State
from .trees import ENTRY, const, op

FRAME_CONSTANTS = (LowLevelILConstFuncId, LowLevelILConstRetAddrBlock, LowLevelILConstScript, LowLevelILConstScriptName)
IGNORED = (LowLevelILSpAdd, LowLevelILDebug, LowLevelILJmp)
COPIES = (LowLevelILStackStore, LowLevelILFrameStore, LowLevelILRegStore, *IGNORED)


class LLILLayer:
    OWN_STORAGE_NAMES = False       # every key is already the neutral one

    def __init__(self, func: LowLevelILFunction):
        self.func = func
        self.entry = func.get_block_by_addr(func.start_addr)
        self.address_taken = set()
        for block in func.basic_blocks:
            for inst in block.instructions:
                for node in walk(inst):
                    if isinstance(node, LowLevelILStackAddr):
                        self.address_taken.add(('stack', node.slot_index))
                    elif isinstance(node, LowLevelILFrameAddr):
                        self.address_taken.add(('param', self.param_position(node.offset)))

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
        if isinstance(terminal, LowLevelILIf):
            return terminal.address, terminal.true_target, terminal.false_target

        return None

    @classmethod
    def only_copies(cls, block) -> bool:
        return all(isinstance(inst, COPIES) for inst in block.instructions)

    @classmethod
    def neutral_key(cls, key: tuple) -> tuple:
        return key

    def param_position(self, offset: int) -> int:
        """The 1-based parameter in the frame slot at offset: the first parameter is in the highest slot"""
        return self.func.num_params - offset // WORD_SIZE

    def evaluate(self, expr, state: State) -> tuple:
        if isinstance(expr, FRAME_CONSTANTS):
            return ('frame',)
        if isinstance(expr, LowLevelILConst):
            return const(expr.value)
        if isinstance(expr, LowLevelILStackLoad):
            key = ('stack', expr.slot_index)
            return state.get(key, ('undef', key))
        if isinstance(expr, LowLevelILFrameLoad):
            key = ('param', self.param_position(expr.offset))
            return state.get(key, key)
        if isinstance(expr, LowLevelILLoad):
            return ('deref', self.evaluate(expr.src, state), state.get(MEMORY_EPOCH, ENTRY))
        if isinstance(expr, LowLevelILStackAddr):
            return ('address', ('stack', expr.slot_index))
        if isinstance(expr, LowLevelILFrameAddr):
            return ('address', ('param', self.param_position(expr.offset)))
        if isinstance(expr, LowLevelILRegLoad):
            return state.register(expr.reg_index)
        if isinstance(expr, LowLevelILGlobalLoad):
            return state.global_value(expr.index)
        if isinstance(expr, LowLevelILBinaryOp):
            return op(expr.operation_name, [self.evaluate(expr.lhs, state), self.evaluate(expr.rhs, state)])
        if isinstance(expr, LowLevelILUnaryOp):
            return op(expr.operation_name, [self.evaluate(expr.operand, state)])

        raise RuntimeError(f'no LLIL rule for {type(expr).__name__}')

    def step(self, inst, state: State, facts: Facts) -> list[Effect]:
        address = inst.address
        if isinstance(inst, LowLevelILStackStore):
            state.set(('stack', inst.slot_index), self.evaluate(inst.value, state))
        elif isinstance(inst, LowLevelILFrameStore):
            state.set(('param', self.param_position(inst.offset)), self.evaluate(inst.value, state))
        elif isinstance(inst, LowLevelILRegStore):
            value = self.evaluate(inst.value, state)
            state.escape(value, self.address_taken, self.neutral_key)
            state.set(('reg', inst.reg_index), value)
        elif isinstance(inst, LowLevelILGlobalStore):
            value = self.evaluate(inst.value, state)
            state.escape(value, self.address_taken, self.neutral_key)
            state.set(('global', inst.index), value)
            return [Effect(address, 'store global', inst.index, (value,))]
        elif isinstance(inst, LowLevelILStore):
            value = self.evaluate(inst.value, state)
            effect = Effect(address, 'store deref', None, (self.evaluate(inst.dest, state), value))
            state.escape(value, self.address_taken, self.neutral_key)
            state.store_through_pointer(address)
            return [effect]
        elif isinstance(inst, LowLevelILDebugLog):
            # As MLIL translates it: a debug.log call with no output that changes nothing
            return [Effect(address, 'call', DEBUG_LOG_CALL_TARGET, self.arguments(inst, state))]
        elif isinstance(inst, LowLevelILSyscall):
            return [self.call(inst, 'syscall', (inst.subsystem, inst.cmd), state)]
        elif isinstance(inst, LowLevelILCallScriptNoReturn):
            # As MLIL translates it: `return module.func(args)`, the callee's registers passed on to our caller
            return [self.call(inst, 'script call', inst.target, state), self.ret(address, state)]
        elif isinstance(inst, LowLevelILCallScript):
            return [self.call(inst, 'script call', inst.target, state)]
        elif isinstance(inst, LowLevelILCall):
            return [self.call(inst, 'call', inst.target, state)]
        elif isinstance(inst, LowLevelILIf):
            facts.branches[address] = Branch(address, self.evaluate(inst.condition, state), inst.true_target.start,
                                             inst.false_target.start)
        elif isinstance(inst, LowLevelILRet):
            return [self.ret(address, state)]
        elif not isinstance(inst, IGNORED):
            raise RuntimeError(f'no LLIL rule for {type(inst).__name__}')

        return []

    def arguments(self, inst, state: State) -> tuple:
        return tuple(self.evaluate(arg, state) for arg in inst.args)

    def call(self, inst, kind: str, target, state: State) -> Effect:
        args = self.arguments(inst, state)
        return Effect(inst.address, kind, target, args,
                      storage=state.call(inst.address, args, self.address_taken, self.neutral_key))

    @classmethod
    def ret(cls, address: int, state: State) -> Effect:
        return Effect(address, 'return', None, (state.register(RESULT_REGISTER),), storage=state.return_registers())
