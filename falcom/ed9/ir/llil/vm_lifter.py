"""ED9 VM bytecode → Falcom LLIL lifter"""

from dataclasses import dataclass
from typing import *

from ir.llil.llil import *
from ir.core import IRParameter

from ...disasm import *
from .llil_builder import *
from ...parser import *

if TYPE_CHECKING:
    from ...parser.scp import *


@dataclass
class LiftResult:
    """Helper container with both Function metadata and its lifted LLIL."""

    function: Function
    llil: LowLevelILFunction


class ED9VMLifter:
    """Lift ED9 VM bytecode (disassembled) into Falcom LLIL."""

    def __init__(
        self,
        *,
        parser: ScpParser,
    ) -> None:
        if parser is None:
            raise ValueError('ED9VMLifter requires a parser instance')
        self._parser = parser

    # ----------------------------------------------------------------- public --
    def lift_function(self, func: Function) -> LowLevelILFunction:
        if func.entry_block is None:
            raise ValueError(f'Function {func.name} has no entry block')

        builder = FalcomVMBuilder()
        ir_params = self._convert_params(func.params)
        builder.create_function(func.name, func.offset, ir_params, is_common_func=func.is_common_func)

        lift_blocks = self._compute_rpo(func.entry_block)
        layout_blocks = sorted(lift_blocks, key = lambda b: b.offset)   # preserve address-order block indices

        llil_blocks: Dict[int, LowLevelILBasicBlock] = {}
        for block in layout_blocks:
            llil_blocks[block.offset] = builder.create_basic_block(block.offset, block.name)

        block_map = {block.offset: block for block in layout_blocks}

        for block in lift_blocks:
            builder.begin_block(llil_blocks[block.offset])
            for inst in block.instructions:
                # Set current SCP instruction address for LLIL address tracking
                builder.set_current_address(inst.offset)
                self._translate_instruction(builder, inst, block, block_map, llil_blocks)

        return builder.finalize()

    def lift_functions(self, functions: Iterable[Function]) -> list[LiftResult]:
        results: list[LiftResult] = []
        for func in functions:
            results.append(LiftResult(function = func, llil = self.lift_function(func)))
        return results

    # --------------------------------------------------------------- helpers --
    def _convert_params(self, params: list[FunctionParam]) -> list[IRParameter]:
        '''Convert Falcom FunctionParam to generic IRParameter'''
        result = []
        for i, param in enumerate(params):
            name = f'arg{i + 1}'
            type_name = param.type.get_python_type()
            default_value = param.default_value.value if param.default_value else None
            result.append(IRParameter(name, type_name, default_value))
        return result

    def _collect_blocks(self, entry: BasicBlock) -> list[BasicBlock]:
        '''All blocks reachable from entry. Kept separate from lift_function's own traversal for
        external callers (e.g. tools/ir_line_order_report.py) that just want the reachable set.'''
        return self._compute_rpo(entry)

    def _compute_rpo(self, entry: BasicBlock) -> list[BasicBlock]:
        '''Reverse post-order over succs.
        In the returned order, every non-entry block follows at least one predecessor.'''
        visited: set[int] = set()
        postorder: list[BasicBlock] = []
        stack: list[tuple[BasicBlock, bool]] = [(entry, False)]

        while stack:
            block, processed = stack.pop()

            if processed:
                postorder.append(block)
                continue

            if block.offset in visited:
                continue

            visited.add(block.offset)
            stack.append((block, True))

            for succ in reversed(block.succs):
                if succ.offset not in visited:
                    stack.append((succ, False))

        return list(reversed(postorder))

    def _translate_instruction(
        self,
        builder: FalcomVMBuilder,
        inst: Instruction,
        block: BasicBlock,
        block_map: Dict[int, BasicBlock],
        llil_blocks: Dict[int, LowLevelILBasicBlock],
    ) -> None:
        opcode = ED9Opcode(inst.opcode)

        match opcode:
            case ED9Opcode.PUSH_INT:
                builder.push_int(int(inst.operands[0].value))

            case ED9Opcode.PUSH_FLOAT:
                builder.push(builder.const_float(inst.operands[0].value))

            case ED9Opcode.PUSH_STR:
                builder.push_str(str(inst.operands[0].value))

            case ED9Opcode.PUSH_RAW:
                builder.push_raw(int(inst.operands[0].value))

            case ED9Opcode.PUSH_CURRENT_FUNC_ID:
                builder.push_func_id()

            case ED9Opcode.PUSH_RET_ADDR:
                target = self._require_block(inst.operands[0].value, block_map, llil_blocks)
                builder.push_ret_addr(target)

            case ED9Opcode.PUSH_CALLER_FRAME:
                target = self._require_block(inst.operands[0].value, block_map, llil_blocks)
                builder.push_caller_frame(target)

            case ED9Opcode.LOAD_STACK:
                builder.load_stack(int(inst.operands[0].value))

            case ED9Opcode.LOAD_STACK_DEREF:
                builder.load_stack_deref(int(inst.operands[0].value))

            case ED9Opcode.PUSH_STACK_OFFSET:
                builder.push_stack_addr(int(inst.operands[0].value))

            case ED9Opcode.POP_TO:
                builder.pop_to(int(inst.operands[0].value))

            case ED9Opcode.POP_TO_DEREF:
                builder.pop_to_deref(int(inst.operands[0].value))

            case ED9Opcode.POP:
                pop_size = int(inst.operands[0].value) if inst.operands else 0
                builder.pop_bytes(pop_size)

            case ED9Opcode.GET_REG:
                builder.get_reg(int(inst.operands[0].value))

            case ED9Opcode.SET_REG:
                builder.set_reg(int(inst.operands[0].value))

            case ED9Opcode.LOAD_GLOBAL:
                builder.load_global(int(inst.operands[0].value))

            case ED9Opcode.SET_GLOBAL:
                builder.set_global(int(inst.operands[0].value))

            case (
                ED9Opcode.ADD |
                ED9Opcode.SUB |
                ED9Opcode.MUL |
                ED9Opcode.DIV |
                ED9Opcode.MOD |
                ED9Opcode.EQ |
                ED9Opcode.NE |
                ED9Opcode.GT |
                ED9Opcode.GE |
                ED9Opcode.LT |
                ED9Opcode.LE |
                ED9Opcode.BITWISE_AND |
                ED9Opcode.BITWISE_OR |
                ED9Opcode.LOGICAL_AND |
                ED9Opcode.LOGICAL_OR
            ):
                self._emit_binary_op(builder, opcode)

            case ED9Opcode.NEG:
                builder.neg()

            case ED9Opcode.NOT:
                builder.bitwise_not()

            case ED9Opcode.EZ:
                builder.test_zero()

            case ED9Opcode.JMP:
                target = self._require_block(inst.operands[0].value, block_map, llil_blocks)
                builder.jmp(target)

            case ED9Opcode.POP_JMP_ZERO:
                true_block = self._branch_target(block.true_succs, llil_blocks)
                false_block = self._branch_target(block.false_succs, llil_blocks)

                builder.pop_jmp_zero(true_block, false_block)

            case ED9Opcode.POP_JMP_NOT_ZERO:
                true_block = self._branch_target(block.true_succs, llil_blocks)
                false_block = self._branch_target(block.false_succs, llil_blocks)

                builder.pop_jmp_not_zero(true_block, false_block)

            case ED9Opcode.CALL:
                func_id = int(inst.operands[0].value)
                builder.call(self._resolve_call_target(func_id))

            case ED9Opcode.CALL_SCRIPT:
                module = self._must_str(inst.operands[0].value)
                func_name = self._must_str(inst.operands[1].value)
                argc = int(inst.operands[2].value)
                builder.call_script(module, func_name, argc)

            case ED9Opcode.CALL_SCRIPT_NO_RETURN:
                module = self._must_str(inst.operands[0].value)
                func_name = self._must_str(inst.operands[1].value)
                argc = int(inst.operands[2].value)
                builder.call_script_no_return(module, func_name, argc)

            case ED9Opcode.SYSCALL:
                subsystem = int(inst.operands[0].value)
                cmd = int(inst.operands[1].value)
                argc = int(inst.operands[2].value)
                builder.syscall(subsystem, cmd, argc)

            case ED9Opcode.DEBUG_SET_LINENO:
                builder.debug_line(int(inst.operands[0].value))

            case ED9Opcode.DEBUG_LOG:
                builder.debug_log(int(inst.operands[0].value))

            case ED9Opcode.RETURN:
                builder.ret()

            case _:
                raise NotImplementedError(f'Unhandled opcode: {opcode.name} (0x{opcode.value:02X})')

    def _emit_binary_op(self, builder: FalcomVMBuilder, opcode: ED9Opcode) -> None:
        mapping = {
            ED9Opcode.ADD: builder.add,
            ED9Opcode.SUB: builder.sub,
            ED9Opcode.MUL: builder.mul,
            ED9Opcode.DIV: builder.div,
            ED9Opcode.MOD: builder.mod,
            ED9Opcode.EQ: builder.eq,
            ED9Opcode.NE: builder.ne,
            ED9Opcode.GT: builder.gt,
            ED9Opcode.GE: builder.ge,
            ED9Opcode.LT: builder.lt,
            ED9Opcode.LE: builder.le,
            ED9Opcode.BITWISE_AND: builder.bitwise_and,
            ED9Opcode.BITWISE_OR: builder.bitwise_or,
            ED9Opcode.LOGICAL_AND: builder.logical_and,
            ED9Opcode.LOGICAL_OR: builder.logical_or,
        }
        mapping[opcode]()

    def _require_block(
        self,
        offset: int,
        block_map: Dict[int, BasicBlock],
        llil_blocks: Dict[int, LowLevelILBasicBlock],
    ) -> LowLevelILBasicBlock:
        block = block_map.get(offset)
        if block is None:
            raise KeyError(f'No basic block at offset 0x{offset:08X}')
        return llil_blocks[block.offset]

    def _branch_target(
        self,
        candidates: list[BasicBlock],
        llil_blocks: Dict[int, LowLevelILBasicBlock],
    ) -> LowLevelILFunction.BasicBlock:
        if candidates:
            return llil_blocks[candidates[0].offset]

        raise RuntimeError('Missing branch target while lifting')

    def _resolve_call_target(self, func_id: int) -> str:
        return self._parser.get_func_name_from_func_id(func_id)

    def _must_str(self, value: ScpValue) -> str:
        if not isinstance(value, ScpValue):
            raise TypeError(f'Expected ScpValue, got {type(value)}')

        if value.type != ScpValue.Type.String:
            raise TypeError(f'CALL_SCRIPT expects string ScpValue, got {value.type}')

        return str(value.value)
