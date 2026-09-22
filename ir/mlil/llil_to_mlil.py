'''LLIL to MLIL Translator - Stack elimination (core operations only)'''

from typing import Dict, List, Optional

from ir.llil import *
from .mlil import *
from .mlil_builder import *


class LLILToMLILTranslator:
    '''LLIL to MLIL translator (base class)'''

    def __init__(self):
        self.builder = MLILBuilder()
        self.llil_func: Optional[LowLevelILFunction] = None
        self.block_map: Dict[LowLevelILBasicBlock, MediumLevelILBasicBlock] = {}

    def translate(self, llil_func: LowLevelILFunction) -> MediumLevelILFunction:
        '''Translate LLIL function to MLIL'''
        self.llil_func = llil_func

        # Create MLIL function
        self.builder.create_function(llil_func.name, llil_func.start_addr, llil_func.params, is_common_func = llil_func.is_common_func)

        # Create MLIL blocks for each LLIL block
        for llil_block in llil_func.basic_blocks:
            mlil_block = self.builder.create_block(llil_block.start, llil_block.label)
            mlil_block.llil_block = llil_block
            self.block_map[llil_block] = mlil_block

        # Translate each block
        for llil_block in llil_func.basic_blocks:
            mlil_block = self.block_map[llil_block]
            self.builder.set_current_block(mlil_block)
            self._translate_block(llil_block, mlil_block)

        return self.builder.finalize()

    def _translate_block(self, llil_block: LowLevelILBasicBlock, mlil_block: MediumLevelILBasicBlock):
        '''Translate a single LLIL block to MLIL'''
        for llil_inst in llil_block.instructions:
            # Set source address for MLIL instructions
            self.builder.set_current_address(llil_inst.address)
            self._translate_instruction(llil_inst)

    def _translate_instruction(self, llil_inst: LowLevelILInstruction):
        '''Translate LLIL instruction to MLIL'''

        # Stack operations
        if isinstance(llil_inst, LowLevelILStackStore):
            self._translate_stack_store(llil_inst)

        # Frame operations
        elif isinstance(llil_inst, LowLevelILFrameStore):
            self._translate_frame_store(llil_inst)

        # Pointer dereference
        elif isinstance(llil_inst, LowLevelILStore):
            self._translate_store(llil_inst)

        # Control flow
        elif isinstance(llil_inst, LowLevelILJmp):
            target = self.block_map[llil_inst.target]
            self.builder.goto(target)

        elif isinstance(llil_inst, LowLevelILIf):
            condition = self._translate_expr(llil_inst.condition)
            true_target = self.block_map[llil_inst.true_target]
            false_target = self.block_map[llil_inst.false_target]
            self.builder.branch_if(condition, true_target, false_target)

        elif isinstance(llil_inst, LowLevelILRet):
            self.builder.ret()

        elif isinstance(llil_inst, LowLevelILCall):
            self._translate_call(llil_inst)

        # SpAdd - eliminated in MLIL (stack pointer management removed)
        elif isinstance(llil_inst, LowLevelILSpAdd):
            pass

        # Debug
        elif isinstance(llil_inst, LowLevelILDebug):
            self.builder.debug(llil_inst.debug_type, llil_inst.value)

        else:
            # Unknown instruction - must be handled by derived class
            raise NotImplementedError(
                f'Unhandled LLIL instruction type: {type(llil_inst).__name__}. '
                f'This may be an architecture-specific instruction that should be '
                f'handled in a derived translator class.'
            )

    def _translate_stack_store(self, llil_inst: LowLevelILStackStore):
        '''Translate StackStore to SetVar (local variable)'''
        var_name = mlil_stack_var_name(llil_inst.slot_index)
        var = self.builder.get_or_create_local(var_name, llil_inst.slot_index)
        value = self._translate_expr(llil_inst.value)
        self.builder.set_var(var, value)

    def _frame_offset_to_param_index(self, offset: int) -> int:
        '''Frame slot to 1-based parameter index

        Arguments are pushed right-to-left, so the first declared parameter sits in
        the highest frame slot and STACK[fp + 0] holds the last one.
        '''
        return self.llil_func.num_params - offset // WORD_SIZE

    def _translate_frame_store(self, llil_inst: LowLevelILFrameStore):
        '''Translate FrameStore to SetVar (parameter)'''
        param_index = self._frame_offset_to_param_index(llil_inst.offset)
        var_name = mlil_arg_var_name(param_index)
        var = self.builder.get_or_create_parameter(param_index, var_name)
        value = self._translate_expr(llil_inst.value)
        self.builder.set_var(var, value)

    def _translate_store(self, llil_inst: LowLevelILStore):
        '''Translate Store to StoreDeref (*ptr = value)'''
        dest = self._translate_expr(llil_inst.dest)
        value = self._translate_expr(llil_inst.value)
        self.builder.store_deref(dest, value)

    def _call_output(self) -> Optional[MLILVariable]:
        '''Variable a call result is written to (architecture specific, none by default)'''
        return None

    def _translate_call(self, llil_inst: LowLevelILCall):
        '''Translate function call'''
        # Translate arguments
        mlil_args = [self._translate_expr(arg) for arg in llil_inst.args]

        # Generate call (target is always a string)
        self.builder.call(llil_inst.target, mlil_args, self._call_output())

        # Add goto to return target (makes this block terminal)
        # return_target is always a LowLevelILBasicBlock
        return_block = self.block_map[llil_inst.return_target]
        self.builder.goto(return_block)

    def _translate_expr(self, llil_expr: LowLevelILInstruction) -> MediumLevelILInstruction:
        '''Translate LLIL expression to MLIL'''

        # Constants
        if isinstance(llil_expr, LowLevelILConst):
            return MLILConst(llil_expr.value, llil_expr.is_hex)

        # Stack operations → Variables
        elif isinstance(llil_expr, LowLevelILStackLoad):
            var_name = mlil_stack_var_name(llil_expr.slot_index)
            var = self.builder.get_or_create_local(var_name, llil_expr.slot_index)
            return self.builder.var(var)

        elif isinstance(llil_expr, LowLevelILFrameLoad):
            param_index = self._frame_offset_to_param_index(llil_expr.offset)
            var_name = mlil_arg_var_name(param_index)
            var = self.builder.get_or_create_parameter(param_index, var_name)
            return self.builder.var(var)

        elif isinstance(llil_expr, LowLevelILStackAddr):
            # Stack address → address of local variable (&var)
            var_name = mlil_stack_var_name(llil_expr.slot_index)
            var = self.builder.get_or_create_local(var_name, llil_expr.slot_index)
            return self.builder.address_of(self.builder.var(var))

        elif isinstance(llil_expr, LowLevelILFrameAddr):
            # Frame address → address of parameter variable (&argN)
            param_index = self._frame_offset_to_param_index(llil_expr.offset)
            var_name = mlil_arg_var_name(param_index)
            var = self.builder.get_or_create_parameter(param_index, var_name)
            return self.builder.address_of(self.builder.var(var))

        elif isinstance(llil_expr, LowLevelILLoad):
            # Pointer dereference → *ptr
            src = self._translate_expr(llil_expr.src)
            return self.builder.deref(src)

        # Binary operations
        elif isinstance(llil_expr, LowLevelILAdd):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.add(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILSub):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.sub(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILMul):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.mul(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILDiv):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.div(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILMod):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.mod(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILAnd):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.bitwise_and(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILOr):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.bitwise_or(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILLogicalAnd):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.logical_and(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILLogicalOr):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.logical_or(lhs, rhs)

        # Comparison operations
        elif isinstance(llil_expr, LowLevelILEq):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.eq(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILNe):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.ne(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILLt):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.lt(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILLe):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.le(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILGt):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.gt(lhs, rhs)

        elif isinstance(llil_expr, LowLevelILGe):
            lhs = self._translate_expr(llil_expr.lhs)
            rhs = self._translate_expr(llil_expr.rhs)
            return self.builder.ge(lhs, rhs)

        # Unary operations
        elif isinstance(llil_expr, LowLevelILNeg):
            operand = self._translate_expr(llil_expr.operand)
            return self.builder.neg(operand)

        elif isinstance(llil_expr, LowLevelILBitwiseNot):
            operand = self._translate_expr(llil_expr.operand)
            return self.builder.bitwise_not(operand)

        elif isinstance(llil_expr, LowLevelILTestZero):
            operand = self._translate_expr(llil_expr.operand)
            return self.builder.test_zero(operand)

        else:
            # Unknown expression - must be handled by derived class
            raise NotImplementedError(
                f'Unhandled LLIL expression type: {type(llil_expr).__name__}. '
                f'This may be an architecture-specific expression that should be '
                f'handled in a derived translator class.'
            )


def translate_llil_to_mlil(llil_func: LowLevelILFunction) -> MediumLevelILFunction:
    '''Translate LLIL to MLIL (generic translator)'''
    translator = LLILToMLILTranslator()
    return translator.translate(llil_func)
