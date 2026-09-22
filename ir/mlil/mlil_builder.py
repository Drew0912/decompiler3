'''MLIL Builder - Helper for constructing MLIL functions'''

from typing import Optional, Union, List, TYPE_CHECKING

from .mlil import *

if TYPE_CHECKING:
    from ir.core import IRParameter


class MLILBuilder:
    '''Builder for constructing MLIL functions'''

    def __init__(self):
        self.function: Optional[MediumLevelILFunction] = None
        self.current_block: Optional[MediumLevelILBasicBlock] = None
        self._inst_counter = 0  # For generating unique inst_index
        self._current_address = 0  # Source SCP address for current instruction

    def set_current_address(self, address: int):
        '''Set source address for subsequent instructions'''
        self._current_address = address

    # === Function Management ===

    def create_function(self, name: str, start_addr: int = 0, params: List['IRParameter'] = None, *, is_common_func: bool = False):
        '''Create MLIL function'''
        if self.function is not None:
            raise RuntimeError('Function already created')
        self.function = MediumLevelILFunction(name, start_addr, params, is_common_func = is_common_func)

    def finalize(self) -> MediumLevelILFunction:
        '''Finalize and return the constructed function'''
        if self.function is None:
            raise RuntimeError('No function created')

        # Fill in missing parameters (unused params not created during translation)
        source_params = self.function.source_params
        # First extend to full length
        while len(self.function.parameters) < len(source_params):
            self.function.parameters.append(None)
        # Then fill any None slots using source param info
        for i, src_param in enumerate(source_params):
            if self.function.parameters[i] is None:
                self.function.parameters[i] = MLILVariable(src_param.name)

        # Verify all blocks have terminal instructions
        for block in self.function.basic_blocks:
            if not block.has_terminal:
                raise RuntimeError(
                    f'Block {block.label} does not have a terminal instruction'
                )

        return self.function

    # === Block Management ===

    def create_block(self, start: int = 0, label: str = None) -> MediumLevelILBasicBlock:
        '''Create a new basic block and add to function'''
        if self.function is None:
            raise RuntimeError('No function created')

        block = self.function.create_block(start, label)
        return block

    def set_current_block(self, block: MediumLevelILBasicBlock):
        '''Set the current block for instruction insertion'''
        if block not in self.function.basic_blocks:
            raise RuntimeError(f'Block {block} not in function')
        self.current_block = block

    def add_instruction(self, inst: MediumLevelILInstruction):
        '''Add instruction to current block'''
        if self.current_block is None:
            raise RuntimeError('No current block set')

        # Assign instruction index and address
        inst.inst_index = self._inst_counter
        inst.address = self._current_address
        self._inst_counter += 1

        # Add to block
        self.current_block.add_instruction(inst)

        # Register with function
        self.function.register_instruction(self.current_block, inst)

    # === Variable Management ===

    def get_or_create_parameter(self, param_index: int, name: str) -> MLILVariable:
        '''Get or create a parameter (1-based index)'''
        if self.function is None:
            raise RuntimeError('No function created')
        return self.function.get_or_create_parameter(param_index, name)

    def get_or_create_local(self, name: str, slot_index: int = UNASSIGNED_SLOT_INDEX) -> MLILVariable:
        '''Get or create a local variable'''
        if self.function is None:
            raise RuntimeError('No function created')
        return self.function.get_or_create_local(name, slot_index)

    def get_or_create_register_var(self, reg_index: int) -> MLILVariable:
        '''Get or create the variable modelling a VM register'''
        if self.function is None:
            raise RuntimeError('No function created')
        return self.function.get_or_create_register_var(reg_index)

    # === Constants ===

    def const_int(self, value: int, is_hex: bool = False) -> MLILConst:
        '''Create integer constant'''
        return MLILConst(value, is_hex)

    def const_float(self, value: float) -> MLILConst:
        '''Create float constant'''
        return MLILConst(value, False)

    def const_str(self, value: str) -> MLILConst:
        '''Create string constant'''
        return MLILConst(value, False)

    # === Variable Operations ===

    def var(self, var: MLILVariable) -> MLILVar:
        '''Load variable value (returns expression, does not add instruction)'''
        return MLILVar(var)

    def set_var(self, var: MLILVariable, value: MediumLevelILInstruction):
        '''Store value to variable (adds instruction)'''
        inst = MLILSetVar(var, value)
        self.add_instruction(inst)

    # === Binary Operations ===

    def add(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILAdd:
        '''Create ADD operation (returns expression, does not add instruction)'''
        return MLILAdd(lhs, rhs)

    def sub(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILSub:
        '''Create SUB operation'''
        return MLILSub(lhs, rhs)

    def mul(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILMul:
        '''Create MUL operation'''
        return MLILMul(lhs, rhs)

    def div(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILDiv:
        '''Create DIV operation'''
        return MLILDiv(lhs, rhs)

    def mod(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILMod:
        '''Create MOD operation'''
        return MLILMod(lhs, rhs)

    def bitwise_and(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILAnd:
        '''Create bitwise AND operation'''
        return MLILAnd(lhs, rhs)

    def bitwise_or(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILOr:
        '''Create bitwise OR operation'''
        return MLILOr(lhs, rhs)

    def bitwise_xor(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILXor:
        '''Create bitwise XOR operation'''
        return MLILXor(lhs, rhs)

    def shl(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILShl:
        '''Create left shift operation'''
        return MLILShl(lhs, rhs)

    def shr(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILShr:
        '''Create right shift operation'''
        return MLILShr(lhs, rhs)

    def logical_and(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILLogicalAnd:
        '''Create logical AND operation'''
        return MLILLogicalAnd(lhs, rhs)

    def logical_or(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILLogicalOr:
        '''Create logical OR operation'''
        return MLILLogicalOr(lhs, rhs)

    # === Comparison Operations ===

    def eq(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILEq:
        '''Create EQ operation'''
        return MLILEq(lhs, rhs)

    def ne(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILNe:
        '''Create NE operation'''
        return MLILNe(lhs, rhs)

    def lt(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILLt:
        '''Create LT operation'''
        return MLILLt(lhs, rhs)

    def le(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILLe:
        '''Create LE operation'''
        return MLILLe(lhs, rhs)

    def gt(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILGt:
        '''Create GT operation'''
        return MLILGt(lhs, rhs)

    def ge(self, lhs: MediumLevelILInstruction, rhs: MediumLevelILInstruction) -> MLILGe:
        '''Create GE operation'''
        return MLILGe(lhs, rhs)

    # === Unary Operations ===

    def neg(self, operand: MediumLevelILInstruction) -> MLILNeg:
        '''Create NEG operation'''
        return MLILNeg(operand)

    def logical_not(self, operand: MediumLevelILInstruction) -> MLILLogicalNot:
        '''Create logical NOT operation'''
        return MLILLogicalNot(operand)

    def test_zero(self, operand: MediumLevelILInstruction) -> MLILTestZero:
        '''Create TEST_ZERO operation'''
        return MLILTestZero(operand)

    def bitwise_not(self, operand: MediumLevelILInstruction) -> MLILBitwiseNot:
        '''Create bitwise NOT operation (~x)'''
        return MLILBitwiseNot(operand)

    def address_of(self, operand: MediumLevelILInstruction) -> MLILAddressOf:
        '''Create ADDRESS_OF operation (&var)'''
        return MLILAddressOf(operand)

    # === Control Flow ===

    def goto(self, target: MediumLevelILBasicBlock):
        '''Unconditional jump'''
        inst = MLILGoto(target)
        self.add_instruction(inst)
        self.current_block.add_outgoing_edge(target)

    def branch_if(self, condition: MediumLevelILInstruction,
                  true_target: MediumLevelILBasicBlock,
                  false_target: MediumLevelILBasicBlock):
        '''Conditional branch'''
        inst = MLILIf(condition, true_target, false_target)
        self.add_instruction(inst)
        self.current_block.add_outgoing_edge(true_target)
        self.current_block.add_outgoing_edge(false_target)

    def ret(self, value: Optional[MediumLevelILInstruction] = None):
        '''Return from function'''
        inst = MLILRet(value)
        self.add_instruction(inst)

    # === Function Calls ===

    def call(self, target: str, args: list[MediumLevelILInstruction], output: Optional[MLILVariable] = None):
        '''Function call'''
        inst = MLILCall(target, args, output)
        self.add_instruction(inst)

    def syscall(self, subsystem: int, cmd: int, args: list[MediumLevelILInstruction], output: Optional[MLILVariable] = None):
        '''System call'''
        inst = MLILSyscall(subsystem, cmd, args, output)
        self.add_instruction(inst)

    def call_script(self, module: str, func: str, args: list[MediumLevelILInstruction], output: Optional[MLILVariable] = None):
        '''Falcom script call'''
        inst = MLILCallScript(module, func, args, output)
        self.add_instruction(inst)

    # === Globals ===

    def load_global(self, index: int) -> MLILLoadGlobal:
        '''Load global variable (returns expression)'''
        return MLILLoadGlobal(index)

    def store_global(self, index: int, value: MediumLevelILInstruction):
        '''Store to global variable'''
        inst = MLILStoreGlobal(index, value)
        self.add_instruction(inst)

    # === Registers ===

    def load_reg(self, index: int) -> MLILLoadReg:
        '''Load register (returns expression)'''
        return MLILLoadReg(index)

    def store_reg(self, index: int, value: MediumLevelILInstruction):
        '''Store to register'''
        inst = MLILStoreReg(index, value)
        self.add_instruction(inst)

    # === Pointer Dereference ===

    def deref(self, operand: MediumLevelILInstruction) -> MLILDeref:
        '''Dereference a pointer expression (returns expression)'''
        return MLILDeref(operand)

    def store_deref(self, dest: MediumLevelILInstruction, value: MediumLevelILInstruction):
        '''Store through a pointer expression (*dest = value)'''
        inst = MLILStoreDeref(dest, value)
        self.add_instruction(inst)

    # === Debug ===

    def nop(self):
        '''No operation'''
        inst = MLILNop()
        self.add_instruction(inst)

    def debug(self, debug_type: str, value):
        '''Debug information'''
        inst = MLILDebug(debug_type, value)
        self.add_instruction(inst)
