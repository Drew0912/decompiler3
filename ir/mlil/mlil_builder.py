"""MLIL Builder - builds an MLIL function: its blocks, variables and statements (expressions are the node classes)"""

from typing import TYPE_CHECKING

from .mlil import *

if TYPE_CHECKING:
    from ir.core import IRParameter


class MLILBuilder:
    """Builder for constructing MLIL functions"""

    def __init__(self):
        self.function: MediumLevelILFunction | None = None
        self.current_block: MediumLevelILBasicBlock | None = None
        self._current_address = 0  # Source SCP address for current instruction
        self._current_llil_index = UNASSIGNED_INST_INDEX

    def set_current_source(self, address: int, llil_index: int):
        """Set the provenance (source address and LLIL instruction) of subsequently added statements"""
        self._current_address = address
        self._current_llil_index = llil_index

    # === Function Management ===

    def create_function(self, name: str, start_addr: int = 0, params: 'list[IRParameter]' = None):
        self.function = MediumLevelILFunction(name, start_addr, params)

    def finalize(self) -> MediumLevelILFunction:
        # Fill in missing parameters (unused params not created during translation)
        source_params = self.function.source_params
        # First extend to full length
        while len(self.function.parameters) < len(source_params):
            self.function.parameters.append(None)
        # Then fill any None slots using source param info
        for i, src_param in enumerate(source_params):
            if self.function.parameters[i] is None:
                self.function.parameters[i] = MLILVariable(src_param.name)

        return self.function

    # === Block Management ===

    def create_block(self, start: int = 0, label: str = None) -> MediumLevelILBasicBlock:
        """Create a new basic block and add to function"""
        return self.function.create_block(start, label)

    def set_current_block(self, block: MediumLevelILBasicBlock):
        """Set the block later statements are added to"""
        self.current_block = block

    def add_instruction(self, inst: MediumLevelILInstruction):
        """Add inst to the current block with the current source (renumber_instructions() numbers it later)"""
        self.stamp(inst)
        self.current_block.add_instruction(inst)

    def stamp(self, node: MediumLevelILInstruction) -> MediumLevelILInstruction:
        """node with the current source: a statement as it is added, an expression as a translator builds it"""
        node.address = self._current_address
        node.llil_index = self._current_llil_index
        return node

    # === Variable Management ===

    def get_or_create_parameter(self, param_index: int, name: str) -> MLILVariable:
        """Get or create a parameter (1-based index)"""
        return self.function.get_or_create_parameter(param_index, name)

    def get_or_create_local(self, name: str, slot_index: int = UNASSIGNED_SLOT_INDEX) -> MLILVariable:
        return self.function.get_or_create_local(name, slot_index)

    def get_or_create_register_var(self, reg_index: int) -> MLILVariable:
        """Get or create the variable modelling a VM register"""
        return self.function.get_or_create_register_var(reg_index)

    # === Statements ===

    def set_var(self, var: MLILVariable, value: MediumLevelILInstruction):
        self.add_instruction(MLILSetVar(var, value))

    def store_global(self, index: int, value: MediumLevelILInstruction):
        self.add_instruction(MLILStoreGlobal(index, value))

    def store_reg(self, index: int, value: MediumLevelILInstruction):
        self.add_instruction(MLILStoreReg(index, value))

    def store_deref(self, dest: MediumLevelILInstruction, value: MediumLevelILInstruction):
        self.add_instruction(MLILStoreDeref(dest, value))

    def debug(self, debug_type: str, value):
        self.add_instruction(MLILDebug(debug_type, value))

    def intrinsic(self, name: str, args: list[MediumLevelILInstruction]):
        self.add_instruction(MLILIntrinsic(name, args))

    # === Control Flow ===

    def goto(self, target: MediumLevelILBasicBlock):
        self.add_instruction(MLILGoto(target))
        self.current_block.add_outgoing_edge(target)

    def branch_if(self, condition: MediumLevelILInstruction,
                  true_target: MediumLevelILBasicBlock,
                  false_target: MediumLevelILBasicBlock):
        self.add_instruction(MLILIf(condition, true_target, false_target))
        self.current_block.add_outgoing_edge(true_target)
        self.current_block.add_outgoing_edge(false_target)

    def ret(self, value: MediumLevelILInstruction | None = None):
        self.add_instruction(MLILRet(value))

    # === Function Calls ===

    def call(self, target: str, args: list[MediumLevelILInstruction], output: MLILVariable | None = None):
        self.add_instruction(MLILCall(target, args, output))

    def syscall(self, subsystem: int, cmd: int, args: list[MediumLevelILInstruction],
                output: MLILVariable | None = None):
        self.add_instruction(MLILSyscall(subsystem, cmd, args, output))

    def call_script(self, module: str, func: str, args: list[MediumLevelILInstruction],
                    output: MLILVariable | None = None):
        self.add_instruction(MLILCallScript(module, func, args, output))
