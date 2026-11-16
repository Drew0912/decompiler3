"""The SSA path's MLIL function and its builder: VM registers and globals modelled as variables, the VM's rules for
them (a VM's subclass gives them), and the types its type pass infers"""

from ir.core import IRParameter
from ir.mlil.mlil import MediumLevelILCall, MediumLevelILFunction, MLILVariable
from ir.mlil.mlil_builder import MLILBuilder
from .mlil_types import MLILType


# === Naming Utilities ===

def mlil_reg_var_name(reg_index: int) -> str:
    """Generate register variable name (reg0, reg1, ...)"""
    return f'reg{reg_index}'


def mlil_global_var_name(global_index: int) -> str:
    """Generate global variable name (global0, global1, ...)"""
    return f'global{global_index}'


# === Function ===

class MediumLevelILFunctionSSA(MediumLevelILFunction):
    """The SSA path's MLIL function: VM registers and globals modelled as variables, which its passes track like any
    other value, and the types its type pass infers, by variable name. A VM's subclass gives the rules for the
    registers and globals: what a call may change, what a return leaves"""

    def __init__(self, name: str, start_addr: int = 0, params: list[IRParameter] | None = None):
        super().__init__(name, start_addr, params)
        self.register_vars: dict[int, MLILVariable] = {}  # VM register index -> variable
        self.global_vars: dict[int, MLILVariable] = {}  # Global var table index -> variable
        self.var_types: dict[str, MLILType] = {}  # Variable name -> inferred type (SSATypeInferencePass)

    def get_or_create_register_var(self, reg_index: int) -> MLILVariable:
        """Get existing register variable or create new one

        VM registers are modelled as variables so the SSA passes track them like
        any other value. Calls define the result register; the VM's call rule says
        which others they may change.
        """
        if reg_index not in self.register_vars:
            self.register_vars[reg_index] = self.get_or_create_local(mlil_reg_var_name(reg_index))

        return self.register_vars[reg_index]

    def is_register_var(self, var: MLILVariable) -> bool:
        return var in self.register_vars.values()

    def register_index_of(self, var: MLILVariable) -> int | None:
        """VM register index of a variable, or None if it does not model a register"""
        for index, register_var in self.register_vars.items():
            if register_var == var:
                return index

        return None

    def get_or_create_global_var(self, global_index: int) -> MLILVariable:
        """Get existing global variable or create new one

        Unlike registers/locals, global variables are kept out of self.locals - they are
        script-wide storage, not something that belongs in a locals-derived variable listing
        """
        if global_index not in self.global_vars:
            self.global_vars[global_index] = MLILVariable(mlil_global_var_name(global_index))

        return self.global_vars[global_index]

    def is_global_var(self, var: MLILVariable) -> bool:
        return var in self.global_vars.values()

    def global_index_of(self, var: MLILVariable) -> int | None:
        """Global var table index of a variable, or None if it does not model a global"""
        for index, global_var in self.global_vars.items():
            if global_var == var:
                return index

        return None

    # === The VM's rules ===

    def call_may_clobber(self, call: MediumLevelILCall, var: MLILVariable) -> bool:
        """Whether call may change var: only a register's or a global's model can change, and the VM's call rule says
        which of them"""
        reg_index = self.register_index_of(var)
        if reg_index is not None:
            return self.call_may_change_register(call, reg_index)

        global_index = self.global_index_of(var)
        return global_index is not None and self.call_may_change_global(call, global_index)

    def call_may_change_register(self, call: MediumLevelILCall, reg_index: int) -> bool:
        """Whether call may change VM register reg_index: the VM's call rule"""
        raise NotImplementedError(f'{type(self).__name__} gives no call rule')

    def call_may_change_global(self, call: MediumLevelILCall, global_index: int) -> bool:
        """Whether call may change global global_index: the VM's call rule"""
        raise NotImplementedError(f'{type(self).__name__} gives no call rule')

    def return_leaves_register(self, reg_index: int) -> bool:
        """Whether a return leaves VM register reg_index holding what the function wrote, for its caller to read: the
        VM's return rule"""
        raise NotImplementedError(f'{type(self).__name__} gives no return rule')


# === Builder ===

class MLILBuilderSSA(MLILBuilder):
    """The SSA path's builder: its function models the VM registers as variables"""

    def __init__(self, function_class: type[MediumLevelILFunctionSSA]):
        super().__init__(function_class)

    def get_or_create_register_var(self, reg_index: int) -> MLILVariable:
        """Get or create the variable modelling a VM register"""
        return self.function.get_or_create_register_var(reg_index)
