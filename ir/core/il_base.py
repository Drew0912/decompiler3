'''Base IL traits for LLIL, MLIL, HLIL'''

from abc import ABC


UNASSIGNED_INST_INDEX = -1   # Index before one is assigned (inst_index, llil_index, mlil_index)


class ILInstruction(ABC):
    '''Base class for all IL instructions'''
    pass


class ControlFlow(ILInstruction):
    '''Control flow instruction trait'''
    pass


class Terminal(ControlFlow):
    '''Terminal control flow instruction trait'''
    pass


class Constant(ILInstruction):
    '''Constant value expression trait'''
    pass


class BinaryOperation(ILInstruction):
    '''Binary operation trait'''
    pass


class UnaryOperation(ILInstruction):
    '''Unary operation trait'''
    pass


class IRParameter:
    '''Function parameter with type and default value'''

    def __init__(self, name: str, type_name: str = None, default_value = None):
        self.name = name
        self.type_name = type_name  # Type as string (e.g. 'int', 'str', 'float')
        self.default_value = default_value

    def __repr__(self):
        if self.default_value is not None:
            return f'IRParameter({self.name!r}, {self.type_name!r}, {self.default_value!r})'
        elif self.type_name:
            return f'IRParameter({self.name!r}, {self.type_name!r})'
        else:
            return f'IRParameter({self.name!r})'
