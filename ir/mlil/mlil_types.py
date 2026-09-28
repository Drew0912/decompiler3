'''MLIL Type System - Type definitions for type inference'''

from typing import AbstractSet, Optional
from enum import Enum, auto


class MLILTypeKind(Enum):
    '''Type kinds for MLIL variables'''
    UNKNOWN = auto()    # Type not yet determined
    INT = auto()        # Integer (32-bit)
    BOOL = auto()       # Boolean (0 or 1)
    STRING = auto()     # String pointer
    FLOAT = auto()      # Floating point
    POINTER = auto()    # Generic pointer
    VARIANT = auto()    # Multiple possible types (type conflict)
    VOID = auto()       # No value (for functions that don't return)


class MLILType:
    '''Base class for MLIL types'''

    def __init__(self, kind: MLILTypeKind):
        self.kind = kind

    def __eq__(self, other) -> bool:
        if not isinstance(other, MLILType):
            return False
        return self.kind == other.kind

    def __hash__(self) -> int:
        return hash(self.kind)

    def __str__(self) -> str:
        return self.kind.name.lower()

    def __repr__(self) -> str:
        return f'MLILType({self.kind.name})'

    def is_unknown(self) -> bool:
        '''Check if type is unknown'''
        return self.kind == MLILTypeKind.UNKNOWN

    def is_numeric(self) -> bool:
        '''Check if type is numeric (int, float, bool)'''
        return self.kind in (MLILTypeKind.INT, MLILTypeKind.FLOAT, MLILTypeKind.BOOL)

    def is_pointer(self) -> bool:
        '''Check if type is pointer (string, pointer)'''
        return self.kind in (MLILTypeKind.STRING, MLILTypeKind.POINTER)

    @classmethod
    def unknown(cls) -> 'MLILType':
        '''Create unknown type'''
        return MLILType(MLILTypeKind.UNKNOWN)

    @classmethod
    def int_type(cls) -> 'MLILType':
        '''Create int type'''
        return MLILType(MLILTypeKind.INT)

    @classmethod
    def bool_type(cls) -> 'MLILType':
        '''Create bool type'''
        return MLILType(MLILTypeKind.BOOL)

    @classmethod
    def string_type(cls) -> 'MLILType':
        '''Create string type'''
        return MLILType(MLILTypeKind.STRING)

    @classmethod
    def float_type(cls) -> 'MLILType':
        '''Create float type'''
        return MLILType(MLILTypeKind.FLOAT)

    @classmethod
    def pointer_type(cls) -> 'MLILType':
        '''Create generic pointer type'''
        return MLILType(MLILTypeKind.POINTER)

    @classmethod
    def void_type(cls) -> 'MLILType':
        '''Create void type'''
        return MLILType(MLILTypeKind.VOID)


class MLILVariantType(MLILType):
    '''Variant type (a type conflict), identified by its member types'''

    def __init__(self, types: AbstractSet[MLILType]):
        super().__init__(MLILTypeKind.VARIANT)
        self.types = frozenset(types)

    def __eq__(self, other) -> bool:
        return isinstance(other, MLILVariantType) and self.types == other.types

    def __hash__(self) -> int:
        return hash((self.kind, self.types))

    def __str__(self) -> str:
        type_names = ', '.join(str(t) for t in sorted(self.types, key = lambda t: t.kind.value))
        return f'variant<{type_names}>'

    def __repr__(self) -> str:
        return f'MLILVariantType({self.types})'


def unify_types(t1: MLILType, t2: MLILType) -> MLILType:
    '''Unify two types, returning the most specific common type'''
    # Same type
    if t1 == t2:
        return t1

    # Unknown type: use the other type
    if t1.is_unknown():
        return t2

    if t2.is_unknown():
        return t1

    # Bool can be promoted to int
    if t1.kind == MLILTypeKind.BOOL and t2.kind == MLILTypeKind.INT:
        return t2

    if t1.kind == MLILTypeKind.INT and t2.kind == MLILTypeKind.BOOL:
        return t1

    # Variant types: merge
    if isinstance(t1, MLILVariantType) and isinstance(t2, MLILVariantType):
        return MLILVariantType(t1.types | t2.types)

    if isinstance(t1, MLILVariantType):
        return MLILVariantType(t1.types | {t2})

    if isinstance(t2, MLILVariantType):
        return MLILVariantType({t1} | t2.types)

    # Incompatible types: create variant
    return MLILVariantType({t1, t2})


# ============================================================================
# Function Signature Database Interface (Platform-agnostic)
# ============================================================================

class FunctionSignatureDB:
    '''Interface for platform-specific function signature databases'''

    def get_call_return_type(self, target) -> Optional[MLILType]:
        '''Get return type for function call (target can be any type)'''
        return None

    def get_syscall_return_type(self, subsystem: int, cmd: int) -> Optional[MLILType]:
        '''Get return type for syscall (subsystem, cmd)'''
        return None

    def get_script_call_return_type(self, module: str, func: str) -> Optional[MLILType]:
        '''Get return type for script call (module, func)'''
        return None
