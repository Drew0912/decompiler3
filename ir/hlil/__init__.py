'''High Level Intermediate Language (HLIL)'''

from .hlil import *
from .hlil_formatter import *
from .mlil_to_hlil import *
from .hlil_passes import *

__all__ = [
    # Types
    'HLILTypeKind',

    # Operators
    'BinaryOp',
    'UnaryOp',
    'BINARY_OP_STR',
    'UNARY_OP_STR',

    # Operations
    'HLILOperation',

    # Base classes
    'HLILInstruction',
    'HLILStatement',
    'HLILExpression',

    # Variables
    'VariableKind',
    'HLILVariable',

    # Expressions
    'HLILVar',
    'HLILConst',
    'HLILBinaryOp',
    'HLILUnaryOp',
    'HLILAddressOf',
    'HLILCall',
    'HLILSyscall',
    'HLILExternCall',

    # Control flow
    'HLILBlock',
    'HLILIf',
    'HLILWhile',
    'HLILDoWhile',
    'HLILFor',
    'HLILSwitch',
    'HLILSwitchCase',
    'HLILBreak',
    'HLILContinue',
    'HLILReturn',

    # Statements
    'HLILAssign',
    'HLILExprStmt',
    'HLILComment',

    # Function
    'HighLevelILFunction',

    # Formatter
    'HLILFormatter',

    # Converter
    'convert_mlil_to_hlil',

    # Passes
    'MLILToHLILPass',
    'CopyPropagationPass',
    'ControlFlowOptimizationPass',
    'LoopRecoveryPass',
    'CommonReturnExtractionPass',
    'DeadCodeEliminationPass',
]
