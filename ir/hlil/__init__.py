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

    # Operator semantics (language-neutral)
    'COMPARISON_OPS',
    'BOOLEAN_BINARY_OPS',
    'NEGATED_COMPARISON_OP',
    'DE_MORGAN_OP',
    'is_boolean_expr',
    'negate_condition',

    # C-family syntax
    'BINARY_OP_STR',
    'UNARY_OP_STR',
    'BINARY_OP_PRECEDENCE',
    'NON_ASSOCIATIVE_OPS',
    'needs_parentheses',

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
    'HLILDeref',
    'HLILCall',
    'HLILSyscall',
    'HLILExternCall',

    # Control flow
    'HLILBlock',
    'HLILIf',
    'HLILWhile',
    'HLILDoWhile',
    'HLILSwitch',
    'HLILSwitchCase',
    'HLILBreak',
    'HLILContinue',
    'HLILReturn',
    'TERMINAL_STATEMENTS',

    # Statements
    'HLILAssign',
    'HLILExprStmt',
    'HLILComment',

    # Shape helpers
    'split_else_if_arm',
    'unwrap_address_taken_var',
    'sub_blocks',
    'contains_bare_break',

    # Function
    'HighLevelILFunction',

    # Formatter
    'HLILFormatter',

    # Converter
    'convert_mlil_to_hlil',

    # Passes
    'MLILToHLILPass',
    'ControlFlowOptimizationPass',
    'LoopRecoveryPass',
    'CommonReturnExtractionPass',
    'DeadCodeEliminationPass',
    'BranchOrderNormalizationPass',
]
