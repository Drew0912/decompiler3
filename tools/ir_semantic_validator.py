"""
IR Semantic Consistency Validator

Validates semantic consistency across LLIL, MLIL, and HLIL layers by comparing
actual decompiled output from SCP files using CFG-based block matching.

Usage:
    python tools/ir_semantic_validator.py --compare llil mlil test.scp
    python tools/ir_semantic_validator.py --all test.scp
    python tools/ir_semantic_validator.py --batch test.scp
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from itertools import pairwise
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TextIO, Tuple, Union

sys.path.insert(0, str(Path(__file__).parent.parent))

from dc3 import fileio
from dc3.utils import raise_recursion_limit
from ir.core import UNASSIGNED_INST_INDEX
from ir.llil import LowLevelILFunction, LowLevelILInstruction, LowLevelILOperation
from ir.mlil import MediumLevelILFunction, MediumLevelILInstruction, MediumLevelILOperation, MLILLoadGlobal
from ir.hlil import (
    HighLevelILFunction, HLILInstruction, HLILOperation, HLILStatement, HLILCall, HLILSyscall, HLILExternCall,
    HLILUnstructured, HLILVariable, VariableKind, BinaryOp, UnaryOp, expr_children, reachable_statements
)
from falcom.ed9.ir.llil.llil_ext import LowLevelILFalcomOperation, LowLevelILGlobalLoad
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.ir.llil.vm_lifter import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil


# =============================================================================
# Section 1: Enums
# =============================================================================

class OperationKind(Enum):
    """Normalized operation categories for semantic comparison"""

    ARITHMETIC = auto()     # ADD, SUB, MUL, DIV, MOD, NEG
    COMPARISON = auto()     # EQ, NE, LT, LE, GT, GE
    LOGICAL = auto()        # AND, OR, NOT (logical)
    BITWISE = auto()        # AND, OR, XOR, SHL, SHR, NOT (bitwise)
    CALL = auto()           # CALL, SYSCALL, CALL_SCRIPT
    BRANCH = auto()         # JMP, BRANCH, IF, GOTO
    ASSIGN = auto()         # SET_VAR, STACK_STORE, ASSIGN
    LOAD = auto()           # VAR, STACK_LOAD, CONST
    RETURN = auto()         # RET, RETURN
    CONTROL_FLOW = auto()   # BREAK, CONTINUE, WHILE, FOR, IF
    NOP = auto()            # NOP, DEBUG, eliminated ops
    UNKNOWN = auto()        # Unrecognized operations


class ComparisonStatus(Enum):
    """Result of comparing two operations across IR layers"""

    EQUIVALENT = auto()     # Semantically identical
    TRANSFORMED = auto()    # Expected transformation (e.g., STACK_LOAD -> VAR)
    DIFFERENT = auto()      # Semantic difference (potential bug)
    ELIMINATED = auto()     # Source operation optimized away (no target match)
    INLINED = auto()        # Multiple source ops merged into one target op


class IRLayer(Enum):
    """IR layer identifier"""

    LLIL = auto()
    MLIL = auto()
    HLIL = auto()


# =============================================================================
# Section 2: Data Structures
# =============================================================================

# Status display symbols
STATUS_SYMBOLS = {
    ComparisonStatus.EQUIVALENT: "=",
    ComparisonStatus.TRANSFORMED: "~",
    ComparisonStatus.DIFFERENT: "!",
    ComparisonStatus.ELIMINATED: "o",
    ComparisonStatus.INLINED: ">",
}


ProvenanceKey = Tuple[str, int]  # (layer name, instruction index in that layer)


@dataclass
class SourceLocation:
    """Maps IR instruction to original SCP bytecode offset"""

    scp_offset: int = 0
    llil_index: int = UNASSIGNED_INST_INDEX
    mlil_index: int = UNASSIGNED_INST_INDEX

    def provenance_keys(self) -> List[ProvenanceKey]:
        """Instruction indices this location names, tagged by layer so indices of different layers never match"""
        keys = []
        if self.llil_index >= 0:
            keys.append((IRLayer.LLIL.name, self.llil_index))
        if self.mlil_index >= 0:
            keys.append((IRLayer.MLIL.name, self.mlil_index))
        return keys


@dataclass
class SemanticOperand:
    """Normalized operand representation for comparison"""

    kind: str               # 'const', 'var', 'reg', 'global', 'expr'
    value: Any = None       # Actual value or identifier

    @property
    def signature(self) -> str:
        """kind:value, as fingerprints and effect keys spell an operand"""
        return f"{self.kind}:{self.value}"

    def __str__(self) -> str:
        if self.kind == 'const':
            return repr(self.value)
        elif self.kind == 'var':
            return str(self.value)
        else:
            return f"{self.kind}:{self.value}"


@dataclass
class SemanticOperation:
    """Normalized operation for cross-layer comparison"""

    kind: OperationKind
    operator: str           # Specific operator (ADD, SUB, EQ, etc.)
    operands: List[SemanticOperand] = field(default_factory=list)
    result: Optional[SemanticOperand] = None
    source_location: SourceLocation = field(default_factory=SourceLocation)

    @property
    def provenance_keys(self) -> List[ProvenanceKey]:
        return self.source_location.provenance_keys()

    def __str__(self) -> str:
        ops_str = ", ".join(str(op) for op in self.operands)
        result_str = f" -> {self.result}" if self.result else ""
        return f"{self.operator}({ops_str}){result_str}"


@dataclass
class ComparisonResult:
    """Result of comparing two operations"""

    status: ComparisonStatus
    source_layer: IRLayer
    target_layer: IRLayer
    source_op: Optional[SemanticOperation] = None
    target_op: Optional[SemanticOperation] = None
    explanation: str = ""
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class MatchStatistics:
    """Match statistics for a comparison report"""

    total_source_blocks: int = 0
    matched_blocks: int = 0
    total_source_ops: int = 0
    aligned_ops: int = 0
    equivalent: int = 0
    transformed: int = 0
    different: int = 0
    eliminated: int = 0
    inlined: int = 0
    hard_fail: int = 0
    soft_signal: int = 0

    @property
    def block_coverage(self) -> float:
        if self.total_source_blocks == 0:
            return 100.0
        return 100.0 * self.matched_blocks / self.total_source_blocks

    @property
    def op_coverage(self) -> float:
        if self.total_source_ops == 0:
            return 100.0
        return 100.0 * self.aligned_ops / self.total_source_ops

    @property
    def total_classified(self) -> int:
        return (
            self.equivalent
            + self.transformed
            + self.different
            + self.eliminated
            + self.inlined
            + self.hard_fail
            + self.soft_signal
        )

    def status_percentages(self) -> Dict[str, float]:
        total = self.total_classified
        if total == 0:
            return {s.name: 0.0 for s in ComparisonStatus}
        return {
            ComparisonStatus.EQUIVALENT.name: 100.0 * self.equivalent / total,
            ComparisonStatus.TRANSFORMED.name: 100.0 * self.transformed / total,
            ComparisonStatus.DIFFERENT.name: 100.0 * self.different / total,
            ComparisonStatus.ELIMINATED.name: 100.0 * self.eliminated / total,
            ComparisonStatus.INLINED.name: 100.0 * self.inlined / total,
        }

    def accumulate(self, other: 'MatchStatistics') -> None:
        """Add another MatchStatistics into this one"""
        self.total_source_blocks += other.total_source_blocks
        self.matched_blocks += other.matched_blocks
        self.total_source_ops += other.total_source_ops
        self.aligned_ops += other.aligned_ops
        self.equivalent += other.equivalent
        self.transformed += other.transformed
        self.different += other.different
        self.eliminated += other.eliminated
        self.inlined += other.inlined
        self.hard_fail += other.hard_fail
        self.soft_signal += other.soft_signal


@dataclass
class BlockComparisonResult:
    """Result for a single matched block pair"""

    source_block_id: int
    target_block_id: int
    similarity: float
    source_offset: int = 0
    target_offset: int = 0
    results: List[ComparisonResult] = field(default_factory=list)


@dataclass
class ComparisonReport:
    """Full comparison report for a layer pair"""

    source_layer: IRLayer
    target_layer: IRLayer
    function_name: str = ""
    block_results: List[BlockComparisonResult] = field(default_factory=list)
    unmatched_source_blocks: List[int] = field(default_factory=list)
    unmatched_target_blocks: List[int] = field(default_factory=list)
    hard_fail_violations: List[ComparisonResult] = field(default_factory=list)
    soft_signal_warnings: List[ComparisonResult] = field(default_factory=list)
    quality_metrics: Dict[str, Union[int, float, Dict[str, int]]] = field(default_factory=dict)
    statistics: MatchStatistics = field(default_factory=MatchStatistics)
    passed: bool = True


@dataclass
class SemanticAtom:
    """Comparison unit used by provenance-first matching"""

    kind: OperationKind
    operator: str
    operands: List[SemanticOperand] = field(default_factory=list)
    provenance_keys: List[ProvenanceKey] = field(default_factory=list)
    fingerprint: str = ""
    critical: bool = False


@dataclass
class EffectEvent:
    """Observable side-effect event for behavior validation"""

    category: str  # call, write_global, write_reg, return
    signature: str
    family: str = ""
    target_key: str = ""
    source_location: SourceLocation = field(default_factory=SourceLocation)
    provenance_keys: List[ProvenanceKey] = field(default_factory=list)


@dataclass
class FunctionReport:
    """Report for all layer comparisons of a single function"""

    function_name: str
    llil_mlil: Optional[ComparisonReport] = None
    mlil_hlil: Optional[ComparisonReport] = None


# =============================================================================
# Section 3: IR Pipeline
# =============================================================================

class IRPipeline:
    """Generates all IR layers from an SCP file"""

    def __init__(self, scp_path: str):
        raise_recursion_limit()

        self.scp_path = scp_path
        self.parser = None
        self.fs = None
        self.functions: List[Tuple[str, LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction]] = []
        self.hlil_failed: set[str] = set()     # functions compared LLIL -> MLIL only

    def load(self) -> bool:
        try:
            scp_path = Path(self.scp_path)
            self.fs = fileio.FileStream(str(scp_path))
            parser = ScpParser(self.fs, scp_path.name)
            parser.parse()
            self.parser = parser
            return True
        except Exception as e:
            print(f"Error parsing SCP file: {e}", file=sys.stderr)
            return False

    def close(self) -> None:
        if self.fs is not None:
            self.fs.Close()
            self.fs = None

    def generate_ir(self, function_name: Optional[str] = None) -> bool:
        if self.parser is None:
            return False

        try:
            self.parser.disasm_all_functions()
            lifter = ED9VMLifter(parser=self.parser)

            for func in self.parser.functions:
                if function_name and func.name != function_name:
                    continue

                try:
                    llil_func = lifter.lift_function(func)
                    mlil_func = convert_falcom_llil_to_mlil(llil_func)
                except Exception:
                    continue    # a function that fails to lift or convert to MLIL is not compared

                try:
                    hlil_func = convert_falcom_mlil_to_hlil(mlil_func)
                except Exception:
                    self.hlil_failed.add(func.name)
                    hlil_func = HighLevelILFunction(func.name)

                self.functions.append((func.name, llil_func, mlil_func, hlil_func))
        finally:
            self.close()

        return len(self.functions) > 0

    def can_compare_mlil_hlil(self, func_name: str) -> bool:
        return func_name not in self.hlil_failed


# =============================================================================
# Section 4: Normalization
# =============================================================================

# Track unknown operations encountered during normalization
_unknown_llil_ops: set = set()
_unknown_mlil_ops: set = set()
_unknown_hlil_ops: set = set()


def report_unknown_operations() -> None:
    if _unknown_llil_ops:
        print(f"Unknown LLIL operations: {sorted(_unknown_llil_ops)}", file=sys.stderr)
    if _unknown_mlil_ops:
        print(f"Unknown MLIL operations: {sorted(_unknown_mlil_ops)}", file=sys.stderr)
    if _unknown_hlil_ops:
        print(f"Unknown HLIL operations: {sorted(_unknown_hlil_ops)}", file=sys.stderr)


def _kinds_by_name(groups: Dict[OperationKind, str]) -> Dict[str, OperationKind]:
    """Operation name, its layer prefix dropped -> kind, from kind -> the names, space-separated"""
    return {name: kind for kind, names in groups.items() for name in names.split()}


LLIL_KINDS = _kinds_by_name({
    OperationKind.ARITHMETIC:   'ADD SUB MUL DIV MOD NEG',
    OperationKind.COMPARISON:   'EQ NE LT LE GT GE TEST_ZERO',
    OperationKind.LOGICAL:      'LOGICAL_AND LOGICAL_OR',
    OperationKind.BITWISE:      'AND OR BITWISE_NOT',
    OperationKind.BRANCH:       'JMP BRANCH',
    OperationKind.CALL:         'CALL SYSCALL CALL_SCRIPT DEBUG_LOG',
    OperationKind.RETURN:       'RET',
    OperationKind.LOAD:         'STACK_LOAD FRAME_LOAD LOAD REG_LOAD GLOBAL_LOAD CONST',
    OperationKind.ASSIGN:       'STACK_STORE FRAME_STORE STORE REG_STORE GLOBAL_STORE',
    OperationKind.NOP:          'DEBUG SP_ADD',
})

MLIL_KINDS = _kinds_by_name({
    OperationKind.ARITHMETIC:   'ADD SUB MUL DIV MOD NEG',
    OperationKind.COMPARISON:   'EQ NE LT LE GT GE TEST_ZERO',
    OperationKind.LOGICAL:      'LOGICAL_AND LOGICAL_OR LOGICAL_NOT',
    OperationKind.BITWISE:      'AND OR XOR SHL SHR BITWISE_NOT',
    OperationKind.BRANCH:       'GOTO IF',
    OperationKind.CALL:         'CALL SYSCALL CALL_SCRIPT',
    OperationKind.RETURN:       'RET',
    OperationKind.LOAD:         'VAR CONST LOAD_GLOBAL LOAD_REG DEREF',
    OperationKind.ASSIGN:       'SET_VAR STORE_GLOBAL STORE_REG STORE_DEREF',
    OperationKind.NOP:          'NOP DEBUG',
})

# ASSIGN, EXPR_STMT, BINARY_OP and UNARY_OP are normalized by normalize_hlil_operation's own code
HLIL_KINDS = _kinds_by_name({
    OperationKind.CONTROL_FLOW: 'IF WHILE DO_WHILE SWITCH BREAK CONTINUE UNSTRUCTURED',
    OperationKind.RETURN:       'RETURN',
    OperationKind.LOAD:         'VAR CONST DEREF',
    OperationKind.CALL:         'CALL SYSCALL',
    OperationKind.NOP:          'BLOCK COMMENT',
})
HLIL_WITHOUT_OPERANDS = {'BREAK', 'CONTINUE', 'UNSTRUCTURED', 'BLOCK', 'COMMENT'}


def normalize_llil_operation(instr: LowLevelILInstruction) -> SemanticOperation:
    """Convert LLIL instruction to normalized SemanticOperation. A tail call's is its script call:
    normalize_llil_operations adds the return that follows it"""
    name = instr.operation.name.removeprefix('LLIL_')
    if instr.operation == LowLevelILFalcomOperation.LLIL_CALL_SCRIPT_NO_RETURN:
        name = 'CALL_SCRIPT'

    loc = SourceLocation(scp_offset=instr.address, llil_index=instr.inst_index)
    kind = LLIL_KINDS.get(name)

    if kind is None:
        _unknown_llil_ops.add(instr.operation.name)
        return SemanticOperation(kind=OperationKind.UNKNOWN, operator=instr.operation.name, source_location=loc)

    if kind == OperationKind.NOP:
        return SemanticOperation(kind=kind, operator=name, source_location=loc)

    result = None
    if name == 'GLOBAL_STORE' and hasattr(instr, 'index'):
        result = SemanticOperand(kind='global', value=f"GLOBALS[{instr.index}]")

    return SemanticOperation(
        kind=kind,
        operator=name,
        operands=_extract_llil_operands(instr),
        result=result,
        source_location=loc,
    )


def normalize_llil_operations(instr: LowLevelILInstruction) -> List[SemanticOperation]:
    """instr's normalized operations: its own and, after a tail call, the return of the callee's result - MLIL
    translates a tail call as `return module.func(args)` (falcom/ed9/ir/mlil/mlil_translator.py)"""
    operations = [normalize_llil_operation(instr)]
    if instr.operation == LowLevelILFalcomOperation.LLIL_CALL_SCRIPT_NO_RETURN:
        loc = SourceLocation(scp_offset=instr.address, llil_index=instr.inst_index)
        operations.append(SemanticOperation(kind=OperationKind.RETURN, operator='RET', source_location=loc))

    return operations


def _expr_or_const_operand(value: Any, instruction_type: type) -> SemanticOperand:
    """An IR node as an expression operand, anything else as a constant"""
    if isinstance(value, instruction_type):
        return SemanticOperand(kind='expr', value=str(value))
    return SemanticOperand(kind='const', value=value)


def _extract_llil_operands(instr: LowLevelILInstruction) -> List[SemanticOperand]:
    """Extract operands from LLIL instruction"""
    operands = []

    if hasattr(instr, 'value'):
        operands.append(SemanticOperand(kind='const', value=instr.value))

    if hasattr(instr, 'slot_index'):
        operands.append(SemanticOperand(kind='var', value=f"Stack[{instr.slot_index}]"))

    if hasattr(instr, 'reg_index'):
        operands.append(SemanticOperand(kind='reg', value=f"Reg[{instr.reg_index}]"))

    if isinstance(instr, LowLevelILGlobalLoad):
        operands.append(SemanticOperand(kind='global', value=f"GLOBALS[{instr.index}]"))

    if hasattr(instr, 'src') and isinstance(instr.src, LowLevelILInstruction):
        operands.append(SemanticOperand(kind='expr', value=str(instr.src)))

    if hasattr(instr, 'dest') and isinstance(instr.dest, LowLevelILInstruction):
        operands.append(SemanticOperand(kind='expr', value=str(instr.dest)))

    if hasattr(instr, 'operand'):
        operands.append(_expr_or_const_operand(instr.operand, LowLevelILInstruction))

    return operands


def normalize_mlil_operation(
    instr: MediumLevelILInstruction,
    register_names: Optional[Dict[str, int]] = None,
) -> SemanticOperation:
    """Convert MLIL instruction to normalized SemanticOperation

    MLIL models VM registers as variables, so reads and writes of one are
    normalized back to LOAD_REG/STORE_REG and stay comparable with LLIL.
    """
    register_names = register_names or {}
    name = instr.operation.name.removeprefix('MLIL_')
    loc = SourceLocation(scp_offset=instr.address, llil_index=instr.llil_index, mlil_index=instr.inst_index)
    kind = MLIL_KINDS.get(name)

    if kind is None:
        _unknown_mlil_ops.add(instr.operation.name)
        return SemanticOperation(kind=OperationKind.UNKNOWN, operator=instr.operation.name, source_location=loc)

    if kind == OperationKind.NOP:
        return SemanticOperation(kind=kind, operator=name, source_location=loc)

    operator, result = name, None
    if name == 'VAR':
        var_name = instr.var.name if hasattr(instr.var, 'name') else str(instr.var)
        if var_name in register_names:
            operator = 'LOAD_REG'
    elif name == 'SET_VAR':
        if hasattr(instr, 'var') and instr.var is not None:
            var_name = instr.var.name if hasattr(instr.var, 'name') else str(instr.var)
            if var_name in register_names:
                operator = 'STORE_REG'
                result = SemanticOperand(kind='reg', value=f"REGS[{register_names[var_name]}]")
            else:
                result = SemanticOperand(kind='var', value=var_name)
    elif name == 'STORE_GLOBAL' and hasattr(instr, 'index'):
        result = SemanticOperand(kind='global', value=f"GLOBALS[{instr.index}]")
    elif name == 'STORE_REG' and hasattr(instr, 'index'):
        result = SemanticOperand(kind='reg', value=f"REGS[{instr.index}]")

    return SemanticOperation(
        kind=kind,
        operator=operator,
        operands=_extract_mlil_operands(instr),
        result=result,
        source_location=loc,
    )


def _extract_mlil_operands(instr: MediumLevelILInstruction) -> List[SemanticOperand]:
    """Extract operands from MLIL instruction"""
    operands = []

    if hasattr(instr, 'target'):
        operands.append(SemanticOperand(kind='var', value=str(instr.target)))

    if hasattr(instr, 'module') and hasattr(instr, 'func'):
        # Same spelling as the HLIL extern call target, so the two match up
        operands.append(SemanticOperand(kind='var', value=f"{instr.module}:{instr.func}"))

    if hasattr(instr, 'subsystem') and hasattr(instr, 'cmd'):
        operands.append(SemanticOperand(kind='var', value=f"{instr.subsystem}:{instr.cmd}"))

    if hasattr(instr, 'value'):
        operands.append(SemanticOperand(kind='const', value=instr.value))

    if hasattr(instr, 'var') and instr.var is not None:
        var_name = instr.var.name if hasattr(instr.var, 'name') else str(instr.var)
        operands.append(SemanticOperand(kind='var', value=var_name))

    if isinstance(instr, MLILLoadGlobal):
        operands.append(SemanticOperand(kind='global', value=f"GLOBALS[{instr.index}]"))

    if hasattr(instr, 'dest') and isinstance(instr.dest, MediumLevelILInstruction):
        operands.append(SemanticOperand(kind='expr', value=str(instr.dest)))

    if hasattr(instr, 'args') and instr.args is not None:
        for arg in instr.args:
            operands.append(SemanticOperand(kind='expr', value=str(arg)))

    if hasattr(instr, 'operand'):
        operands.append(_expr_or_const_operand(instr.operand, MediumLevelILInstruction))

    return operands


def normalize_hlil_operation(instr: HLILInstruction) -> SemanticOperation:
    """Convert HLIL instruction to normalized SemanticOperation"""
    op = instr.operation
    loc = SourceLocation(scp_offset=instr.address, mlil_index=instr.mlil_index)

    # Assignment
    if op == HLILOperation.HLIL_ASSIGN:
        if hasattr(instr, 'src') and hasattr(instr.src, 'operation') and not _is_global_call_assignment(instr):
            src_op = instr.src.operation
            if src_op == HLILOperation.HLIL_CALL:
                return SemanticOperation(
                    kind=OperationKind.CALL,
                    operator='CALL',
                    operands=_extract_hlil_operands(instr.src),
                    source_location=loc,
                )
            elif src_op == HLILOperation.HLIL_SYSCALL:
                return SemanticOperation(
                    kind=OperationKind.CALL,
                    operator='SYSCALL',
                    operands=_extract_hlil_operands(instr.src),
                    source_location=loc,
                )

        result = None
        if hasattr(instr, 'dest') and hasattr(instr.dest, 'var') and instr.dest.var is not None:
            result = _hlil_var_operand(instr.dest.var)
        return SemanticOperation(
            kind=OperationKind.ASSIGN,
            operator='ASSIGN',
            operands=_extract_hlil_operands(instr),
            result=result,
            source_location=loc,
        )

    # Expression statement - unwrap
    elif op == HLILOperation.HLIL_EXPR_STMT:
        if hasattr(instr, 'expr') and instr.expr is not None:
            return _apply_location_fallback(normalize_hlil_operation(instr.expr), loc)

        return SemanticOperation(
            kind=OperationKind.NOP,
            operator='EXPR_STMT',
            operands=_extract_hlil_operands(instr),
            source_location=loc,
        )

    # Expressions
    elif op == HLILOperation.HLIL_BINARY_OP:
        bin_op = instr.op if hasattr(instr, 'op') else None
        return SemanticOperation(
            kind=_get_binary_op_kind(bin_op),
            operator=bin_op.name if bin_op else 'BINARY_OP',
            operands=_extract_hlil_operands(instr),
            source_location=loc,
        )
    elif op == HLILOperation.HLIL_UNARY_OP:
        unary_op = instr.op if hasattr(instr, 'op') else None
        return SemanticOperation(
            kind=_get_unary_op_kind(unary_op),
            operator=unary_op.name if unary_op else 'UNARY_OP',
            operands=_extract_hlil_operands(instr),
            source_location=loc,
        )

    # Every other operation by its kind
    op_name = op.name if hasattr(op, 'name') else str(op)
    name = op_name.removeprefix('HLIL_')
    kind = HLIL_KINDS.get(name)

    if kind is None:
        _unknown_hlil_ops.add(op_name)
        return SemanticOperation(kind=OperationKind.UNKNOWN, operator=op_name, source_location=loc)

    return SemanticOperation(
        kind=kind,
        operator=name,
        operands=[] if name in HLIL_WITHOUT_OPERANDS else _extract_hlil_operands(instr),
        source_location=loc,
    )


def _hlil_var_operand(var: Any) -> SemanticOperand:
    """Operand for an HLIL variable; globals and registers have no name, only a slot"""
    if not isinstance(var, HLILVariable):
        return SemanticOperand(kind='var', value=str(var))

    if var.kind == VariableKind.GLOBAL:
        return SemanticOperand(kind='global', value=str(var))

    if var.kind == VariableKind.REG:
        return SemanticOperand(kind='reg', value=str(var))

    return SemanticOperand(kind='var', value=var.name)


def _extract_hlil_operands(instr: HLILInstruction) -> List[SemanticOperand]:
    """Extract operands from HLIL instruction"""
    operands = []

    if hasattr(instr, 'func_name'):
        operands.append(SemanticOperand(kind='var', value=str(instr.func_name)))

    if hasattr(instr, 'target'):
        operands.append(SemanticOperand(kind='var', value=str(instr.target)))

    if hasattr(instr, 'subsystem') and hasattr(instr, 'cmd'):
        operands.append(SemanticOperand(kind='var', value=f"{instr.subsystem}:{instr.cmd}"))

    if hasattr(instr, 'value'):
        operands.append(SemanticOperand(kind='const', value=instr.value))

    if hasattr(instr, 'var') and instr.var is not None:
        operands.append(_hlil_var_operand(instr.var))

    # A plain var dest (e.g. HLIL_ASSIGN's x = ...) is already captured via that
    # operation's own `result` field - only a compound dest (e.g. *ptr = ...) needs
    # capturing here, so it is not silently dropped from validation coverage.
    if hasattr(instr, 'dest') and isinstance(instr.dest, HLILInstruction) and not hasattr(instr.dest, 'var'):
        operands.append(SemanticOperand(kind='expr', value=str(instr.dest)))

    if hasattr(instr, 'args') and instr.args is not None:
        for arg in instr.args:
            operands.append(SemanticOperand(kind='expr', value=str(arg)))

    if hasattr(instr, 'operand'):
        operands.append(_expr_or_const_operand(instr.operand, HLILInstruction))

    return operands


def _get_binary_op_kind(op: Optional[BinaryOp]) -> OperationKind:
    """Map HLIL BinaryOp to OperationKind"""
    if op is None:
        return OperationKind.UNKNOWN

    if op in (BinaryOp.ADD, BinaryOp.SUB, BinaryOp.MUL, BinaryOp.DIV, BinaryOp.MOD):
        return OperationKind.ARITHMETIC
    elif op in (BinaryOp.EQ, BinaryOp.NE, BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE):
        return OperationKind.COMPARISON
    elif op in (BinaryOp.AND, BinaryOp.OR):
        return OperationKind.LOGICAL
    elif op in (BinaryOp.BIT_AND, BinaryOp.BIT_OR, BinaryOp.BIT_XOR, BinaryOp.SHL, BinaryOp.SHR):
        return OperationKind.BITWISE

    return OperationKind.UNKNOWN


def _get_unary_op_kind(op: Optional[UnaryOp]) -> OperationKind:
    """Map HLIL UnaryOp to OperationKind"""
    if op is None:
        return OperationKind.UNKNOWN

    if op == UnaryOp.NEG:
        return OperationKind.ARITHMETIC
    elif op == UnaryOp.NOT:
        return OperationKind.LOGICAL
    elif op == UnaryOp.BIT_NOT:
        return OperationKind.BITWISE

    return OperationKind.UNKNOWN


# =============================================================================
# Section 5: CFG Construction
# =============================================================================

@dataclass
class CFGNode:
    """Basic block node in CFG"""

    id: int
    address: int = 0
    operations: List[SemanticOperation] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


class CFG:
    """Control Flow Graph representation"""

    def __init__(self) -> None:
        self.nodes: Dict[int, CFGNode] = {}

    def add_node(self, node: CFGNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, from_id: int, to_id: int) -> None:
        if from_id in self.nodes and to_id in self.nodes:
            if to_id not in self.nodes[from_id].successors:
                self.nodes[from_id].successors.append(to_id)
            if from_id not in self.nodes[to_id].predecessors:
                self.nodes[to_id].predecessors.append(from_id)

    def get_node(self, node_id: int) -> Optional[CFGNode]:
        return self.nodes.get(node_id)


# Internal stack operations, which build_cfg_from_llil leaves out
LLIL_STACK_OPERATIONS = (
    LowLevelILOperation.LLIL_STACK_STORE,
    LowLevelILOperation.LLIL_STACK_LOAD,
    LowLevelILOperation.LLIL_SP_ADD,
)


def _cfg_from_blocks(
    basic_blocks: List[Any],
    normalize: Callable[[Any], List[SemanticOperation]],
    skipped_operations: Tuple[Any, ...] = (),
) -> CFG:
    """One node per basic block holding its normalized operations but the NOPs, the first block the entry. No edges
    on purpose: edges on one layer alone make block matching worse, so all three CFG builders get them together
    (docs/FUTURE_WORK.md, "Static Game-Logic Check"); so every node is an exit"""
    cfg = CFG()

    for i, bb in enumerate(basic_blocks):
        ops = [op for instr in bb.instructions if instr.operation not in skipped_operations for op in normalize(instr)]
        operations = [op for op in ops if op.kind != OperationKind.NOP]
        cfg.add_node(CFGNode(id=i, address=bb.start, operations=operations, is_entry=(i == 0), is_exit=True))

    return cfg


def build_cfg_from_llil(llil_func: LowLevelILFunction) -> CFG:
    """Construct CFG from LLILFunction"""
    return _cfg_from_blocks(llil_func.basic_blocks, normalize_llil_operations, LLIL_STACK_OPERATIONS)


def build_cfg_from_mlil(mlil_func: MediumLevelILFunction) -> CFG:
    """Construct CFG from MLILFunction"""
    register_names = {var.name: index for index, var in mlil_func.register_vars.items()}
    return _cfg_from_blocks(mlil_func.basic_blocks, lambda instr: [normalize_mlil_operation(instr, register_names)])


def _collect_call_expressions(node: Any, found: List[Any]) -> None:
    """Collect call expressions inside an expression, in evaluation order"""
    for child in expr_children(node):
        _collect_call_expressions(child, found)

    if isinstance(node, (HLILCall, HLILSyscall, HLILExternCall)):
        found.append(node)


def _statement_expressions(instr: HLILInstruction) -> List[Any]:
    """Expressions a statement evaluates, in evaluation order"""
    if hasattr(instr, 'condition'):
        return [instr.condition]

    if hasattr(instr, 'scrutinee'):
        return [instr.scrutinee]

    if hasattr(instr, 'dest') and hasattr(instr, 'src'):
        return [instr.src]

    if hasattr(instr, 'expr'):
        return [instr.expr]

    if hasattr(instr, 'value'):
        return [instr.value]

    return []


def _is_global_call_assignment(instr: HLILInstruction) -> bool:
    """`GLOBALS[n] = call()` - normalized as the global write, its call kept as a folded call"""
    dest_var = getattr(getattr(instr, 'dest', None), 'var', None)
    src_op = getattr(getattr(instr, 'src', None), 'operation', None)
    return (
        isinstance(dest_var, HLILVariable)
        and dest_var.kind == VariableKind.GLOBAL
        and src_op in (HLILOperation.HLIL_CALL, HLILOperation.HLIL_SYSCALL)
    )


def _statement_own_call(instr: HLILInstruction) -> Optional[Any]:
    """Call expression the statement's own normalized operation already stands for"""
    if _is_global_call_assignment(instr):
        return None

    if hasattr(instr, 'dest') and hasattr(instr, 'src') and hasattr(instr.src, 'args'):
        return instr.src

    if hasattr(instr, 'expr') and instr.expr is not None and hasattr(instr.expr, 'args'):
        return instr.expr

    return None


def _folded_call_operations(instr: HLILInstruction) -> List[SemanticOperation]:
    """CALL operations for calls folded into a statement's expressions

    HLIL folds a call result into the instruction that reads it, so calls appear
    inside if conditions, return values and other call arguments. They still run,
    before the statement that reads them.
    """
    own_call = _statement_own_call(instr)
    found: List[Any] = []

    for expression in _statement_expressions(instr):
        _collect_call_expressions(expression, found)

    loc = SourceLocation(scp_offset=instr.address, mlil_index=instr.mlil_index)

    return [
        _apply_location_fallback(normalize_hlil_operation(call), loc)
        for call in found
        if call is not own_call
    ]


def build_cfg_from_hlil(hlil_func: HighLevelILFunction) -> CFG:
    """Construct CFG from HLILFunction (flatten structured control flow)"""
    cfg = CFG()

    def extract_statements(body) -> List[Any]:
        """Extract statement list from HLIL body"""
        if body is None:
            return []
        if isinstance(body, list):
            return body
        if hasattr(body, 'statements'):
            return list(body.statements)
        return [body]

    def flatten_statements(stmts: List[HLILStatement], block_id: int) -> Tuple[int, List[int]]:
        """Flatten HLIL statements into CFG blocks, return (next_id, exit_ids)"""
        if not stmts:
            return block_id, []

        current_ops: List[SemanticOperation] = []
        current_id = block_id
        exits: List[int] = []

        def save_current_block() -> Optional[int]:
            """The operations gathered so far as a block of their own: its id, or None when there are none"""
            nonlocal current_ops, current_id
            if not current_ops:
                return None

            address = current_ops[0].source_location.scp_offset
            cfg.add_node(CFGNode(id=current_id, address=address, operations=current_ops))
            current_id += 1
            current_ops = []
            return current_id - 1

        for stmt in stmts:
            op = normalize_hlil_operation(stmt)

            # Calls folded into this statement's expressions run before it
            folded_ops = _folded_call_operations(stmt)

            # Handle control flow statements
            if hasattr(stmt, 'operation'):
                if stmt.operation == HLILOperation.HLIL_SWITCH:
                    current_ops.extend(folded_ops)
                    save_current_block()

                    # Create scrutinee block
                    switch_node = CFGNode(id=current_id, address=op.source_location.scp_offset, operations=[op])
                    cfg.add_node(switch_node)
                    switch_id = current_id
                    current_id += 1

                    # Each case body is a successor of the switch
                    for case in stmt.cases:
                        case_stmts = extract_statements(case.body)
                        if not case_stmts:
                            continue

                        case_start = current_id
                        case_id, case_exits = flatten_statements(case_stmts, current_id)
                        current_id = max(case_id, current_id)
                        cfg.add_edge(switch_id, case_start)
                        exits.extend(case_exits)

                    continue
                elif stmt.operation == HLILOperation.HLIL_IF:
                    current_ops.extend(folded_ops)
                    save_current_block()

                    # Create condition block
                    cond_node = CFGNode(id=current_id, address=op.source_location.scp_offset, operations=[op])
                    cfg.add_node(cond_node)
                    cond_id = current_id
                    current_id += 1

                    # Process then branch (HLILIf.true_block, not .body)
                    then_stmts = extract_statements(stmt.true_block)
                    if then_stmts:
                        then_start = current_id
                        then_id, then_exits = flatten_statements(then_stmts, current_id)
                        current_id = max(then_id, current_id)
                        cfg.add_edge(cond_id, then_start)
                    else:
                        then_exits = []

                    # Process else branch (HLILIf.false_block, not .else_body)
                    else_exits = []
                    if stmt.false_block:
                        else_stmts = extract_statements(stmt.false_block)
                        if else_stmts:
                            else_start = current_id
                            else_id, else_exits = flatten_statements(else_stmts, current_id)
                            current_id = max(else_id, current_id)
                            cfg.add_edge(cond_id, else_start)

                    exits.extend(then_exits)
                    exits.extend(else_exits)
                    continue
                elif stmt.operation == HLILOperation.HLIL_WHILE:
                    # The block before the loop stays unlinked: consecutive blocks get no edges
                    # (docs/VALIDATOR_GUIDE.md, Limitations)
                    save_current_block()

                    # Create loop header (condition calls run on each iteration)
                    header_node = CFGNode(id=current_id, address=op.source_location.scp_offset, operations=folded_ops + [op])
                    cfg.add_node(header_node)
                    header_id = current_id
                    current_id += 1

                    # Process loop body
                    body_stmts = extract_statements(stmt.body)
                    if body_stmts:
                        body_start = current_id
                        body_id, body_exits = flatten_statements(body_stmts, current_id)
                        current_id = max(body_id, current_id)
                        cfg.add_edge(header_id, body_start)
                        # Back edge
                        for exit_id in body_exits:
                            cfg.add_edge(exit_id, header_id)

                    exits.append(header_id)  # Loop exit
                    continue
                elif stmt.operation == HLILOperation.HLIL_DO_WHILE:
                    save_current_block()

                    # Body runs before the condition is first tested
                    body_start = current_id
                    body_exits: List[int] = []
                    body_stmts = extract_statements(stmt.body)
                    if body_stmts:
                        body_id, body_exits = flatten_statements(body_stmts, current_id)
                        current_id = max(body_id, current_id)

                    # Condition block (condition calls run after the body on each iteration)
                    cond_node = CFGNode(id=current_id, address=op.source_location.scp_offset, operations=folded_ops + [op])
                    cfg.add_node(cond_node)
                    cond_id = current_id
                    current_id += 1

                    for exit_id in body_exits:
                        cfg.add_edge(exit_id, cond_id)

                    # Back edge
                    cfg.add_edge(cond_id, body_start)

                    exits.append(cond_id)  # Loop exit
                    continue

            current_ops.extend(folded_ops)

            if op.kind != OperationKind.NOP:
                current_ops.append(op)

        # Save remaining ops
        last_id = save_current_block()
        if last_id is not None:
            exits.append(last_id)

        return current_id, exits

    # Flatten all statements
    stmts = list(hlil_func.body.statements)
    if stmts:
        _, exit_ids = flatten_statements(stmts, 0)
        if cfg.nodes:
            cfg.nodes[0].is_entry = True
            for eid in exit_ids:
                if eid in cfg.nodes:
                    cfg.nodes[eid].is_exit = True

    return cfg


# =============================================================================
# Section 6: Block Matching
# =============================================================================

def compute_operation_similarity(op1: SemanticOperation, op2: SemanticOperation) -> float:
    """Compare two SemanticOperations (0.0-1.0 score)"""
    score = 0.0
    # Provenance-first bonus to stabilize mapping under HLIL restructuring.
    if _has_provenance_overlap(op1.provenance_keys, op2.provenance_keys):
        score += 0.3

    # Kind match (40%)
    if op1.kind == op2.kind:
        score += 0.4

    # Operator match (40%)
    if op1.operator == op2.operator:
        score += 0.4
    elif _is_transform_pair(op1.operator, op2.operator):
        score += 0.3

    # Operand count match (20%)
    if len(op1.operands) == len(op2.operands):
        score += 0.1
        matching_operands = sum(
            1 for a, b in zip(op1.operands, op2.operands)
            if a.kind == b.kind
        )
        if op1.operands:
            score += 0.1 * (matching_operands / len(op1.operands))

    return min(1.0, score)


def _is_transform_pair(op1: str, op2: str) -> bool:
    """Check if two operators are known transformation pairs"""
    transforms = {
        ('STACK_LOAD', 'VAR'), ('STACK_STORE', 'SET_VAR'),
        ('FRAME_LOAD', 'VAR'), ('FRAME_STORE', 'SET_VAR'),
        ('BRANCH', 'IF'), ('JMP', 'GOTO'),
        ('TEST_ZERO', 'EQ'),
    }
    return (op1, op2) in transforms or (op2, op1) in transforms


def compute_block_content_similarity(node1: CFGNode, node2: CFGNode) -> float:
    """Compare block content using operation sequence alignment"""
    if not node1.operations or not node2.operations:
        if not node1.operations and not node2.operations:
            return 1.0
        return 0.0

    m, n = len(node1.operations), len(node2.operations)
    dp = [[0.0] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            sim = compute_operation_similarity(
                node1.operations[i - 1], node2.operations[j - 1]
            )
            dp[i][j] = max(
                dp[i - 1][j - 1] + sim,
                dp[i - 1][j],
                dp[i][j - 1]
            )

    max_ops = max(m, n)
    total_sim = dp[m][n]
    normalized_score = total_sim / max_ops if max_ops > 0 else 1.0

    return min(1.0, normalized_score)


def compute_block_structural_similarity(node1: CFGNode, node2: CFGNode) -> float:
    """Compare structural similarity using degree and edge types"""
    in_diff = abs(len(node1.predecessors) - len(node2.predecessors))
    out_diff = abs(len(node1.successors) - len(node2.successors))

    max_in = max(len(node1.predecessors), len(node2.predecessors), 1)
    max_out = max(len(node1.successors), len(node2.successors), 1)

    in_sim = 1.0 - (in_diff / max_in)
    out_sim = 1.0 - (out_diff / max_out)

    entry_match = 1.0 if node1.is_entry == node2.is_entry else 0.5
    exit_match = 1.0 if node1.is_exit == node2.is_exit else 0.5

    return 0.4 * in_sim + 0.4 * out_sim + 0.1 * entry_match + 0.1 * exit_match


def compute_combined_block_similarity(node1: CFGNode, node2: CFGNode) -> float:
    """Combine content (70%) + structure (30%) similarity"""
    content_sim = compute_block_content_similarity(node1, node2)
    struct_sim = compute_block_structural_similarity(node1, node2)

    return 0.7 * content_sim + 0.3 * struct_sim


class SimilarityMatrix:
    """Store pairwise block similarities"""

    def __init__(self, rows: int, cols: int):
        self.matrix: List[List[float]] = [
            [0.0] * cols for _ in range(rows)
        ]
        self.rows = rows
        self.cols = cols

    def set(self, i: int, j: int, value: float) -> None:
        if 0 <= i < self.rows and 0 <= j < self.cols:
            self.matrix[i][j] = value

    def get(self, i: int, j: int) -> float:
        if 0 <= i < self.rows and 0 <= j < self.cols:
            return self.matrix[i][j]
        return 0.0


def build_initial_similarity_matrix(source_cfg: CFG, target_cfg: CFG) -> SimilarityMatrix:
    """Build initial similarity matrix using block content similarity"""
    source_nodes = list(source_cfg.nodes.keys())
    target_nodes = list(target_cfg.nodes.keys())

    matrix = SimilarityMatrix(len(source_nodes), len(target_nodes))

    for i, src_id in enumerate(source_nodes):
        for j, tgt_id in enumerate(target_nodes):
            src_node = source_cfg.nodes[src_id]
            tgt_node = target_cfg.nodes[tgt_id]
            matrix.set(i, j, compute_combined_block_similarity(src_node, tgt_node))

    return matrix


def propagate_similarity(
    matrix: SimilarityMatrix,
    source_cfg: CFG,
    target_cfg: CFG,
    alpha: float = 0.3,
    max_iterations: int = 10,
    epsilon: float = 0.001
) -> SimilarityMatrix:
    """Iteratively propagate neighbor similarity until convergence"""
    source_nodes = list(source_cfg.nodes.keys())
    target_nodes = list(target_cfg.nodes.keys())

    src_idx = {nid: i for i, nid in enumerate(source_nodes)}
    tgt_idx = {nid: i for i, nid in enumerate(target_nodes)}

    for iteration in range(max_iterations):
        max_change = 0.0
        new_matrix = SimilarityMatrix(matrix.rows, matrix.cols)

        for i, src_id in enumerate(source_nodes):
            src_node = source_cfg.nodes[src_id]

            for j, tgt_id in enumerate(target_nodes):
                tgt_node = target_cfg.nodes[tgt_id]

                content_sim = matrix.get(i, j)

                neighbor_sim = 0.0
                neighbor_count = 0

                for src_succ in src_node.successors:
                    if src_succ in src_idx:
                        for tgt_succ in tgt_node.successors:
                            if tgt_succ in tgt_idx:
                                neighbor_sim += matrix.get(src_idx[src_succ], tgt_idx[tgt_succ])
                                neighbor_count += 1

                for src_pred in src_node.predecessors:
                    if src_pred in src_idx:
                        for tgt_pred in tgt_node.predecessors:
                            if tgt_pred in tgt_idx:
                                neighbor_sim += matrix.get(src_idx[src_pred], tgt_idx[tgt_pred])
                                neighbor_count += 1

                if neighbor_count > 0:
                    neighbor_sim /= neighbor_count
                    new_sim = (1 - alpha) * content_sim + alpha * neighbor_sim
                else:
                    new_sim = content_sim

                new_matrix.set(i, j, new_sim)

                max_change = max(max_change, abs(new_sim - content_sim))

        matrix = new_matrix

        if max_change < epsilon:
            break

    return matrix


def greedy_block_matching(matrix: SimilarityMatrix) -> List[Tuple[int, int]]:
    """Each source block in turn takes its most similar unused target block, if the similarity is above 0.3"""
    matches: List[Tuple[int, int]] = []
    used_cols: set = set()

    for i in range(matrix.rows):
        best_j = -1
        best_cost = float('inf')

        for j in range(matrix.cols):
            cost = 1.0 - matrix.get(i, j)
            if j not in used_cols and cost < best_cost:
                best_cost = cost
                best_j = j

        if best_j >= 0 and best_cost < 0.7:  # Only match if similarity > 0.3
            matches.append((i, best_j))
            used_cols.add(best_j)

    return matches


class CFGMatcher:
    """Match basic blocks between two CFGs"""

    def __init__(self, source_cfg: CFG, target_cfg: CFG):
        self.source_cfg = source_cfg
        self.target_cfg = target_cfg
        self.matches: List[Tuple[int, int]] = []

    def match(self) -> List[Tuple[int, int]]:
        """Find optimal block matching between CFGs.

        Pass 1: match blocks by SCP address (exact, O(N)).
        Pass 2: remaining unmatched blocks use similarity fallback.
        """
        if not self.source_cfg.nodes or not self.target_cfg.nodes:
            return []

        self.matches = []
        matched_src: set = set()
        matched_tgt: set = set()

        # Pass 1: address-based matching
        src_by_addr: Dict[int, int] = {}
        for nid, node in self.source_cfg.nodes.items():
            if node.address != 0:
                src_by_addr[node.address] = nid

        for tgt_id, tgt_node in self.target_cfg.nodes.items():
            if tgt_node.address != 0 and tgt_node.address in src_by_addr:
                src_id = src_by_addr[tgt_node.address]
                if src_id not in matched_src:
                    self.matches.append((src_id, tgt_id))
                    matched_src.add(src_id)
                    matched_tgt.add(tgt_id)

        # Pass 2: similarity fallback for unmatched blocks
        remaining_src = [n for n in self.source_cfg.nodes if n not in matched_src]
        remaining_tgt = [n for n in self.target_cfg.nodes if n not in matched_tgt]

        if remaining_src and remaining_tgt:
            sub_src_cfg = CFG()
            for nid in remaining_src:
                sub_src_cfg.add_node(self.source_cfg.nodes[nid])

            sub_tgt_cfg = CFG()
            for nid in remaining_tgt:
                sub_tgt_cfg.add_node(self.target_cfg.nodes[nid])

            matrix = build_initial_similarity_matrix(sub_src_cfg, sub_tgt_cfg)
            matrix = propagate_similarity(matrix, sub_src_cfg, sub_tgt_cfg)
            idx_matches = greedy_block_matching(matrix)

            sub_src_nodes = list(sub_src_cfg.nodes.keys())
            sub_tgt_nodes = list(sub_tgt_cfg.nodes.keys())

            for i, j in idx_matches:
                self.matches.append((sub_src_nodes[i], sub_tgt_nodes[j]))

        return self.matches


# =============================================================================
# Section 7: Operation Comparison
# =============================================================================

GAP_PENALTY = -0.5     # align_operations: the score of an operation left unpaired


def align_operations(
    source_ops: List[SemanticOperation], target_ops: List[SemanticOperation]
) -> List[Tuple[Optional[SemanticOperation], Optional[SemanticOperation]]]:
    """Align operations within matched blocks using Needleman-Wunsch"""
    aligned: List[Tuple[Optional[SemanticOperation], Optional[SemanticOperation]]] = []

    if not source_ops and not target_ops:
        return aligned

    if not source_ops:
        return [(None, op) for op in target_ops]

    if not target_ops:
        return [(op, None) for op in source_ops]

    m, n = len(source_ops), len(target_ops)
    dp = [[0.0] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        dp[i][0] = dp[i - 1][0] + GAP_PENALTY

    for j in range(1, n + 1):
        dp[0][j] = dp[0][j - 1] + GAP_PENALTY

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            match_score = compute_operation_similarity(source_ops[i - 1], target_ops[j - 1])
            dp[i][j] = max(
                dp[i - 1][j - 1] + match_score,
                dp[i - 1][j] + GAP_PENALTY,
                dp[i][j - 1] + GAP_PENALTY
            )

    # Backtrack
    i, j = m, n
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            match_score = compute_operation_similarity(source_ops[i - 1], target_ops[j - 1])
            if dp[i][j] == dp[i - 1][j - 1] + match_score:
                aligned.append((source_ops[i - 1], target_ops[j - 1]))
                i -= 1
                j -= 1
                continue

        if i > 0 and dp[i][j] == dp[i - 1][j] + GAP_PENALTY:
            aligned.append((source_ops[i - 1], None))
            i -= 1
        elif j > 0:
            aligned.append((None, target_ops[j - 1]))
            j -= 1

    aligned.reverse()
    return aligned


def compare_operands(op1: SemanticOperation, op2: SemanticOperation) -> bool:
    """Same operand count, each pair of the same kind, constants of the same value"""
    if len(op1.operands) != len(op2.operands):
        return False

    return all(a.kind == b.kind and (a.kind != 'const' or a.value == b.value)
               for a, b in zip(op1.operands, op2.operands))


# Commutative operators
COMMUTATIVE_OPS = {'ADD', 'MUL', 'AND', 'OR', 'EQ', 'NE', 'LOGICAL_AND', 'LOGICAL_OR'}


def compare_expression_trees(op1: SemanticOperation, op2: SemanticOperation) -> bool:
    """Same kind, the same operator or a transform pair, and the same operands - either way round for a commutative
    binary operator"""
    if op1.kind != op2.kind:
        return False

    if op1.operator != op2.operator and not _is_transform_pair(op1.operator, op2.operator):
        return False

    if compare_operands(op1, op2):
        return True

    if op1.operator in COMMUTATIVE_OPS and len(op1.operands) == 2:
        reversed_op1 = SemanticOperation(
            kind=op1.kind,
            operator=op1.operator,
            operands=[op1.operands[1], op1.operands[0]],
            result=op1.result,
            source_location=op1.source_location
        )
        return compare_operands(reversed_op1, op2)

    return False


@dataclass
class TransformationRule:
    """Describes an expected transformation between IR layers"""

    source_pattern: str
    target_pattern: str


# LLIL to MLIL expected transformations
LLIL_MLIL_TRANSFORMATIONS: List[TransformationRule] = [
    TransformationRule('STACK_LOAD', 'VAR'),
    TransformationRule('STACK_STORE', 'SET_VAR'),
    TransformationRule('FRAME_LOAD', 'VAR'),
    TransformationRule('FRAME_STORE', 'SET_VAR'),
    TransformationRule('REG_LOAD', 'LOAD_REG'),
    TransformationRule('REG_STORE', 'STORE_REG'),
    TransformationRule('GLOBAL_LOAD', 'LOAD_GLOBAL'),
    TransformationRule('GLOBAL_STORE', 'STORE_GLOBAL'),
    TransformationRule('BRANCH', 'IF'),
    TransformationRule('JMP', 'GOTO'),
    TransformationRule('TEST_ZERO', 'EQ'),
]

# MLIL to HLIL expected transformations
MLIL_HLIL_TRANSFORMATIONS: List[TransformationRule] = [
    TransformationRule('IF', 'IF'),
    TransformationRule('GOTO', 'WHILE'),
    TransformationRule('SET_VAR', 'ASSIGN'),
    TransformationRule('STORE_REG', 'ASSIGN'),
    TransformationRule('VAR', 'VAR'),
    TransformationRule('RET', 'RETURN'),
    TransformationRule('RETURN', 'RET'),
    TransformationRule('CALL', 'CALL'),
    TransformationRule('SYSCALL', 'SYSCALL'),
]


def is_expected_transformation(source_op: str, target_op: str, transformations: List[TransformationRule]) -> bool:
    """Is source_op -> target_op one of the transformations expected between the two layers"""
    return any(rule.source_pattern == source_op and rule.target_pattern == target_op for rule in transformations)


def classify_difference(
    source_op: SemanticOperation,
    target_op: SemanticOperation,
    layer_transforms: List[TransformationRule]
) -> ComparisonStatus:
    """Classify difference as EQUIVALENT, TRANSFORMED, or DIFFERENT"""
    if compare_expression_trees(source_op, target_op):
        return ComparisonStatus.EQUIVALENT

    if is_expected_transformation(source_op.operator, target_op.operator, layer_transforms):
        return ComparisonStatus.TRANSFORMED

    # Same kind but different operator might still be transformed
    if source_op.kind == target_op.kind:
        return ComparisonStatus.TRANSFORMED

    return ComparisonStatus.DIFFERENT


# =============================================================================
# Section 8: Provenance + Behavior Validation
# =============================================================================

# A critical atom's operators: calls, returns, stores and assignments
CRITICAL_OPERATORS = {
    'CALL', 'SYSCALL', 'CALL_SCRIPT', 'RET', 'RETURN', 'STORE_GLOBAL', 'GLOBAL_STORE', 'STORE_REG', 'ASSIGN', 'SET_VAR'
}

CRITICAL_BRANCH_OPERATORS = {'IF', 'GOTO', 'WHILE'}

EFFECT_CATEGORY_CALL = 'call'
EFFECT_CATEGORY_WRITE_GLOBAL = 'write_global'
EFFECT_CATEGORY_WRITE_REG = 'write_reg'
EFFECT_CATEGORY_RETURN = 'return'

CALL_FAMILY = 'call_family'
RETURN_FAMILY = 'return_family'
UNKNOWN_TARGET_KEY = 'unknown'

PROVENANCE_MATCH_SCORE = 100
ADDRESS_MATCH_SCORE = 80
SIGNATURE_MATCH_SCORE = 40
FAMILY_TARGET_MATCH_SCORE = 30
OPERAND_COUNT_MATCH_SCORE = FAMILY_TARGET_MATCH_SCORE
CONDITION_EQUIVALENT_MATCH_SCORE = 40
MIN_EFFECT_MATCH_SCORE = FAMILY_TARGET_MATCH_SCORE
MIN_CONDITION_MATCH_SCORE = CONDITION_EQUIVALENT_MATCH_SCORE


def _semantic_fingerprint(op: SemanticOperation) -> str:
    operand_fingerprint = ",".join(operand.signature for operand in op.operands)
    return f"{op.kind.name}:{op.operator}:{operand_fingerprint}"


def semantic_operation_to_atom(op: SemanticOperation) -> SemanticAtom:
    critical = op.operator in CRITICAL_OPERATORS or op.operator in CRITICAL_BRANCH_OPERATORS

    return SemanticAtom(
        kind=op.kind,
        operator=op.operator,
        operands=list(op.operands),
        provenance_keys=sorted(set(op.provenance_keys)),
        fingerprint=_semantic_fingerprint(op),
        critical=critical,
    )


def extract_semantic_atoms(ops: List[SemanticOperation]) -> List[SemanticAtom]:
    return [semantic_operation_to_atom(op) for op in ops]


def _build_provenance_index(atoms: List[SemanticAtom]) -> Dict[ProvenanceKey, List[int]]:
    provenance_index: Dict[ProvenanceKey, List[int]] = {}
    for atom_idx, atom in enumerate(atoms):
        for provenance in atom.provenance_keys:
            provenance_index.setdefault(provenance, []).append(atom_idx)
    return provenance_index


def _normalized_operator_family(operator: str) -> str:
    if operator in ('CALL', 'SYSCALL', 'CALL_SCRIPT'):
        return CALL_FAMILY
    if operator in ('RET', 'RETURN'):
        return RETURN_FAMILY
    if operator in ('STORE_GLOBAL', 'GLOBAL_STORE'):
        return EFFECT_CATEGORY_WRITE_GLOBAL
    if operator in ('STORE_REG',):
        return EFFECT_CATEGORY_WRITE_REG
    if operator in ('SET_VAR', 'ASSIGN'):
        return 'write_var'
    if operator in CRITICAL_BRANCH_OPERATORS:
        return 'branch_condition'
    return operator


def _has_provenance_overlap(left: List[ProvenanceKey], right: List[ProvenanceKey]) -> bool:
    return bool(set(left).intersection(right))


def _atom_match_score(source_atom: SemanticAtom, target_atom: SemanticAtom) -> int:
    if source_atom.kind != target_atom.kind:
        return 0

    source_family = _normalized_operator_family(source_atom.operator)
    target_family = _normalized_operator_family(target_atom.operator)
    if source_family != target_family:
        return 0

    score = 0
    if _has_provenance_overlap(source_atom.provenance_keys, target_atom.provenance_keys):
        score += PROVENANCE_MATCH_SCORE

    if source_atom.fingerprint == target_atom.fingerprint:
        score += SIGNATURE_MATCH_SCORE

    if len(source_atom.operands) == len(target_atom.operands):
        score += OPERAND_COUNT_MATCH_SCORE

    return score


def _match_atoms_provenance_first(
    source_atoms: List[SemanticAtom],
    target_atoms: List[SemanticAtom],
) -> Tuple[List[Tuple[int, int]], int, int]:
    """Match source/target atoms by provenance first, then fingerprint fallback."""
    matches: List[Tuple[int, int]] = []
    used_target_indices: set[int] = set()
    provenance_matches = 0
    fallback_matches = 0

    target_by_provenance = _build_provenance_index(target_atoms)
    target_by_fingerprint: Dict[str, List[int]] = {}
    for target_idx, atom in enumerate(target_atoms):
        target_by_fingerprint.setdefault(atom.fingerprint, []).append(target_idx)

    for source_idx, source_atom in enumerate(source_atoms):
        matched_target_idx = -1

        # Pass 1: provenance-first mapping.
        for provenance in source_atom.provenance_keys:
            candidate_indices = target_by_provenance.get(provenance, [])
            for candidate_idx in candidate_indices:
                if candidate_idx in used_target_indices:
                    continue
                candidate = target_atoms[candidate_idx]
                if _atom_match_score(source_atom, candidate) >= PROVENANCE_MATCH_SCORE:
                    matched_target_idx = candidate_idx
                    break
            if matched_target_idx >= 0:
                break

        if matched_target_idx >= 0:
            matches.append((source_idx, matched_target_idx))
            used_target_indices.add(matched_target_idx)
            provenance_matches += 1
            continue

        # Pass 2: semantic-fingerprint fallback.
        for candidate_idx in target_by_fingerprint.get(source_atom.fingerprint, []):
            if candidate_idx in used_target_indices:
                continue
            candidate = target_atoms[candidate_idx]
            if _atom_match_score(source_atom, candidate) >= SIGNATURE_MATCH_SCORE:
                matched_target_idx = candidate_idx
                break

        if matched_target_idx >= 0:
            matches.append((source_idx, matched_target_idx))
            used_target_indices.add(matched_target_idx)
            fallback_matches += 1

    return matches, provenance_matches, fallback_matches


def _normalize_operand_key(operand: Optional[SemanticOperand]) -> str:
    if operand is None:
        return UNKNOWN_TARGET_KEY
    if operand.kind in ('var', 'reg', 'global', 'const'):
        return operand.signature
    return operand.kind


def _apply_location_fallback(
    op: SemanticOperation,
    source_location: SourceLocation,
) -> SemanticOperation:
    """Preserve statement source info when HLIL expressions drop it."""
    if op.source_location.scp_offset == 0 and source_location.scp_offset != 0:
        op.source_location.scp_offset = source_location.scp_offset
    if op.source_location.mlil_index < 0 and source_location.mlil_index >= 0:
        op.source_location.mlil_index = source_location.mlil_index
    return op


def _build_effect_event(op: SemanticOperation, category: str, family: str, target_key: str) -> EffectEvent:
    return EffectEvent(
        category=category,
        signature=f"{family}:{target_key}",
        family=family,
        target_key=target_key,
        source_location=op.source_location,
        provenance_keys=op.provenance_keys,
    )


def semantic_op_to_effect_event(op: SemanticOperation) -> Optional[EffectEvent]:
    if op.kind == OperationKind.CALL:
        target_key = _normalize_operand_key(op.operands[0] if op.operands else None)
        return _build_effect_event(op, EFFECT_CATEGORY_CALL, CALL_FAMILY, target_key)

    if op.kind == OperationKind.ASSIGN:
        # Only a global result is a global write - operand text can name a global that is only read.
        # Only global writes are shared state, so only they anchor the comparison.
        # Local and register writes are private to the function and are expected to
        # be folded away (into a call result, a condition or the returned value);
        # the per-operation comparison still reports them as equivalent, transformed
        # or eliminated.
        if op.result is None or op.result.kind != 'global':
            return None

        target_key = str(op.result.value)
        return _build_effect_event(op, EFFECT_CATEGORY_WRITE_GLOBAL, EFFECT_CATEGORY_WRITE_GLOBAL, target_key)

    if op.kind == OperationKind.RETURN:
        target_key = _normalize_operand_key(op.operands[0] if op.operands else None)
        return _build_effect_event(op, EFFECT_CATEGORY_RETURN, RETURN_FAMILY, target_key)

    return None


def build_effect_event_sequence(ops: List[SemanticOperation]) -> List[EffectEvent]:
    events: List[EffectEvent] = []
    for op in ops:
        event = semantic_op_to_effect_event(op)
        if event is not None:
            events.append(event)
    return events


def _best_first_matches(
    sources: List[Any],
    targets: List[Any],
    score_of: Callable[[Any, Any], int],
    minimum_score: int,
) -> List[Tuple[int, int]]:
    """(source index, target index) pairs scoring at least minimum_score, taken greedily: best score first, then
    nearest indices; each index used once"""
    candidates: List[Tuple[int, int, int]] = []
    for source_index, source in enumerate(sources):
        for target_index, target in enumerate(targets):
            score = score_of(source, target)
            if score >= minimum_score:
                candidates.append((score, source_index, target_index))

    candidates.sort(key=lambda item: (-item[0], abs(item[1] - item[2])))
    matches: List[Tuple[int, int]] = []
    used_source_indices: set[int] = set()
    used_target_indices: set[int] = set()

    for _, source_index, target_index in candidates:
        if source_index in used_source_indices or target_index in used_target_indices:
            continue
        matches.append((source_index, target_index))
        used_source_indices.add(source_index)
        used_target_indices.add(target_index)

    return matches


def _effect_match_score(source_event: EffectEvent, target_event: EffectEvent) -> int:
    if source_event.category != target_event.category:
        return 0

    score = 0
    if _has_provenance_overlap(source_event.provenance_keys, target_event.provenance_keys):
        score += PROVENANCE_MATCH_SCORE

    if (
        source_event.source_location.scp_offset != 0
        and source_event.source_location.scp_offset == target_event.source_location.scp_offset
    ):
        score += ADDRESS_MATCH_SCORE

    if source_event.signature == target_event.signature:
        score += SIGNATURE_MATCH_SCORE

    if (
        source_event.family == target_event.family
        and source_event.target_key != UNKNOWN_TARGET_KEY
        and source_event.target_key == target_event.target_key
    ):
        score += FAMILY_TARGET_MATCH_SCORE

    return score


def _match_effect_events(
    source_events: List[EffectEvent],
    target_events: List[EffectEvent],
) -> Tuple[List[Tuple[int, int]], List[int], List[int]]:
    matches = _best_first_matches(source_events, target_events, _effect_match_score, MIN_EFFECT_MATCH_SCORE)
    matched_sources = {source_index for source_index, _ in matches}
    matched_targets = {target_index for _, target_index in matches}

    unmatched_source = [index for index in range(len(source_events)) if index not in matched_sources]
    unmatched_target = [index for index in range(len(target_events)) if index not in matched_targets]

    # Identical returns on both sides of a branch are merged into one on the way to
    # HLIL, so several source returns can share a target return
    matched_return_signatures = {
        source_events[source_index].signature
        for source_index, _ in matches
        if source_events[source_index].category == EFFECT_CATEGORY_RETURN
    }
    unmatched_source = [
        index for index in unmatched_source
        if not (source_events[index].category == EFFECT_CATEGORY_RETURN
                and source_events[index].signature in matched_return_signatures)
    ]

    matches.sort()
    return matches, unmatched_source, unmatched_target


def _normalize_condition_signature(op: SemanticOperation) -> str:
    if op.operator in ('WHILE', 'IF'):
        operands = [operand.signature for operand in op.operands]
        joined = ",".join(sorted(operands))
        return f"branch_condition:{joined}"

    if op.operator in ('EQ', 'NE', 'LT', 'LE', 'GT', 'GE'):
        if len(op.operands) >= 2:
            left = op.operands[0].signature
            right = op.operands[1].signature
            if op.operator in ('EQ', 'NE'):
                pair = "|".join(sorted([left, right]))
                return f"{op.operator}:{pair}"
            return f"{op.operator}:{left}|{right}"
    return _semantic_fingerprint(op)


def _is_condition_semantically_equivalent(source: SemanticOperation, target: SemanticOperation) -> bool:
    source_sig = _normalize_condition_signature(source)
    target_sig = _normalize_condition_signature(target)
    if source_sig == target_sig:
        return True

    equivalent_pairs = {
        ('GOTO', 'WHILE'),
    }
    if (source.operator, target.operator) in equivalent_pairs or (target.operator, source.operator) in equivalent_pairs:
        return True
    return False


def _condition_match_score(source_condition: SemanticOperation, target_condition: SemanticOperation) -> int:
    score = 0
    if _has_provenance_overlap(
        source_condition.provenance_keys,
        target_condition.provenance_keys,
    ):
        score += PROVENANCE_MATCH_SCORE

    if _is_condition_semantically_equivalent(source_condition, target_condition):
        score += CONDITION_EQUIVALENT_MATCH_SCORE

    return score


def _hard_fail_category_for_event(event: EffectEvent, missing_target: bool) -> str:
    prefix = 'missing' if missing_target else 'added'
    if event.category == EFFECT_CATEGORY_CALL:
        return f"{prefix}_call_anchor"
    if event.category == EFFECT_CATEGORY_RETURN:
        return f"{prefix}_return_anchor"
    return f"{prefix}_write_anchor"


def _build_hard_fail(
    category: str,
    source_layer: IRLayer,
    target_layer: IRLayer,
    explanation: str,
    source_location: SourceLocation,
    source_op: Optional[SemanticOperation] = None,
    target_op: Optional[SemanticOperation] = None,
) -> ComparisonResult:
    return ComparisonResult(
        status=ComparisonStatus.DIFFERENT,
        source_layer=source_layer,
        target_layer=target_layer,
        source_op=source_op,
        target_op=target_op,
        explanation=f"HARD_FAIL: {category}: {explanation}",
        source_location=source_location,
    )


def validate_hard_fail_semantics(
    source_ops: List[SemanticOperation],
    target_ops: List[SemanticOperation],
    source_layer: IRLayer,
    target_layer: IRLayer,
) -> List[ComparisonResult]:
    violations: List[ComparisonResult] = []

    source_events = build_effect_event_sequence(source_ops)
    target_events = build_effect_event_sequence(target_ops)
    matched_events, unmatched_source_indices, unmatched_target_indices = _match_effect_events(
        source_events, target_events
    )

    for source_index in unmatched_source_indices:
        event = source_events[source_index]
        violations.append(_build_hard_fail(
            _hard_fail_category_for_event(event, missing_target=True),
            source_layer,
            target_layer,
            f"Missing target effect {event.signature}",
            event.source_location,
        ))

    for target_index in unmatched_target_indices:
        event = target_events[target_index]
        violations.append(_build_hard_fail(
            _hard_fail_category_for_event(event, missing_target=False),
            source_layer,
            target_layer,
            f"Added target effect {event.signature}",
            event.source_location,
        ))

    for (previous_source, previous_target), (current_source, current_target) in pairwise(matched_events):
        previous_source_event = source_events[previous_source]
        current_source_event = source_events[current_source]
        if previous_source_event.category != current_source_event.category:
            continue
        if previous_target < current_target:
            continue
        violations.append(_build_hard_fail(
            'local_order_violation',
            source_layer,
            target_layer,
            (
                f"Critical effect order reversed for {previous_source_event.category}: "
                f"{previous_source_event.signature} before {current_source_event.signature}"
            ),
            previous_source_event.source_location,
        ))

    source_conditions = [op for op in source_ops if op.operator in CRITICAL_BRANCH_OPERATORS]
    target_conditions = [op for op in target_ops if op.operator in CRITICAL_BRANCH_OPERATORS]
    condition_matches = _best_first_matches(
        source_conditions, target_conditions, _condition_match_score, MIN_CONDITION_MATCH_SCORE
    )
    for source_index, target_index in condition_matches:
        source_condition = source_conditions[source_index]
        target_condition = target_conditions[target_index]
        if not _is_condition_semantically_equivalent(source_condition, target_condition):
            violations.append(_build_hard_fail(
                'control_reachability_change',
                source_layer,
                target_layer,
                f"Control condition mismatch: {source_condition.operator} vs {target_condition.operator}",
                source_condition.source_location,
                source_op=source_condition,
                target_op=target_condition,
            ))

    return violations


def _extract_hard_fail_category(explanation: str) -> str:
    prefix = 'HARD_FAIL: '
    if not explanation.startswith(prefix):
        return 'unknown'
    remainder = explanation[len(prefix):]
    return remainder.split(':', 1)[0].strip()


def _compute_quality_metrics(
    source_ops: List[SemanticOperation],
    target_ops: List[SemanticOperation],
    hard_fail_violations: List[ComparisonResult],
) -> Dict[str, Union[int, float, Dict[str, int]]]:
    source_atoms = extract_semantic_atoms(source_ops)
    target_atoms = extract_semantic_atoms(target_ops)
    critical_source_atoms = [atom for atom in source_atoms if atom.critical]
    matched_pairs, provenance_match_count, fallback_match_count = _match_atoms_provenance_first(
        source_atoms, target_atoms
    )

    source_with_provenance = sum(1 for atom in source_atoms if atom.provenance_keys)
    provenance_coverage = 100.0 * source_with_provenance / len(source_atoms) if source_atoms else 100.0

    matched_source_indices = {source_idx for source_idx, _ in matched_pairs}
    matched_critical = sum(
        1
        for source_idx, source_atom in enumerate(source_atoms)
        if source_atom.critical and source_idx in matched_source_indices
    )
    critical_match_rate = (
        100.0 * matched_critical / len(critical_source_atoms) if critical_source_atoms else 100.0
    )
    unmatched_critical = len(critical_source_atoms) - matched_critical

    hard_fail_counts: Dict[str, int] = {}
    for violation in hard_fail_violations:
        key = _extract_hard_fail_category(violation.explanation)
        hard_fail_counts[key] = hard_fail_counts.get(key, 0) + 1

    return {
        "provenance_coverage": round(provenance_coverage, 1),
        "critical_atom_match_rate": round(critical_match_rate, 1),
        "unmatched_critical": unmatched_critical,
        "provenance_matched_atoms": provenance_match_count,
        "fallback_matched_atoms": fallback_match_count,
        "hard_fail_counts": hard_fail_counts,
    }


# =============================================================================
# Section 9: Unified IRLayerComparator
# =============================================================================

class IRLayerComparator:
    """Unified CFG-based comparator for any adjacent IR layer pair.

    Replaces both LLILMLILComparator and MLILHLILComparator with a single
    parameterized class that uses CFG block matching for all comparisons.
    """

    def __init__(
        self,
        source_cfg: CFG,
        target_cfg: CFG,
        source_layer: IRLayer,
        target_layer: IRLayer,
        transform_rules: List[TransformationRule],
        min_provenance_coverage: float = 0.0,
        max_unmatched_critical: int = -1,
        target_hard_fails: Optional[List[ComparisonResult]] = None,
    ):
        self.source_cfg = source_cfg
        self.target_cfg = target_cfg
        self.source_layer = source_layer
        self.target_layer = target_layer
        self.transform_rules = transform_rules
        self.min_provenance_coverage = min_provenance_coverage
        self.max_unmatched_critical = max_unmatched_critical

        # Failures found in the target layer itself rather than by comparing it
        self.target_hard_fails = target_hard_fails or []

    def _result(
        self,
        status: ComparisonStatus,
        explanation: str,
        source_op: Optional[SemanticOperation] = None,
        target_op: Optional[SemanticOperation] = None,
    ) -> ComparisonResult:
        """A result for this layer pair, located at its source operation, else at its target operation"""
        located = source_op or target_op
        return ComparisonResult(
            status=status,
            source_layer=self.source_layer,
            target_layer=self.target_layer,
            source_op=source_op,
            target_op=target_op,
            explanation=explanation,
            source_location=located.source_location if located else SourceLocation(),
        )

    def compare(self) -> ComparisonReport:
        """Run full CFG-based comparison and return a ComparisonReport."""
        report = ComparisonReport(
            source_layer=self.source_layer,
            target_layer=self.target_layer,
        )

        # Match blocks
        matcher = CFGMatcher(self.source_cfg, self.target_cfg)
        block_matches = matcher.match()

        matched_source = {m[0] for m in block_matches}
        matched_target = {m[1] for m in block_matches}

        # Statistics
        stats = report.statistics
        stats.total_source_blocks = len(self.source_cfg.nodes)
        stats.matched_blocks = len(block_matches)

        # Count total source ops
        for node in self.source_cfg.nodes.values():
            stats.total_source_ops += len(node.operations)

        # Compare matched blocks
        for src_id, tgt_id in block_matches:
            src_node = self.source_cfg.get_node(src_id)
            tgt_node = self.target_cfg.get_node(tgt_id)
            sim_score = compute_combined_block_similarity(src_node, tgt_node)

            src_offset = src_node.address
            tgt_offset = tgt_node.address

            block_result = BlockComparisonResult(
                source_block_id=src_id,
                target_block_id=tgt_id,
                similarity=sim_score,
                source_offset=src_offset,
                target_offset=tgt_offset,
            )

            aligned = align_operations(src_node.operations, tgt_node.operations)

            for src_op, tgt_op in aligned:
                if src_op is None and tgt_op is not None:
                    # Target-only operation (added by transformation)
                    result = self._result(ComparisonStatus.TRANSFORMED, f"Added: {tgt_op.operator}", target_op=tgt_op)
                    stats.transformed += 1
                elif src_op is not None and tgt_op is None:
                    # Source-only operation (eliminated)
                    result = self._result(ComparisonStatus.ELIMINATED, f"Eliminated: {src_op.operator}", src_op)
                    stats.eliminated += 1
                else:
                    # Both present - classify
                    status = classify_difference(src_op, tgt_op, self.transform_rules)
                    if status == ComparisonStatus.EQUIVALENT:
                        explanation = f"{src_op.operator} == {tgt_op.operator}"
                    elif status == ComparisonStatus.TRANSFORMED:
                        explanation = f"{src_op.operator} -> {tgt_op.operator}"
                    else:
                        explanation = f"Mismatch: {src_op.operator} vs {tgt_op.operator}"

                    result = self._result(status, explanation, src_op, tgt_op)

                    if status == ComparisonStatus.EQUIVALENT:
                        stats.equivalent += 1
                    elif status == ComparisonStatus.TRANSFORMED:
                        stats.transformed += 1
                    else:
                        stats.different += 1

                    stats.aligned_ops += 1

                block_result.results.append(result)

            report.block_results.append(block_result)

        # Handle unmatched source blocks (ELIMINATED)
        for node_id, node in self.source_cfg.nodes.items():
            if node_id not in matched_source and node.operations:
                report.unmatched_source_blocks.append(node_id)
                block_result = BlockComparisonResult(
                    source_block_id=node_id,
                    target_block_id=-1,
                    similarity=0.0,
                    source_offset=node.address,
                    target_offset=0,
                )
                for op in node.operations:
                    stats.eliminated += 1
                    block_result.results.append(
                        self._result(ComparisonStatus.ELIMINATED, f"Eliminated: {op.operator}", op)
                    )
                report.block_results.append(block_result)

        # Handle unmatched target blocks
        for node_id, node in self.target_cfg.nodes.items():
            if node_id not in matched_target and node.operations:
                report.unmatched_target_blocks.append(node_id)
                block_result = BlockComparisonResult(
                    source_block_id=-1,
                    target_block_id=node_id,
                    similarity=0.0,
                    source_offset=0,
                    target_offset=node.address,
                )
                for op in node.operations:
                    block_result.results.append(
                        self._result(ComparisonStatus.INLINED, f"Added: {op.operator}", target_op=op)
                    )
                    stats.inlined += 1
                report.block_results.append(block_result)

        # Hard-fail and quality checks over every operation
        all_source_ops: List[SemanticOperation] = []
        all_target_ops: List[SemanticOperation] = []
        for node in self.source_cfg.nodes.values():
            all_source_ops.extend(node.operations)
        for node in self.target_cfg.nodes.values():
            all_target_ops.extend(node.operations)

        report.hard_fail_violations = validate_hard_fail_semantics(
            all_source_ops, all_target_ops, self.source_layer, self.target_layer
        )
        report.hard_fail_violations.extend(self.target_hard_fails)
        report.quality_metrics = _compute_quality_metrics(
            all_source_ops, all_target_ops, report.hard_fail_violations
        )

        provenance_coverage = report.quality_metrics["provenance_coverage"]
        unmatched_critical = report.quality_metrics["unmatched_critical"]
        if provenance_coverage < self.min_provenance_coverage:
            report.soft_signal_warnings.append(self._result(
                ComparisonStatus.TRANSFORMED,
                f"SOFT_SIGNAL: Provenance coverage {provenance_coverage:.1f}% below "
                f"threshold {self.min_provenance_coverage:.1f}%",
            ))

        if self.max_unmatched_critical >= 0 and unmatched_critical > self.max_unmatched_critical:
            report.hard_fail_violations.append(self._result(
                ComparisonStatus.DIFFERENT,
                f"HARD_FAIL: unmatched critical atoms {unmatched_critical} exceeds "
                f"threshold {self.max_unmatched_critical}",
            ))

        # Set pass/fail
        stats.hard_fail += len(report.hard_fail_violations)
        stats.soft_signal += len(report.soft_signal_warnings)
        allow_structural_drift = (
            self.source_layer == IRLayer.MLIL and self.target_layer == IRLayer.HLIL
        )
        report.passed = (
            (allow_structural_drift or stats.different == 0)
            and len(report.hard_fail_violations) == 0
        )

        return report


def compare_llil_mlil(
    llil_func: LowLevelILFunction,
    mlil_func: MediumLevelILFunction,
    func_name: str = "",
    min_provenance_coverage: float = 0.0,
    max_unmatched_critical: int = -1,
) -> ComparisonReport:
    """Convenience: compare LLIL and MLIL layers using CFG matching"""
    llil_cfg = build_cfg_from_llil(llil_func)
    mlil_cfg = build_cfg_from_mlil(mlil_func)

    comparator = IRLayerComparator(
        source_cfg=llil_cfg,
        target_cfg=mlil_cfg,
        source_layer=IRLayer.LLIL,
        target_layer=IRLayer.MLIL,
        transform_rules=LLIL_MLIL_TRANSFORMATIONS,
        min_provenance_coverage=min_provenance_coverage,
        max_unmatched_critical=max_unmatched_critical,
    )
    report = comparator.compare()
    report.function_name = func_name
    return report


def _unstructured_jump_failures(hlil_func: HighLevelILFunction) -> List[ComparisonResult]:
    """A HARD_FAIL for every jump HLIL could not express on a path that can run"""
    return [
        _build_hard_fail(
            'unstructured_jump',
            IRLayer.MLIL,
            IRLayer.HLIL,
            f"Unstructured jump to {stmt.target} ({stmt.reason})",
            SourceLocation(scp_offset=stmt.address, mlil_index=stmt.mlil_index),
        )
        for stmt in reachable_statements(hlil_func.body)
        if isinstance(stmt, HLILUnstructured)
    ]


def compare_mlil_hlil(
    mlil_func: MediumLevelILFunction,
    hlil_func: HighLevelILFunction,
    func_name: str = "",
    min_provenance_coverage: float = 0.0,
    max_unmatched_critical: int = -1,
) -> ComparisonReport:
    """Convenience: compare MLIL and HLIL layers using CFG matching"""
    mlil_cfg = build_cfg_from_mlil(mlil_func)
    hlil_cfg = build_cfg_from_hlil(hlil_func)

    comparator = IRLayerComparator(
        source_cfg=mlil_cfg,
        target_cfg=hlil_cfg,
        source_layer=IRLayer.MLIL,
        target_layer=IRLayer.HLIL,
        transform_rules=MLIL_HLIL_TRANSFORMATIONS,
        min_provenance_coverage=min_provenance_coverage,
        max_unmatched_critical=max_unmatched_critical,
        target_hard_fails=_unstructured_jump_failures(hlil_func),
    )
    report = comparator.compare()
    report.function_name = func_name
    return report


def compare_function(
    pipeline: IRPipeline,
    func_name: str,
    llil: LowLevelILFunction,
    mlil: MediumLevelILFunction,
    hlil: HighLevelILFunction,
    **gates: Any,
) -> FunctionReport:
    """Both layer comparisons of one pipeline function, under the quality gates (compare_llil_mlil's keywords); the
    MLIL -> HLIL one only where HLIL conversion succeeded"""
    func_report = FunctionReport(function_name=func_name)
    func_report.llil_mlil = compare_llil_mlil(llil, mlil, func_name, **gates)
    if pipeline.can_compare_mlil_hlil(func_name):
        func_report.mlil_hlil = compare_mlil_hlil(mlil, hlil, func_name, **gates)
    return func_report


# =============================================================================
# Section 10: Output Formatting + Validation Runner
# =============================================================================

PROGRESS_LINE_WIDTH = 70


class Progress:
    """Progress reporter for stderr"""

    def update(self, idx: int, total: int, label: str) -> None:
        print(f"\r  [{idx}/{total}] {label:<50s}", end="", file=sys.stderr, flush=True)

    def clear(self) -> None:
        print("\r" + " " * PROGRESS_LINE_WIDTH + "\r", end="", file=sys.stderr, flush=True)


class Formatter:
    """Encapsulates all output formatting with color support"""

    def __init__(self, use_color: bool = True):
        self.green = "\033[32m" if use_color else ""
        self.yellow = "\033[33m" if use_color else ""
        self.red = "\033[31m" if use_color else ""
        self.cyan = "\033[36m" if use_color else ""
        self.dim = "\033[2m" if use_color else ""
        self.reset = "\033[0m" if use_color else ""

    def _status_color(self, status: ComparisonStatus) -> str:
        if status == ComparisonStatus.EQUIVALENT:
            return self.green
        elif status == ComparisonStatus.TRANSFORMED:
            return self.yellow
        elif status == ComparisonStatus.ELIMINATED:
            return self.dim
        else:
            return self.red

    def comparison_report(self, report: ComparisonReport) -> str:
        """Format a comparison report as block-centric text output"""
        lines: List[str] = []

        src_name = report.source_layer.name
        tgt_name = report.target_layer.name

        if report.function_name:
            lines.append(f"{self.cyan}=== {report.function_name}: {src_name} -> {tgt_name} ==={self.reset}")
        else:
            lines.append(f"{self.cyan}=== {src_name} -> {tgt_name} ==={self.reset}")

        lines.append(self.match_statistics(report.statistics))
        lines.append("")

        for block in report.block_results:
            if block.target_block_id == -1:
                lines.append(
                    f"{src_name} Block {block.source_block_id} [0x{block.source_offset:X}] -> (eliminated)"
                )
            elif block.source_block_id == -1:
                lines.append(
                    f"{tgt_name} Block {block.target_block_id} [0x{block.target_offset:X}] (added)"
                )
            else:
                lines.append(
                    f"Block {block.source_block_id} [0x{block.source_offset:X}] <-> "
                    f"Block {block.target_block_id} [0x{block.target_offset:X}] "
                    f"(similarity: {block.similarity:.2f})"
                )

            for result in block.results:
                symbol = STATUS_SYMBOLS[result.status]
                addr = result.source_location.scp_offset
                scp_offset = f"[0x{addr:X}]"
                color = self._status_color(result.status)

                src_text = str(result.source_op) if result.source_op else "(none)"
                tgt_text = str(result.target_op) if result.target_op else "(eliminated)"

                if result.status == ComparisonStatus.ELIMINATED:
                    lines.append(f"  {color}{scp_offset} {symbol} {src_text} -> {tgt_text}{self.reset}")
                else:
                    lines.append(f"  {color}{scp_offset} {symbol} {src_text} <-> {tgt_text}{self.reset}")

            lines.append("")

        if report.hard_fail_violations:
            lines.append(f"{self.red}Hard-Fail Violations:{self.reset}")
            for violation in report.hard_fail_violations:
                lines.append(f"  {self.red}! {violation.explanation}{self.reset}")
            lines.append("")

        if report.soft_signal_warnings:
            lines.append(f"{self.yellow}Soft Signals:{self.reset}")
            for warning in report.soft_signal_warnings:
                lines.append(f"  {self.yellow}~ {warning.explanation}{self.reset}")
            lines.append("")

        if report.quality_metrics:
            lines.append("Quality Metrics:")
            lines.append(
                f"  provenance_coverage:   {report.quality_metrics.get('provenance_coverage', 0.0)}%"
            )
            lines.append(
                f"  critical_match_rate:   {report.quality_metrics.get('critical_atom_match_rate', 0.0)}%"
            )
            lines.append(
                f"  unmatched_critical:    {report.quality_metrics.get('unmatched_critical', 0)}"
            )
            lines.append("")

        return "\n".join(lines)

    def match_statistics(self, stats: MatchStatistics) -> str:
        """Format match statistics block"""
        lines: List[str] = []

        lines.append("Match Statistics:")
        lines.append(
            f"  Block coverage:     {stats.matched_blocks}/{stats.total_source_blocks} "
            f"matched ({stats.block_coverage:.1f}%)"
        )
        lines.append(
            f"  Operation coverage: {stats.aligned_ops}/{stats.total_source_ops} "
            f"aligned ({stats.op_coverage:.1f}%)"
        )
        lines.append("")

        pcts = stats.status_percentages()

        lines.append(f"  {self.green}= Equivalent:   {stats.equivalent:4d} ({pcts['EQUIVALENT']:5.1f}%){self.reset}")
        lines.append(f"  {self.yellow}~ Transformed:  {stats.transformed:4d} ({pcts['TRANSFORMED']:5.1f}%){self.reset}")
        lines.append(f"  {self.red}! Different:    {stats.different:4d} ({pcts['DIFFERENT']:5.1f}%){self.reset}")
        lines.append(f"  {self.dim}o Eliminated:   {stats.eliminated:4d} ({pcts['ELIMINATED']:5.1f}%){self.reset}")
        lines.append(f"  {self.cyan}> Inlined:      {stats.inlined:4d} ({pcts['INLINED']:5.1f}%){self.reset}")
        lines.append(f"  {self.red}! Hard-Fail:    {stats.hard_fail:4d}{self.reset}")
        lines.append(f"  {self.yellow}~ Soft-Signal:  {stats.soft_signal:4d}{self.reset}")

        return "\n".join(lines)

    def layer_summary(self, label: str, reports: List[ComparisonReport]) -> str:
        """Format aggregate summary for a list of comparison reports (one layer pair)"""
        aggregate = MatchStatistics()
        for r in reports:
            aggregate.accumulate(r.statistics)

        passed = sum(1 for r in reports if r.passed)
        total = len(reports)

        lines: List[str] = []
        lines.append(f"{label}: {passed}/{total} passed")
        lines.append(self.match_statistics(aggregate))
        return "\n".join(lines)

    def func_report(self, fr: FunctionReport) -> str:
        """Format a single function's batch result"""
        lines: List[str] = []
        lines.append(f"  {self.cyan}{fr.function_name}{self.reset}")

        for label, report in (("LLIL->MLIL", fr.llil_mlil), ("MLIL->HLIL", fr.mlil_hlil)):
            if report:
                s = report.statistics
                status = f"{self.green}PASS{self.reset}" if report.passed else f"{self.red}FAIL{self.reset}"
                lines.append(
                    f"    {label}: {status}  "
                    f"blocks={s.matched_blocks}/{s.total_source_blocks}  "
                    f"eq={s.equivalent} trans={s.transformed} diff={s.different} "
                    f"elim={s.eliminated}"
                )

        return "\n".join(lines)

    @classmethod
    def report_to_json(cls, report: ComparisonReport) -> Dict[str, Any]:
        """Convert ComparisonReport to JSON-serializable dict"""
        s = report.statistics
        return {
            "source_layer": report.source_layer.name,
            "target_layer": report.target_layer.name,
            "function": report.function_name,
            "passed": report.passed,
            "statistics": {
                "block_coverage": {
                    "matched": s.matched_blocks,
                    "total": s.total_source_blocks,
                    "percentage": round(s.block_coverage, 1),
                },
                "operation_coverage": {
                    "aligned": s.aligned_ops,
                    "total": s.total_source_ops,
                    "percentage": round(s.op_coverage, 1),
                },
                "status_counts": {
                    "equivalent": s.equivalent,
                    "transformed": s.transformed,
                    "different": s.different,
                    "eliminated": s.eliminated,
                    "inlined": s.inlined,
                    "hard_fail": s.hard_fail,
                    "soft_signal": s.soft_signal,
                },
            },
            "quality_metrics": report.quality_metrics,
            "block_results": [
                {
                    "source_block": br.source_block_id,
                    "source_offset": f"0x{br.source_offset:X}",
                    "target_block": br.target_block_id,
                    "target_offset": f"0x{br.target_offset:X}",
                    "similarity": round(br.similarity, 3),
                    "results": [
                        {
                            "status": r.status.name,
                            "source_op": str(r.source_op) if r.source_op else None,
                            "target_op": str(r.target_op) if r.target_op else None,
                            "scp_offset": r.source_location.scp_offset,
                            "explanation": r.explanation,
                        }
                        for r in br.results
                    ],
                }
                for br in report.block_results
            ],
            "unmatched_source_blocks": report.unmatched_source_blocks,
            "unmatched_target_blocks": report.unmatched_target_blocks,
            "hard_fail_violations": len(report.hard_fail_violations),
            "soft_signal_warnings": len(report.soft_signal_warnings),
        }

    @classmethod
    def function_report_to_json(cls, fr: FunctionReport) -> Dict[str, Any]:
        """Convert FunctionReport to JSON-serializable dict"""
        result: Dict[str, Any] = {"function": fr.function_name}

        if fr.llil_mlil:
            result["llil_mlil"] = cls.report_to_json(fr.llil_mlil)

        if fr.mlil_hlil:
            result["mlil_hlil"] = cls.report_to_json(fr.mlil_hlil)

        return result


class Validator:
    """Runs comparisons and outputs results"""

    def __init__(
        self,
        pipeline: IRPipeline,
        formatter: Formatter,
        progress: Progress,
        stream: TextIO = sys.stdout,
        as_json: bool = False,
        min_provenance_coverage: float = 0.0,
        max_unmatched_critical: int = -1,
    ):
        self.pipeline = pipeline
        self.fmt = formatter
        self.progress = progress
        self.stream = stream
        self.as_json = as_json
        # The quality gates every comparison runs under: compare_llil_mlil's and compare_mlil_hlil's keywords
        self.gates = dict(
            min_provenance_coverage=min_provenance_coverage, max_unmatched_critical=max_unmatched_critical
        )

    def _print(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    def compare(self, layer1: str, layer2: str) -> int:
        """Compare a single layer pair across all functions"""
        layer1 = layer1.lower()
        layer2 = layer2.lower()

        all_reports: List[ComparisonReport] = []
        total = len(self.pipeline.functions)
        label = f"{layer1.upper()}->{layer2.upper()}"

        for idx, (func_name, llil, mlil, hlil) in enumerate(self.pipeline.functions, 1):
            self.progress.update(idx, total, f"{label} {func_name}")

            if layer1 == "llil" and layer2 == "mlil":
                report = compare_llil_mlil(llil, mlil, func_name, **self.gates)
            elif layer1 == "mlil" and layer2 == "hlil":
                if not self.pipeline.can_compare_mlil_hlil(func_name):
                    continue
                report = compare_mlil_hlil(mlil, hlil, func_name, **self.gates)
            else:
                print(f"Unsupported layer pair: {layer1} -> {layer2}", file=sys.stderr)
                return 1

            all_reports.append(report)

            if not self.as_json:
                self._print(self.fmt.comparison_report(report))
                self._print("")

        self.progress.clear()

        if self.as_json:
            json_output = [Formatter.report_to_json(r) for r in all_reports]
            self._print(json.dumps(json_output, indent=2))
        else:
            self._print(f"\n{self.fmt.layer_summary(label, all_reports)}")

        has_failures = any(not r.passed for r in all_reports)
        return 1 if has_failures else 0

    def batch(self, failed_only: bool = False) -> int:
        """Batch validate all functions across both layer pairs"""
        total = len(self.pipeline.functions)

        if not self.as_json:
            self._print(f"{self.fmt.cyan}=== Batch Validation: {self.pipeline.scp_path} ==={self.fmt.reset}")
            self._print(f"Functions: {total}\n")

        all_func_reports: List[FunctionReport] = []

        for idx, (func_name, llil, mlil, hlil) in enumerate(self.pipeline.functions, 1):
            self.progress.update(idx, total, f"Comparing {func_name}")

            func_report = compare_function(self.pipeline, func_name, llil, mlil, hlil, **self.gates)

            llil_ok = func_report.llil_mlil.passed if func_report.llil_mlil else True
            hlil_ok = func_report.mlil_hlil.passed if func_report.mlil_hlil else True

            all_func_reports.append(func_report)

            if not self.as_json:
                show_llil = not failed_only or not llil_ok
                show_hlil = not failed_only or not hlil_ok
                if show_llil or show_hlil:
                    self._print(self.fmt.func_report(func_report))
                    if func_report.llil_mlil and show_llil:
                        self._print(self.fmt.comparison_report(func_report.llil_mlil))
                    if func_report.mlil_hlil and show_hlil:
                        self._print(self.fmt.comparison_report(func_report.mlil_hlil))

        self.progress.clear()

        llil_mlil_reports = [fr.llil_mlil for fr in all_func_reports if fr.llil_mlil]
        mlil_hlil_reports = [fr.mlil_hlil for fr in all_func_reports if fr.mlil_hlil]

        if self.as_json:
            json_output = {
                "scp_path": self.pipeline.scp_path,
                "total_functions": total,
                "functions": [Formatter.function_report_to_json(fr) for fr in all_func_reports],
            }
            self._print(json.dumps(json_output, indent=2))
        else:
            self._print(f"\n{self.fmt.layer_summary('LLIL->MLIL', llil_mlil_reports)}")
            self._print(f"\n{self.fmt.layer_summary('MLIL->HLIL', mlil_hlil_reports)}")

        all_passed = all(r.passed for r in llil_mlil_reports) and all(r.passed for r in mlil_hlil_reports)
        return 0 if all_passed else 1

    def output_dir(self, dir_path: str) -> int:
        """Write LLIL-MLIL and MLIL-HLIL results to separate files"""
        out_path = Path(dir_path)
        out_path.mkdir(parents=True, exist_ok=True)

        scp_name = Path(self.pipeline.scp_path).stem
        no_color_fmt = Formatter(use_color=False)

        for layer1, layer2 in (("llil", "mlil"), ("mlil", "hlil")):
            pair_file = out_path / f"{scp_name}_{layer1}_{layer2}.txt"
            with open(pair_file, 'w', encoding='utf-8') as f:
                file_validator = Validator(self.pipeline, no_color_fmt, self.progress, f, self.as_json, **self.gates)
                file_validator.compare(layer1, layer2)
            print(f"{layer1.upper()}->{layer2.upper()}: {pair_file}", file=sys.stderr)

        return 0


# =============================================================================
# Section 11: CLI + Main
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    arg_parser = argparse.ArgumentParser(
        description="IR Semantic Consistency Validator (CFG-based)"
    )
    arg_parser.add_argument("scp_file", help="Path to SCP file")
    arg_parser.add_argument(
        "--compare", nargs=2, metavar=("LAYER1", "LAYER2"),
        help="Compare two IR layers (e.g., llil mlil)"
    )
    arg_parser.add_argument("--all", action="store_true", help="Compare all layer pairs")
    arg_parser.add_argument("--batch", action="store_true", help="Batch validate all functions")
    arg_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    arg_parser.add_argument("--no-color", action="store_true", help="Disable color output")
    arg_parser.add_argument("--function", metavar="NAME", help="Filter specific function")
    arg_parser.add_argument("--failed-only", action="store_true", help="Show only failed functions in batch mode")
    arg_parser.add_argument("--export-regression", metavar="FILE", help="Export regression baseline")
    arg_parser.add_argument("--compare-regression", metavar="FILE", help="Compare against regression baseline")
    arg_parser.add_argument("--output-dir", metavar="DIR", help="Write results to separate files per layer pair")
    arg_parser.add_argument(
        "--min-provenance-coverage",
        type=float,
        default=0.0,
        help="Fail quality gate if provenance coverage falls below this percentage (0-100)"
    )
    arg_parser.add_argument(
        "--max-unmatched-critical",
        type=int,
        default=-1,
        help="Fail quality gate if unmatched critical atom count exceeds this value (-1 disables)"
    )

    return arg_parser


# =============================================================================
# Section 12: Regression Testing
# =============================================================================

def export_baseline(pipeline: IRPipeline, output_file: str) -> bool:
    """Export validation results as regression baseline"""
    function_results = []

    for func_name, llil, mlil, hlil in pipeline.functions:
        func_report = compare_function(pipeline, func_name, llil, mlil, hlil)
        function_results.append(Formatter.function_report_to_json(func_report))

    baseline = {
        "version": "2.0",
        "file": pipeline.scp_path,
        "functions": function_results,
    }

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=2)
        return True
    except Exception as e:
        print(f"Error exporting baseline: {e}", file=sys.stderr)
        return False


def compare_baseline(pipeline: IRPipeline, baseline_file: str) -> int:
    """Compare current results against baseline and report differences"""
    try:
        with open(baseline_file, 'r', encoding='utf-8') as f:
            baseline = json.load(f)
    except Exception as e:
        print(f"Error loading baseline: {e}", file=sys.stderr)
        return 1

    current_results: Dict[str, Dict] = {}
    for func_name, llil, mlil, hlil in pipeline.functions:
        func_report = compare_function(pipeline, func_name, llil, mlil, hlil)
        current_results[func_name] = Formatter.function_report_to_json(func_report)

    baseline_results = {f["function"]: f for f in baseline.get("functions", [])}

    regressions = []
    improvements = []

    def extract_gate_count(result: Dict[str, Any], layer_key: str) -> int:
        layer = result.get(layer_key, {})
        stats = layer.get("statistics", {})
        status_counts = stats.get("status_counts", {})
        return int(status_counts.get("hard_fail", 0))

    for func_name, current in current_results.items():
        if func_name not in baseline_results:
            continue

        base = baseline_results[func_name]

        for layer_key in ("llil_mlil", "mlil_hlil"):
            if layer_key in current and layer_key in base:
                cur_diff = extract_gate_count(current, layer_key)
                base_diff = extract_gate_count(base, layer_key)
                layer_label = layer_key.upper().replace("_", "-")

                if cur_diff > base_diff:
                    regressions.append({
                        "function": func_name, "layer": layer_label,
                        "baseline_diff": base_diff, "current_diff": cur_diff,
                    })
                elif cur_diff < base_diff:
                    improvements.append({
                        "function": func_name, "layer": layer_label,
                        "baseline_diff": base_diff, "current_diff": cur_diff,
                    })

    print("=== Regression Test Results ===")
    print(f"Baseline: {baseline_file}")
    print(f"Functions compared: {len(current_results)}")
    print()

    if regressions:
        print(f"REGRESSIONS FOUND: {len(regressions)}")
        for r in regressions:
            print(f"  {r['function']} ({r['layer']}): {r['baseline_diff']} -> {r['current_diff']} differences")
        print()

    if improvements:
        print(f"Improvements: {len(improvements)}")
        for i in improvements:
            print(f"  {i['function']} ({i['layer']}): {i['baseline_diff']} -> {i['current_diff']} differences")
        print()

    if not regressions and not improvements:
        print("No changes detected from baseline")

    return 1 if regressions else 0


# =============================================================================
# Main Entry Point
# =============================================================================

def run_mode(args: argparse.Namespace, pipeline: IRPipeline) -> int:
    """Runs what args asks for - a regression export or comparison, or a validation - and returns its exit code"""
    # Regression testing (no formatter/progress needed)
    if args.export_regression:
        return 0 if export_baseline(pipeline, args.export_regression) else 1

    if args.compare_regression:
        return compare_baseline(pipeline, args.compare_regression)

    # Create validator
    use_color = not args.no_color and not args.output_dir
    formatter = Formatter(use_color)
    progress = Progress()
    validator = Validator(
        pipeline,
        formatter,
        progress,
        as_json=args.json,
        min_provenance_coverage=args.min_provenance_coverage,
        max_unmatched_critical=args.max_unmatched_critical,
    )

    # Dispatch
    if args.output_dir:
        return validator.output_dir(args.output_dir)

    if args.compare:
        return validator.compare(args.compare[0], args.compare[1])

    if args.all:
        # Both pairs run, in this order; either one failing fails the run
        return max(validator.compare("llil", "mlil"), validator.compare("mlil", "hlil"))

    # Default: batch (--batch asks for it by name)
    return validator.batch(args.failed_only)


def main() -> int:
    args = create_parser().parse_args()

    # Load SCP
    pipeline = IRPipeline(args.scp_file)
    if not pipeline.load():
        return 1

    # Generate IR
    if not pipeline.generate_ir(function_name=args.function):
        print("No functions found", file=sys.stderr)
        return 1

    exit_code = run_mode(args, pipeline)
    # The comparisons normalize every operation: only now are the unknown ones collected
    report_unknown_operations()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
