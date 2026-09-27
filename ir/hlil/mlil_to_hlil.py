'''MLIL to HLIL Converter - SSA-based Graph Rewriting'''

import sys
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple

from ir.mlil.mlil import *
from ir.mlil.mlil_types import MLILType, MLILTypeKind
from .hlil import *
from .structural_analysis import StructuralAnalyzer


# Operator mapping tables
_BINARY_OP_MAP = {
    MediumLevelILOperation.MLIL_ADD         : BinaryOp.ADD,
    MediumLevelILOperation.MLIL_SUB         : BinaryOp.SUB,
    MediumLevelILOperation.MLIL_MUL         : BinaryOp.MUL,
    MediumLevelILOperation.MLIL_DIV         : BinaryOp.DIV,
    MediumLevelILOperation.MLIL_MOD         : BinaryOp.MOD,
    MediumLevelILOperation.MLIL_AND         : BinaryOp.BIT_AND,
    MediumLevelILOperation.MLIL_OR          : BinaryOp.BIT_OR,
    MediumLevelILOperation.MLIL_XOR         : BinaryOp.BIT_XOR,
    MediumLevelILOperation.MLIL_SHL         : BinaryOp.SHL,
    MediumLevelILOperation.MLIL_SHR         : BinaryOp.SHR,
    MediumLevelILOperation.MLIL_LOGICAL_AND : BinaryOp.AND,
    MediumLevelILOperation.MLIL_LOGICAL_OR  : BinaryOp.OR,
    MediumLevelILOperation.MLIL_EQ          : BinaryOp.EQ,
    MediumLevelILOperation.MLIL_NE          : BinaryOp.NE,
    MediumLevelILOperation.MLIL_LT          : BinaryOp.LT,
    MediumLevelILOperation.MLIL_LE          : BinaryOp.LE,
    MediumLevelILOperation.MLIL_GT          : BinaryOp.GT,
    MediumLevelILOperation.MLIL_GE          : BinaryOp.GE,
}

_UNARY_OP_MAP = {
    MediumLevelILOperation.MLIL_NEG         : UnaryOp.NEG,
    MediumLevelILOperation.MLIL_BITWISE_NOT : UnaryOp.BIT_NOT,
}

_MLIL_TYPE_MAP = {
    MLILTypeKind.UNKNOWN  : HLILTypeKind.UNKNOWN,
    MLILTypeKind.INT      : HLILTypeKind.INT,
    MLILTypeKind.FLOAT    : HLILTypeKind.FLOAT,
    MLILTypeKind.STRING   : HLILTypeKind.STRING,
    MLILTypeKind.BOOL     : HLILTypeKind.INT,
    MLILTypeKind.POINTER  : HLILTypeKind.INT,
    MLILTypeKind.VARIANT  : HLILTypeKind.UNKNOWN,
    MLILTypeKind.VOID     : HLILTypeKind.VOID,
}

# Re-emitting a block reached from several conditions is the only faithful option
# without goto, but it grows output, so cap how far it can run per function.
CLONE_STATEMENT_BUDGET   = 400  # total statements re-emitted per function
CLONE_MAX_REGION_BLOCKS  = 48   # blocks in one re-emitted region


def _mlil_type_to_hlil(mlil_type: MLILType) -> HLILTypeKind:
    return _MLIL_TYPE_MAP[mlil_type.kind]


# ============================================================================
# Call Result Folding
# ============================================================================


class CallResultFolder:
    '''Decides which call results can be folded into the instruction that reads them.

    MLIL calls are statements writing an output variable, so a result reaches its
    reader as a separate variable read. HLIL has call expressions, so a result that
    is read once, right away, and never again becomes part of the reader:

        reg0 = f()          ->      var = f()
        var = reg0

    The fold is only legal when nothing observable sits between the call and the
    reader, and when the variable is dead afterwards. Other calls may sit there
    if they fold into the same reader, since those end up in the same expression:

        reg0 = f()          ->      if (f() == g())
        reg1 = g()
        if (reg0 == reg1)

    That makes the expression's operand order the calls' execution order, so a
    chain is only folded while the two agree.
    '''

    def __init__(self, mlil_func: MediumLevelILFunction, block_successors: Dict[int, List[int]]):
        self.mlil_func = mlil_func
        self.block_successors = block_successors
        self.predecessors: Dict[int, List[int]] = {}

        # Live variable names on exit from each block
        self.live_out: Dict[int, Set[str]] = {}

        # Call position -> reader position, for calls whose result is folded
        self.folded_call: Dict[Tuple[int, int], Tuple[int, int]] = {}

        # Reader position and variable name -> call position
        self.folded_use: Dict[Tuple[int, int, str], Tuple[int, int]] = {}

    def analyze(self):
        '''Find every call result that can be folded into its reader'''
        self._build_predecessors()
        self._compute_liveness()
        self._find_foldable_calls()

    def is_folded(self, block_idx: int, instr_idx: int) -> bool:
        '''Check whether this call is emitted as part of its reader instead'''
        return (block_idx, instr_idx) in self.folded_call

    def folded_call_at(self, block_idx: int, instr_idx: int, var_name: str) -> Optional[Tuple[int, int]]:
        '''Position of the call whose result this variable read stands for'''
        return self.folded_use.get((block_idx, instr_idx, var_name))

    def _build_predecessors(self):
        for block_idx in range(len(self.mlil_func.basic_blocks)):
            self.predecessors[block_idx] = []

        for block_idx, successors in self.block_successors.items():
            for succ in successors:
                if succ in self.predecessors:
                    self.predecessors[succ].append(block_idx)

    def _compute_liveness(self):
        '''Backward dataflow over variable names (non-SSA MLIL)'''
        block_uses: Dict[int, Set[str]] = {}
        block_defs: Dict[int, Set[str]] = {}
        block_count = len(self.mlil_func.basic_blocks)

        for block_idx, block in enumerate(self.mlil_func.basic_blocks):
            uses: Set[str] = set()
            defs: Set[str] = set()

            for instr in block.instructions:
                for name in self._read_names(instr):
                    if name not in defs:
                        uses.add(name)

                written = self._written_name(instr)
                if written is not None:
                    defs.add(written)

            block_uses[block_idx] = uses
            block_defs[block_idx] = defs
            self.live_out[block_idx] = set()

        live_in: Dict[int, Set[str]] = {idx: set() for idx in range(block_count)}

        changed = True
        while changed:
            changed = False

            for block_idx in reversed(range(block_count)):
                new_live_out: Set[str] = set()
                for succ in self.block_successors.get(block_idx, []):
                    new_live_out |= live_in.get(succ, set())

                new_live_in = block_uses[block_idx] | (new_live_out - block_defs[block_idx])

                if new_live_out != self.live_out[block_idx] or new_live_in != live_in[block_idx]:
                    self.live_out[block_idx] = new_live_out
                    live_in[block_idx] = new_live_in
                    changed = True

    def _find_foldable_calls(self):
        # Reverse program order, so a later call's decision is already made when
        # the call feeding it is considered - that is what lets chains resolve
        for block_idx in reversed(range(len(self.mlil_func.basic_blocks))):
            block = self.mlil_func.basic_blocks[block_idx]

            for instr_idx in reversed(range(len(block.instructions))):
                instr = block.instructions[instr_idx]

                if not isinstance(instr, MediumLevelILCall) or instr.output is None:
                    continue

                var_name = instr.output.name

                reader = self._resolve_reader(block_idx, instr_idx, var_name)
                if reader is None:
                    continue

                reader_block_idx, reader_instr_idx = reader
                reader_instr = self.mlil_func.basic_blocks[reader_block_idx].instructions[reader_instr_idx]

                # Exactly one read, and nothing reads it afterwards
                if self._count_reads(reader_instr, var_name) != 1:
                    continue

                if not self._is_dead_after(reader_block_idx, reader_instr_idx, var_name):
                    continue

                # The read's position must run the call exactly when and where the statement did
                if self._read_unsafe_to_fold(reader_instr, var_name):
                    continue

                self.folded_call[(block_idx, instr_idx)] = reader
                self.folded_use[(reader_block_idx, reader_instr_idx, var_name)] = (block_idx, instr_idx)

    def _resolve_reader(self, block_idx: int, instr_idx: int,
                        var_name: str) -> Optional[Tuple[int, int]]:
        '''Reader for this call result, seeing through calls that fold away

        A call whose own result is folded into a later reader does not really
        separate this call from that reader - both end up in the same expression.
        Stepping over it turns a run of `reg = f()` statements into one nested
        expression, which is what the bytecode was written as.
        '''
        position = self._find_reader(block_idx, instr_idx)
        if position is None:
            return None

        instr = self.mlil_func.basic_blocks[position[0]].instructions[position[1]]

        if not isinstance(instr, MediumLevelILCall) or instr.output is None:
            return position

        # Reading the result makes this call the reader, not something to skip
        if self._count_reads(instr, var_name) > 0:
            return position

        # Reassigning our own variable clobbers the result before anything reads it
        if instr.output.name == var_name:
            return None

        reader = self.folded_call.get(position)
        if reader is None:
            return None

        reader_instr = self.mlil_func.basic_blocks[reader[0]].instructions[reader[1]]
        order = self._read_order(reader_instr)

        if var_name not in order or instr.output.name not in order:
            return None

        # Both calls run when the expression is evaluated, so the operands have
        # to appear in the order the calls did
        if order.index(var_name) > order.index(instr.output.name):
            return None

        return reader

    def _find_reader(self, block_idx: int, instr_idx: int) -> Optional[Tuple[int, int]]:
        '''Next real instruction after this call, or None

        Only nops and unconditional jumps may be skipped, and a following block
        must be entered from this call alone. Whether that instruction is the
        reader or merely folds away too is left to `_resolve_reader`.
        '''
        block = self.mlil_func.basic_blocks[block_idx]

        for idx in range(instr_idx + 1, len(block.instructions)):
            instr = block.instructions[idx]

            if is_nop_instr(instr):
                continue

            if isinstance(instr, MLILGoto):
                break

            return (block_idx, idx)

        successors = self.block_successors.get(block_idx, [])
        if len(successors) != 1:
            return None

        succ = successors[0]
        if succ == block_idx or len(self.predecessors.get(succ, [])) != 1:
            return None

        for idx, instr in enumerate(self.mlil_func.basic_blocks[succ].instructions):
            if is_nop_instr(instr):
                continue

            if isinstance(instr, MLILGoto):
                return None

            return (succ, idx)

        return None

    def _is_dead_after(self, block_idx: int, instr_idx: int, var_name: str) -> bool:
        '''Check that nothing reads var_name after the reader before it is rewritten'''
        block = self.mlil_func.basic_blocks[block_idx]

        for idx in range(instr_idx + 1, len(block.instructions)):
            instr = block.instructions[idx]

            if var_name in self._read_names(instr):
                return False

            if self._written_name(instr) == var_name:
                return True

        return var_name not in self.live_out[block_idx]

    def _written_name(self, instr: MediumLevelILInstruction) -> Optional[str]:
        '''Variable this instruction assigns, if any'''
        if isinstance(instr, MLILSetVar):
            return instr.var.name

        if isinstance(instr, MediumLevelILCall) and instr.output is not None:
            return instr.output.name

        return None

    def _read_names(self, instr: MediumLevelILInstruction) -> Set[str]:
        '''Variable names this instruction reads'''
        return set(self._read_order(instr))

    def _read_order(self, instr: MediumLevelILInstruction) -> List[str]:
        '''Variable names this instruction reads, in evaluation order

        Folding several calls into one expression makes that expression's
        operand order their execution order, so the two have to agree.
        '''
        names: List[str] = []
        self._collect_read_names(instr, names)
        return names

    def _collect_read_names(self, node: MediumLevelILInstruction, names: List[str]):
        if isinstance(node, MLILVar):
            names.append(node.var.name)

        elif isinstance(node, MLILBinaryOp):
            self._collect_read_names(node.lhs, names)
            self._collect_read_names(node.rhs, names)

        elif isinstance(node, MLILUnaryOp):
            self._collect_read_names(node.operand, names)

        elif isinstance(node, MediumLevelILCall):
            for arg in node.args:
                self._collect_read_names(arg, names)

        elif isinstance(node, MLILSetVar):
            self._collect_read_names(node.value, names)

        elif isinstance(node, (MLILStoreReg, MLILStoreGlobal)):
            self._collect_read_names(node.value, names)

        elif isinstance(node, MLILStoreDeref):
            self._collect_read_names(node.dest, names)
            self._collect_read_names(node.value, names)

        elif isinstance(node, MLILIf):
            self._collect_read_names(node.condition, names)

        elif isinstance(node, MLILRet):
            if node.value is not None:
                self._collect_read_names(node.value, names)

    def _count_reads(self, node: MediumLevelILInstruction, var_name: str) -> int:
        '''How often an instruction reads a variable'''
        if isinstance(node, MLILVar):
            return 1 if node.var.name == var_name else 0

        if isinstance(node, MLILBinaryOp):
            return self._count_reads(node.lhs, var_name) + self._count_reads(node.rhs, var_name)

        if isinstance(node, MLILUnaryOp):
            return self._count_reads(node.operand, var_name)

        if isinstance(node, MediumLevelILCall):
            return sum(self._count_reads(arg, var_name) for arg in node.args)

        if isinstance(node, MLILSetVar):
            return self._count_reads(node.value, var_name)

        if isinstance(node, (MLILStoreReg, MLILStoreGlobal)):
            return self._count_reads(node.value, var_name)

        if isinstance(node, MLILStoreDeref):
            return self._count_reads(node.dest, var_name) + self._count_reads(node.value, var_name)

        if isinstance(node, MLILIf):
            return self._count_reads(node.condition, var_name)

        if isinstance(node, MLILRet):
            return self._count_reads(node.value, var_name) if node.value is not None else 0

        return 0

    def _contains_impure_read(self, node: MediumLevelILInstruction) -> bool:
        '''Whether node reads through a pointer, or reads REG[]/GLOBAL[], anywhere in its tree.

        Both are impure the same way: not SSA-tracked variables, and a call is conservatively
        assumed able to write either (see e.g. pass_reg_global_propagation.py's MLILCall
        handling, which drops every cached REG/GLOBAL value on a call).
        '''
        if isinstance(node, (MLILDeref, MLILLoadReg, MLILLoadGlobal)):
            return True

        if isinstance(node, MLILBinaryOp):
            return self._contains_impure_read(node.lhs) or self._contains_impure_read(node.rhs)

        if isinstance(node, MLILUnaryOp):
            return self._contains_impure_read(node.operand)

        if isinstance(node, MediumLevelILCall):
            return any(self._contains_impure_read(arg) for arg in node.args)

        return False

    def _read_unsafe_to_fold(self, node: MediumLevelILInstruction, var_name: str, gated: bool = False) -> bool:
        '''Whether replacing var_name's read inside node with its call changes what the call does.

        Folding moves the call to the read's position, and that position differs from the
        statement's when:
        - an impure read (pointer dereference or REG[]/GLOBAL[] load) sits earlier in node's
          evaluation order (e.g. MLILStoreDeref evaluates dest before value) - the call would now
          run after it instead of before, so the read could miss what the call changes
        - it is under the rhs of MLILLogicalAnd/Or (gated) - the VM evaluates both operands, but
          HLIL's && / || short-circuit, so the call would only run sometimes
        - it is under MLILAddressOf - &var names the variable's storage, which a call has not got
        '''
        if isinstance(node, MLILVar):
            return gated and node.var.name == var_name

        if isinstance(node, MLILAddressOf):
            return self._count_reads(node.operand, var_name) > 0

        if isinstance(node, MLILBinaryOp):
            if self._count_reads(node.rhs, var_name) > 0 and self._contains_impure_read(node.lhs):
                return True

            rhs_gated = gated or isinstance(node, (MLILLogicalAnd, MLILLogicalOr))
            return (self._read_unsafe_to_fold(node.lhs, var_name, gated) or
                    self._read_unsafe_to_fold(node.rhs, var_name, rhs_gated))

        if isinstance(node, MLILUnaryOp):
            return self._read_unsafe_to_fold(node.operand, var_name, gated)

        if isinstance(node, MediumLevelILCall):
            seen_impure = False
            for arg in node.args:
                if seen_impure and self._count_reads(arg, var_name) > 0:
                    return True

                if self._read_unsafe_to_fold(arg, var_name, gated):
                    return True

                seen_impure = seen_impure or self._contains_impure_read(arg)

            return False

        if isinstance(node, MLILSetVar):
            return self._read_unsafe_to_fold(node.value, var_name)

        if isinstance(node, (MLILStoreReg, MLILStoreGlobal)):
            return self._read_unsafe_to_fold(node.value, var_name)

        if isinstance(node, MLILStoreDeref):
            if self._count_reads(node.value, var_name) > 0 and self._contains_impure_read(node.dest):
                return True

            return (self._read_unsafe_to_fold(node.dest, var_name) or
                    self._read_unsafe_to_fold(node.value, var_name))

        if isinstance(node, MLILIf):
            return self._read_unsafe_to_fold(node.condition, var_name)

        if isinstance(node, MLILRet):
            return self._read_unsafe_to_fold(node.value, var_name) if node.value is not None else False

        return False


# ============================================================================
# MLIL to HLIL Converter
# ============================================================================

@dataclass
class LoopStackEntry:
    '''Active loop context for break/continue generation'''
    header: int
    exit: Optional[int]
    label: Optional[str] = None


@dataclass
class FollowOn:
    '''Block to carry on at after an if or a loop, in the same target block and stop point'''
    block_idx: int
    jump_source: Optional[MediumLevelILInstruction] = None
    force_plain: bool = False


class MLILToHLILConverter:

    def __init__(self, mlil_func: MediumLevelILFunction):
        self.mlil_func = mlil_func
        self.hlil_func = HighLevelILFunction(mlil_func.name, mlil_func.start_addr, is_common_func=mlil_func.is_common_func)

        self.block_successors: Dict[int, List[int]] = {}
        self.visited_blocks: Set[int] = set()
        self.globally_processed: Set[int] = set()

        # Blocks currently being re-emitted, and the remaining re-emission allowance
        self.cloning_blocks: Set[int] = set()
        self.clone_budget = CLONE_STATEMENT_BUDGET

        # Merge points an enclosing if will emit after itself, innermost last
        self.pending_merges: List[int] = []

        # Loop detection
        self.loop_headers: Set[int] = set()  # Blocks that are loop headers

        # Active loops, innermost last (for break/continue generation)
        self.loop_stack: List[LoopStackEntry] = []

        # Structural analyzer for accurate merge point detection
        self.structural_analyzer: Optional[StructuralAnalyzer] = None

        # Call results that become part of the instruction reading them
        self.folder = CallResultFolder(mlil_func, self.block_successors)

        # Converted call expressions, keyed by call position
        self.expr_cache: Dict[Tuple[int, int], HLILExpression] = {}

        # Current context
        self.current_block_idx: int = 0
        self.current_instr_idx: int = 0

    def convert(self) -> HighLevelILFunction:
        # Phase 1: Build CFG and detect loops
        self._build_cfg()
        self._detect_loops()

        # Phase 2: Decide which call results fold into their reader
        self.folder.analyze()

        # Phase 3: Convert parameters
        self._convert_parameters()

        # Phase 4: Reconstruct control flow
        if self.mlil_func.basic_blocks:
            self._reconstruct_control_flow(0, self.hlil_func.body)

        # Phase 5: Declare the variables the body actually uses
        self._declare_used_variables()

        return self.hlil_func

    def _convert_parameters(self):
        '''Build the HLIL parameter list from the MLIL one'''
        for i, mlil_var in enumerate(self.mlil_func.parameters):
            if mlil_var is None:
                continue

            type_hint = self._get_type_hint(mlil_var.name)

            # Get default value from source_params
            default_value = None
            if i < len(self.mlil_func.source_params):
                default_value = self.mlil_func.source_params[i].default_value

            hlil_var = HLILVariable(mlil_var.name, type_hint=type_hint,
                                    default_value=default_value, kind=VariableKind.PARAM)
            self.hlil_func.parameters.append(hlil_var)

    def _declare_used_variables(self):
        '''Declare every local the emitted body mentions, in first-use order'''
        param_names = {param.name for param in self.hlil_func.parameters}
        declared: Set[str] = set()

        for name in self._collect_used_var_names(self.hlil_func.body):
            if name is None or name in param_names or name in declared:
                continue

            declared.add(name)
            self.hlil_func.variables.append(HLILVariable(name, type_hint = self._get_type_hint(name)))

    @classmethod
    def _collect_used_var_names(cls, node) -> List[str]:
        '''Local variable names appearing in an HLIL subtree, in source order - an assignment
        target included'''
        return [n.var.name for n in iter_tree(node) if isinstance(n, HLILVar) and n.var.kind == VariableKind.LOCAL]

    def _get_type_hint(self, var_name: str) -> Optional[HLILTypeKind]:
        mlil_type = self.mlil_func.var_types.get(var_name)
        if mlil_type is None:
            return None
        hlil_type = _mlil_type_to_hlil(mlil_type)
        if hlil_type == HLILTypeKind.UNKNOWN:
            return None
        return hlil_type

    def _build_cfg(self):
        num_blocks = len(self.mlil_func.basic_blocks)

        for i, block in enumerate(self.mlil_func.basic_blocks):
            successors = []
            if block.instructions:
                last_instr = block.instructions[-1]
                if isinstance(last_instr, MLILIf):
                    if last_instr.true_target is not None:
                        successors.append(last_instr.true_target.index)

                    if last_instr.false_target is not None:
                        successors.append(last_instr.false_target.index)

                elif isinstance(last_instr, MLILGoto):
                    if last_instr.target is not None:
                        successors.append(last_instr.target.index)

                elif not isinstance(last_instr, MLILRet):
                    if i + 1 < num_blocks:
                        successors.append(i + 1)

            self.block_successors[i] = successors

        # Initialize structural analyzer with the built CFG
        if num_blocks > 0:
            self.structural_analyzer = StructuralAnalyzer(num_blocks, self.block_successors)

    def _detect_loops(self):
        '''Record the loop headers the structural analyzer found'''
        if not self.mlil_func.basic_blocks or self.structural_analyzer is None:
            return

        self.loop_headers.update(self.structural_analyzer.loops)

    def _find_merge_block(self, cond_block_idx: int, true_target_idx: int, false_target_idx: int) -> Optional[int]:
        '''Find merge point for if-else using structural analyzer.'''
        if true_target_idx == false_target_idx:
            return true_target_idx

        if self.structural_analyzer is not None:
            return self.structural_analyzer.find_merge_point(
                cond_block_idx, true_target_idx, false_target_idx
            )

        return None

    def _is_passthrough_block(self, block_idx: int) -> bool:
        if block_idx >= len(self.mlil_func.basic_blocks):
            return False
        block = self.mlil_func.basic_blocks[block_idx]
        if not block.instructions:
            return False
        return (
            all(is_nop_instr(instr) for instr in block.instructions[:-1]) and
            isinstance(block.instructions[-1], MLILGoto)
        )

    def _skip_passthrough_blocks(self, block_idx: int, stop_at: Optional[int] = None) -> int:
        '''Follow a chain of blocks that only jump onward, to the first real block'''
        seen: Set[int] = set()

        while (self._is_passthrough_block(block_idx) and
               block_idx not in seen and
               block_idx != stop_at):
            seen.add(block_idx)
            last_instr = self.mlil_func.basic_blocks[block_idx].instructions[-1]

            if not isinstance(last_instr, MLILGoto) or last_instr.target is None:
                break

            block_idx = last_instr.target.index

        return block_idx

    def _block_ends_with_return(self, block_idx: int) -> bool:
        if block_idx >= len(self.mlil_func.basic_blocks):
            return False
        instructions = self.mlil_func.basic_blocks[block_idx].instructions
        return bool(instructions) and isinstance(instructions[-1], MLILRet)

    def _find_loop_break_target(self, loop_info) -> Optional[int]:
        '''Break target for a while(1) loop: its single non-returning exit.

        Exits that return are emitted inline as return statements and need no break.
        With several non-returning exits there is no single place to continue, so the
        loop keeps no break target.
        '''
        candidates: List[int] = []

        for exit_idx in loop_info.exits:
            effective_idx = self._skip_passthrough_blocks(exit_idx)

            # A passthrough chain can lead back into the loop
            if effective_idx in loop_info.body:
                continue

            if self._block_ends_with_return(effective_idx):
                continue

            if effective_idx not in candidates:
                candidates.append(effective_idx)

        if len(candidates) == 1:
            return candidates[0]

        return None

    def _process_loop(self, header_idx: int, target_block: HLILBlock,
                      stop_at: Optional[int]) -> Optional[FollowOn]:
        '''Process a loop starting at header_idx'''
        mlil_block = self.mlil_func.basic_blocks[header_idx]
        header_label = mlil_block.label

        loop_info = self.structural_analyzer.get_loop_info(header_idx) if self.structural_analyzer else None

        if loop_info is None:
            print(f'[loop] no LoopInfo for header {header_label} in {self.mlil_func.name}', file = sys.stderr)
            return FollowOn(header_idx, force_plain = True)

        last_instr = mlil_block.instructions[-1] if mlil_block.instructions else None

        loop_body_start = None
        exit_block_idx = None
        condition = None
        header_if_into_body = False

        # Header instructions run on every iteration, so they belong in the loop body.
        # When there are any, the condition has to move into the body as well.
        has_real_header_instr = any(not is_nop_instr(instr) for instr in mlil_block.instructions[:-1])

        if isinstance(last_instr, MLILIf):
            true_target = last_instr.true_target.index if last_instr.true_target else None
            false_target = last_instr.false_target.index if last_instr.false_target else None
            true_in_body = true_target in loop_info.body
            false_in_body = false_target in loop_info.body

            if true_in_body != false_in_body and has_real_header_instr:
                # while (1) { header; if (!cond) break; body }
                exit_block_idx = false_target if true_in_body else true_target
                condition = HLILConst(1)
                header_if_into_body = True

            elif true_in_body and not false_in_body:
                loop_body_start = true_target
                exit_block_idx = false_target
                condition = self._convert_expr(last_instr.condition)

            elif false_in_body and not true_in_body:
                loop_body_start = false_target
                exit_block_idx = true_target
                condition = negate_condition(self._convert_expr(last_instr.condition))

            elif true_in_body and false_in_body:
                # Loop condition is not at the header: while(1) with the if inside the body
                condition = HLILConst(1)
                header_if_into_body = True

            else:
                print(f'[loop] cannot decide loop body at header {header_label} in {self.mlil_func.name} (treated as non-loop)', file = sys.stderr)
                return FollowOn(header_idx, force_plain = True)

        elif isinstance(last_instr, MLILGoto) and last_instr.target is not None and last_instr.target.index in loop_info.body:
            loop_body_start = last_instr.target.index
            condition = HLILConst(1)
            exit_block_idx = self._find_loop_break_target(loop_info)

        else:
            print(f'[loop] cannot decide loop body at header {header_label} in {self.mlil_func.name} (treated as non-loop)', file = sys.stderr)
            return FollowOn(header_idx, force_plain = True)

        self.visited_blocks.add(header_idx)
        self.globally_processed.add(header_idx)

        stack_entry = LoopStackEntry(header = header_idx, exit = exit_block_idx)
        self.loop_stack.append(stack_entry)

        loop_body = HLILBlock()

        # Header instructions execute on every iteration, so they open the loop body
        self.current_block_idx = header_idx

        for instr_idx, instr in enumerate(mlil_block.instructions[:-1]):
            self.current_instr_idx = instr_idx

            stmts = self._convert_instruction(instr, header_idx, instr_idx)
            for stmt in stmts:
                loop_body.add_statement(stmt)

        self.current_instr_idx = len(mlil_block.instructions) - 1

        if header_if_into_body:
            follow_on = self._process_if_statement(last_instr, header_idx, loop_body, stop_at = header_idx)

            if follow_on is not None:
                self._reconstruct_control_flow(follow_on.block_idx, loop_body, stop_at = header_idx,
                                               jump_source = follow_on.jump_source)

        elif loop_body_start is not None:
            self._reconstruct_control_flow(loop_body_start, loop_body, stop_at = header_idx, jump_source = last_instr)

        # Drop the redundant trailing continue of this loop's own body
        if loop_body.statements:
            tail = loop_body.statements[-1]

            if isinstance(tail, HLILContinue) and tail.label is None:
                loop_body.statements.pop()

        self.loop_stack.pop()

        while_stmt = HLILWhile(condition, loop_body, label = stack_entry.label)
        target_block.add_statement(while_stmt)

        # The caller carries on after the loop (outside the popped loop context)
        if exit_block_idx is not None:
            self.visited_blocks.discard(exit_block_idx)
            return FollowOn(exit_block_idx, jump_source = last_instr)

        return None

    def _process_if_statement(self, if_instr: MLILIf, block_idx: int,
                               target_block: HLILBlock, stop_at: Optional[int]) -> Optional[FollowOn]:
        '''Process an if statement, detecting and handling else-if chains'''
        condition = self._convert_expr(if_instr.condition)
        true_target_idx = if_instr.true_target.index if if_instr.true_target else None
        false_target_idx = if_instr.false_target.index if if_instr.false_target else None

        # Handle degenerate case: if (C) goto A else A
        # Both branches go to same block. Condition C may have side effects,
        # so we generate: if (C || true) { A } to preserve C's evaluation
        if true_target_idx == false_target_idx and true_target_idx is not None:
            always_true = HLILBinaryOp(BinaryOp.OR, condition, HLILConst(1))
            body = HLILBlock()
            self._reconstruct_control_flow(true_target_idx, body, stop_at = stop_at, jump_source = if_instr)
            if_stmt = HLILIf(always_true, body, None)
            target_block.add_statement(HLILComment(f'if (C || true) {{ A }}'))
            target_block.add_statement(if_stmt)
            return None

        # Several tests funnelling into one body are one condition, not nested ifs
        collapsed = self._collapse_funnel_chain(if_instr, true_target_idx, false_target_idx)

        if collapsed is not None:
            condition, true_target_idx, false_target_idx = collapsed

        # Find merge block for the entire if/else-if chain
        merge_block_idx = None
        if true_target_idx is not None and false_target_idx is not None:
            merge_block_idx = self._find_merge_block(block_idx, true_target_idx, false_target_idx)

        branch_stop = merge_block_idx if merge_block_idx is not None else stop_at
        saved_visited = self.visited_blocks.copy()

        # Check if one branch is empty (goes directly to merge)
        true_is_empty = merge_block_idx == true_target_idx
        false_is_empty = merge_block_idx == false_target_idx

        # Track if we detected an else-if pattern (skip early return handling for these)
        is_else_if_pattern = False

        # Check if else-if chain is through true_target (inverted condition pattern)
        # e.g., switch-case: if (!match) goto next_check else case_body
        # Use structural analysis to detect: true_target has 2 successors (condition block)
        # Don't invert if true_target is already the merge (empty true branch)
        if (self.structural_analyzer is not None and
            true_target_idx is not None and false_target_idx is not None and
            not true_is_empty and
            self.structural_analyzer.should_invert_condition(true_target_idx, false_target_idx)):
            # Swap branches and negate condition
            condition = negate_condition(condition)
            old_true_target = true_target_idx  # Save for checking merge block conflict
            true_target_idx, false_target_idx = false_target_idx, true_target_idx
            true_is_empty, false_is_empty = false_is_empty, False  # else-if block is never empty
            is_else_if_pattern = True
            # Merge block conflict: if merge_block equals the old true_target (now false),
            # processing false branch would stop immediately. Use outer stop_at instead.
            if merge_block_idx == old_true_target:
                branch_stop = stop_at

        # A branch reaching this merge falls through to it once the if ends, so
        # meeting it again is not a lost path and must not be re-emitted.
        if branch_stop is not None:
            self.pending_merges.append(branch_stop)

        # Process each branch (skip if empty - it's just the merge point); an else-if
        # chain is just an if inside the false branch
        # MLIL: if (C) goto true_target else false_target
        # C true -> true_target, C false -> false_target
        true_block = HLILBlock()
        if true_target_idx is not None and not true_is_empty:
            true_block = self._emit_branch(true_target_idx, saved_visited, stop_at, merge_block_idx, branch_stop, if_instr)

        # Taken from visited_blocks, not rebuilt from saved_visited: a branch can remove
        # blocks as well as add them
        all_visited = self.visited_blocks.copy()

        false_block = HLILBlock()
        if false_target_idx is not None and not false_is_empty:
            false_block = self._emit_branch(false_target_idx, saved_visited, stop_at, merge_block_idx, branch_stop, if_instr)
            all_visited |= self.visited_blocks

        if branch_stop is not None:
            self.pending_merges.pop()

        self.visited_blocks = all_visited
        if stop_at is not None:
            self.visited_blocks.discard(stop_at)

        # Check if branches end with return (skip for else-if patterns)
        true_ends_with_return = (not is_else_if_pattern and true_block.statements and
            isinstance(true_block.statements[-1], HLILReturn))
        false_ends_with_return = (not is_else_if_pattern and false_block.statements and
            isinstance(false_block.statements[-1], HLILReturn))

        # MLIL: if (C) goto true_target else false_target
        # HLIL: if (C) { true_block } else { false_block }

        # Early return patterns (skip for else-if chains to preserve structure)
        if true_ends_with_return and false_ends_with_return:
            if len(true_block.statements) <= len(false_block.statements):
                if_stmt = HLILIf(condition, true_block, None)
                target_block.add_statement(if_stmt)
                for stmt in false_block.statements:
                    target_block.add_statement(stmt)

            else:
                if_stmt = HLILIf(negate_condition(condition), false_block, None)
                target_block.add_statement(if_stmt)
                for stmt in true_block.statements:
                    target_block.add_statement(stmt)

        elif true_ends_with_return:
            if_stmt = HLILIf(condition, true_block, None)
            target_block.add_statement(if_stmt)
            for stmt in false_block.statements:
                target_block.add_statement(stmt)

        elif false_ends_with_return:
            if_stmt = HLILIf(negate_condition(condition), false_block, None)
            target_block.add_statement(if_stmt)
            for stmt in true_block.statements:
                target_block.add_statement(stmt)

        else:
            # MLIL: if (C) goto true_target else false_target
            # HLIL: if (C) { true_block } else { false_block }
            # Handle empty branches: negate condition if true branch is empty
            if not true_block.statements and false_block.statements:
                # true branch is empty, negate and use false as body
                if_stmt = HLILIf(negate_condition(condition), false_block, None)

            elif true_block.statements and not false_block.statements:
                # false branch is empty, use true as body
                if_stmt = HLILIf(condition, true_block, None)

            else:
                if_stmt = HLILIf(condition, true_block, false_block if false_block.statements else None)

            target_block.add_statement(if_stmt)

        # The caller carries on at the merge block
        if merge_block_idx is not None and merge_block_idx != stop_at:
            self.visited_blocks.discard(merge_block_idx)
            return FollowOn(merge_block_idx, jump_source = if_instr)

        return None

    def _emit_branch(self, target_idx: int, saved_visited: Set[int], stop_at: Optional[int],
                     merge_block_idx: Optional[int], branch_stop: Optional[int], if_instr: MLILIf) -> HLILBlock:
        '''Build one branch of an if, starting from the blocks visited before the if'''
        block = HLILBlock()
        self.visited_blocks = saved_visited.copy()

        # The outer stop point is off limits, unless it is the merge or this branch's own start
        if stop_at is not None and stop_at != merge_block_idx and stop_at != target_idx:
            self.visited_blocks.add(stop_at)

        self._reconstruct_control_flow(target_idx, block, stop_at = branch_stop, jump_source = if_instr)
        return block

    def _bare_test_block(self, block_idx: int) -> Optional[Tuple[MLILIf, int, int]]:
        '''The test and its targets, if block_idx holds nothing but a 2-way test.

        Bare means it holds only the test and is entered only from the previous
        link, so folding it into a condition loses no other work and steals it
        from no other path.
        '''
        if block_idx is None or block_idx >= len(self.mlil_func.basic_blocks):
            return None

        if block_idx in self.loop_headers:
            return None

        block = self.mlil_func.basic_blocks[block_idx]

        if len(block.instructions) != 1 or len(block.incoming_edges) != 1:
            return None

        instr = block.instructions[0]

        if not isinstance(instr, MLILIf) or instr.true_target is None or instr.false_target is None:
            return None

        return instr, instr.true_target.index, instr.false_target.index

    def _collapse_funnel_chain(self, if_instr: MLILIf, true_idx: Optional[int],
                               false_idx: Optional[int]):
        '''Merge consecutive tests that all branch to one block into one || condition.

        Tests sharing a body are a switch case carrying several labels. Left as
        nested ifs the body has to be repeated once per test, so folding them here
        keeps it emitted once. Returns (condition, shared_target, else_target).
        '''
        if true_idx is None or false_idx is None:
            return None

        for shared, following in ((true_idx, false_idx), (false_idx, true_idx)):
            link = self._bare_test_block(following)

            if link is None or shared not in (link[1], link[2]):
                continue

            first = self._convert_expr(if_instr.condition)
            conditions = [negate_condition(first) if shared == false_idx else first]
            current = following

            while True:
                link = self._bare_test_block(current)

                if link is None:
                    break

                instr, link_true, link_false = link

                if shared not in (link_true, link_false):
                    break

                # Convert in the test's own context: a folded call result is looked
                # up by reader position, and a miss would drop the call entirely
                saved_block, saved_instr = self.current_block_idx, self.current_instr_idx
                self.current_block_idx, self.current_instr_idx = current, 0

                try:
                    cond = self._convert_expr(instr.condition)

                finally:
                    self.current_block_idx, self.current_instr_idx = saved_block, saved_instr

                conditions.append(negate_condition(cond) if shared == link_false else cond)
                current = link_false if shared == link_true else link_true

            if len(conditions) < 2 or current == shared:
                continue

            combined = conditions[0]
            for cond in conditions[1:]:
                combined = HLILBinaryOp(BinaryOp.OR, combined, cond)

            return combined, shared, current

        return None

    def _warn_dropped_path(self, block_idx: int, reason: str):
        block_label = self.mlil_func.basic_blocks[block_idx].label
        print(f'[hlil] dropped path to {block_label} in {self.mlil_func.name} ({reason})',
              file = sys.stderr)

    def _clone_region_blocks(self, block_idx: int, stop_at: Optional[int]) -> Optional[Set[int]]:
        '''Blocks reachable from block_idx up to stop_at, or None if unsafe to repeat.

        A loop we are currently inside is refused: re-entering its header would
        rebuild that loop underneath itself. A self-contained loop further down
        is fine - it gets rebuilt whole.
        '''
        active_headers = {entry.header for entry in self.loop_stack}
        region: Set[int] = set()
        queue = deque([block_idx])

        while queue:
            current = queue.popleft()

            if current in region or current == stop_at:
                continue

            if current >= len(self.mlil_func.basic_blocks):
                continue

            if current in active_headers:
                return None

            region.add(current)

            if len(region) > CLONE_MAX_REGION_BLOCKS:
                return None

            queue.extend(self.block_successors.get(current, []))

        return region or None

    def _clone_processed_region(self, block_idx: int, target_block: HLILBlock,
                                stop_at: Optional[int],
                                jump_source: Optional[MediumLevelILInstruction]) -> bool:
        '''Re-emit a region already emitted on another path.

        Rebuilds it rather than deep-copying so nested structuring, merge detection
        and break/continue all resolve against this path's context.
        '''
        if block_idx in self.cloning_blocks:
            self._warn_dropped_path(block_idx, 'already being re-emitted')
            return False

        region = self._clone_region_blocks(block_idx, stop_at)

        if region is None:
            self._warn_dropped_path(block_idx, 'region not repeatable')
            return False

        scratch = HLILBlock()
        saved_visited = self.visited_blocks.copy()
        saved_processed = self.globally_processed.copy()

        self.visited_blocks -= region
        self.globally_processed -= region
        self.cloning_blocks.add(block_idx)

        try:
            self._reconstruct_control_flow(block_idx, scratch, stop_at = stop_at,
                                           jump_source = jump_source)

        finally:
            self.cloning_blocks.discard(block_idx)
            self.visited_blocks = saved_visited
            self.globally_processed |= saved_processed

        if len(scratch.statements) > self.clone_budget:
            self._warn_dropped_path(block_idx, f'{len(scratch.statements)} statements over budget')
            return False

        self.clone_budget -= len(scratch.statements)

        for stmt in scratch.statements:
            target_block.add_statement(stmt)

        return True

    def _reconstruct_control_flow(self, block_idx: int, target_block: HLILBlock,
                                   stop_at: Optional[int] = None,
                                   jump_source: Optional[MediumLevelILInstruction] = None,
                                   force_plain: bool = False) -> None:
        '''Reconstruct structured statements starting at block_idx.

        Sequential block chains, including the code after an if or a loop
        (FollowOn), are followed iteratively, so recursion depth grows with
        control structure nesting, not with function length.
        force_plain skips the loop-header dispatch for the first block only
        (used by _process_loop fallbacks to avoid bouncing back).
        '''
        while True:
            block_idx = self._skip_passthrough_blocks(block_idx, stop_at)

            if block_idx >= len(self.mlil_func.basic_blocks):
                return None

            # Jump to an active loop's exit becomes break, to its header becomes continue
            for depth, entry in enumerate(reversed(self.loop_stack)):
                if entry.exit == block_idx or entry.header == block_idx:
                    if depth > 0 and entry.label is None:
                        entry.label = f'loop_{entry.header}'

                    label = entry.label if depth > 0 else None

                    if entry.exit == block_idx:
                        stmt = HLILBreak(label = label)

                    else:
                        stmt = HLILContinue(label = label)

                    if jump_source is not None:
                        self._set_hlil_source_info(stmt, jump_source)

                    else:
                        first_instrs = self.mlil_func.basic_blocks[block_idx].instructions
                        stmt.address = first_instrs[0].address if first_instrs else 0

                    target_block.add_statement(stmt)
                    return None

            # Already emitted somewhere else in the function
            if block_idx in self.visited_blocks or block_idx in self.globally_processed:
                if block_idx in self.loop_headers and block_idx in self.globally_processed:
                    block_label = self.mlil_func.basic_blocks[block_idx].label
                    print(f'[loop] jump into inactive loop header {block_label} in {self.mlil_func.name} (possible lost path)', file = sys.stderr)
                    return None

                # An enclosing if emits its merge point after itself, so control
                # reaches it by falling out of this branch - nothing is lost.
                if block_idx in self.pending_merges:
                    return None

                # Still reachable from here too - several conditions funnelling into one
                # shared body. HLIL has no goto, so repeating it is the only faithful
                # representation; refusing warns rather than dropping the path silently.
                self._clone_processed_region(block_idx, target_block, stop_at, jump_source)
                return None

            if stop_at is not None and block_idx == stop_at:
                # Reached the merge point - stop here, don't process this block
                # The merge block will be processed after the if-else by the outer scope
                self.visited_blocks.add(block_idx)
                return None

            # Check if this is a loop header
            if not force_plain and block_idx in self.loop_headers:
                follow_on = self._process_loop(block_idx, target_block, stop_at)
                if follow_on is None:
                    return None

                block_idx, jump_source, force_plain = follow_on.block_idx, follow_on.jump_source, follow_on.force_plain
                continue

            force_plain = False
            self.visited_blocks.add(block_idx)
            self.globally_processed.add(block_idx)

            self.current_block_idx = block_idx
            mlil_block = self.mlil_func.basic_blocks[block_idx]

            for instr_idx, instr in enumerate(mlil_block.instructions[:-1]):
                self.current_instr_idx = instr_idx
                stmts = self._convert_instruction(instr, block_idx, instr_idx)
                for stmt in stmts:
                    target_block.add_statement(stmt)

            if not mlil_block.instructions:
                return None

            last_instr = mlil_block.instructions[-1]
            last_instr_idx = len(mlil_block.instructions) - 1
            self.current_instr_idx = last_instr_idx

            if isinstance(last_instr, MLILIf):
                follow_on = self._process_if_statement(last_instr, block_idx, target_block, stop_at)
                if follow_on is None:
                    return None

                block_idx, jump_source = follow_on.block_idx, follow_on.jump_source
                continue

            elif isinstance(last_instr, MLILGoto):
                if last_instr.target is None:
                    return None

                block_idx = last_instr.target.index
                jump_source = last_instr
                continue

            elif isinstance(last_instr, MLILRet):
                stmts = self._convert_instruction(last_instr, block_idx, last_instr_idx)
                for stmt in stmts:
                    target_block.add_statement(stmt)
                return None

            else:
                stmts = self._convert_instruction(last_instr, block_idx, last_instr_idx)
                for stmt in stmts:
                    target_block.add_statement(stmt)

                if block_idx + 1 >= len(self.mlil_func.basic_blocks):
                    return None

                jump_source = last_instr
                block_idx = block_idx + 1
                continue

    @classmethod
    def _set_hlil_source_info(cls, hlil_instr: HLILInstruction, mlil_instr: MediumLevelILInstruction) -> None:
        '''Propagate source address info from MLIL to HLIL'''
        hlil_instr.address = mlil_instr.address
        hlil_instr.mlil_index = mlil_instr.inst_index

    def _convert_instruction(self, instr: MediumLevelILInstruction,
                              block_idx: int, instr_idx: int) -> List[HLILStatement]:
        '''Convert instruction, may return multiple statements for temp vars'''
        key = (block_idx, instr_idx)
        result = []

        if isinstance(instr, MLILDebug):
            stmt = HLILComment(f'{instr.debug_type}({instr.value})')
            self._set_hlil_source_info(stmt, instr)
            result.append(stmt)

        elif isinstance(instr, MLILNop):
            pass

        elif isinstance(instr, MLILRet):
            if instr.value:
                stmt = HLILReturn(self._convert_expr(instr.value))

            else:
                stmt = HLILReturn()

            self._set_hlil_source_info(stmt, instr)
            result.append(stmt)

        elif isinstance(instr, MLILSetVar):
            stmt = HLILAssign(
                HLILVar(HLILVariable(instr.var.name, None)),
                self._convert_expr(instr.value)
            )
            self._set_hlil_source_info(stmt, instr)
            result.append(stmt)

        elif isinstance(instr, (MLILStoreReg, MLILStoreGlobal)):
            # Registers and globals outside the variable model are shared state:
            # always emit the literal array write
            kind = VariableKind.REG if isinstance(instr, MLILStoreReg) else VariableKind.GLOBAL
            var = HLILVariable(kind = kind, index = instr.index)
            stmt = HLILAssign(HLILVar(var), self._convert_expr(instr.value))
            self._set_hlil_source_info(stmt, instr)
            result.append(stmt)

        elif isinstance(instr, MLILStoreDeref):
            stmt = HLILAssign(HLILDeref(self._convert_expr(instr.dest)), self._convert_expr(instr.value))
            self._set_hlil_source_info(stmt, instr)
            result.append(stmt)

        elif isinstance(instr, MediumLevelILCall):
            call_expr = self._convert_expr(instr)

            if self.folder.is_folded(block_idx, instr_idx):
                # The instruction reading the result emits this call
                self.expr_cache[key] = call_expr

            elif instr.output is None:
                # Result unused: keep the call for its side effects
                stmt = HLILExprStmt(call_expr)
                self._set_hlil_source_info(stmt, instr)
                result.append(stmt)

            else:
                var = HLILVariable(instr.output.name, None)
                stmt = HLILAssign(HLILVar(var), call_expr)
                self._set_hlil_source_info(stmt, instr)
                result.append(stmt)

        elif isinstance(instr, (MLILIf, MLILGoto)):
            pass

        elif isinstance(instr, MediumLevelILExpr):
            stmt = HLILExprStmt(self._convert_expr(instr))
            self._set_hlil_source_info(stmt, instr)
            result.append(stmt)

        return result

    def _convert_expr(self, expr: MediumLevelILExpr) -> HLILExpression:
        if isinstance(expr, MLILVar):
            # A read of a folded call result becomes the call itself
            call_key = self.folder.folded_call_at(
                self.current_block_idx, self.current_instr_idx, expr.var.name
            )

            if call_key is not None:
                folded = self.expr_cache.get(call_key)
                if folded is not None:
                    return folded

            return HLILVar(HLILVariable(expr.var.name, None))

        elif isinstance(expr, MLILConst):
            return HLILConst(expr.value, expr.is_hex)

        elif isinstance(expr, MLILBinaryOp):
            op = _BINARY_OP_MAP.get(expr.operation)
            if op is None:
                raise ValueError(f'Unknown binary op: {expr.operation}')
            return HLILBinaryOp(op, self._convert_expr(expr.lhs), self._convert_expr(expr.rhs))

        elif isinstance(expr, MLILAddressOf):
            operand = self._convert_expr(expr.operand)
            return HLILAddressOf(operand)

        elif isinstance(expr, MLILDeref):
            operand = self._convert_expr(expr.operand)
            return HLILDeref(operand)

        elif isinstance(expr, MLILUnaryOp):
            if expr.operation in (MediumLevelILOperation.MLIL_LOGICAL_NOT, MediumLevelILOperation.MLIL_TEST_ZERO):
                operand = self._convert_expr(expr.operand)
                return HLILBinaryOp(BinaryOp.EQ, operand, HLILConst(0))
            op = _UNARY_OP_MAP.get(expr.operation)
            if op is None:
                raise ValueError(f'Unknown unary op: {expr.operation}')
            return HLILUnaryOp(op, self._convert_expr(expr.operand))

        elif isinstance(expr, MLILLoadReg):
            # A register outside the variable model holds a value from elsewhere
            var = HLILVariable(kind = VariableKind.REG, index = expr.index)
            return HLILVar(var)

        elif isinstance(expr, MLILLoadGlobal):
            # Globals are shared state: always read the literal array slot
            var = HLILVariable(kind = VariableKind.GLOBAL, index = expr.index)
            return HLILVar(var)

        elif isinstance(expr, MLILCall):
            args = [self._convert_expr(arg) for arg in expr.args]
            return HLILCall(str(expr.target), args)

        elif isinstance(expr, MLILSyscall):
            args = [self._convert_expr(arg) for arg in expr.args]
            return HLILSyscall(expr.subsystem, expr.cmd, args)

        elif isinstance(expr, MLILCallScript):
            args = [self._convert_expr(arg) for arg in expr.args]
            return HLILExternCall(f'{expr.module}:{expr.func}', args)

        else:
            return HLILConst(f'<{type(expr).__name__}>')


def convert_mlil_to_hlil(mlil_func: MediumLevelILFunction) -> HighLevelILFunction:
    converter = MLILToHLILConverter(mlil_func)
    return converter.convert()
