"""Call Result Folding"""

from ir.mlil.mlil import *


class CallResultFolder:
    """Decides which call results can be folded into the instruction that reads them.

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
    """

    def __init__(self, mlil_func: MediumLevelILFunction, block_successors: dict[int, list[int]]):
        self.mlil_func = mlil_func
        self.block_successors = block_successors
        self.predecessors: dict[int, list[int]] = {}

        # Live variable names on exit from each block
        self.live_out: dict[int, set[str]] = {}

        # Call position -> reader position, for calls whose result is folded
        self.folded_call: dict[tuple[int, int], tuple[int, int]] = {}

        # Reader position and variable name -> call position
        self.folded_use: dict[tuple[int, int, str], tuple[int, int]] = {}

    def analyze(self):
        """Find every call result that can be folded into its reader"""
        self._build_predecessors()
        self._compute_liveness()
        self._find_foldable_calls()

    def is_folded(self, block_idx: int, instr_idx: int) -> bool:
        """Check whether this call is emitted as part of its reader instead"""
        return (block_idx, instr_idx) in self.folded_call

    def folded_call_at(self, block_idx: int, instr_idx: int, var_name: str) -> tuple[int, int] | None:
        """Position of the call whose result this variable read stands for"""
        return self.folded_use.get((block_idx, instr_idx, var_name))

    def _build_predecessors(self):
        for block_idx in range(len(self.mlil_func.basic_blocks)):
            self.predecessors[block_idx] = []

        for block_idx, successors in self.block_successors.items():
            for succ in successors:
                self.predecessors[succ].append(block_idx)

    def _compute_liveness(self):
        """Backward dataflow over variable names (non-SSA MLIL)"""
        block_uses: dict[int, set[str]] = {}
        block_defs: dict[int, set[str]] = {}
        block_count = len(self.mlil_func.basic_blocks)

        for block_idx, block in enumerate(self.mlil_func.basic_blocks):
            uses: set[str] = set()
            defs: set[str] = set()

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

        live_in: dict[int, set[str]] = {idx: set() for idx in range(block_count)}

        changed = True
        while changed:
            changed = False

            for block_idx in reversed(range(block_count)):
                new_live_out: set[str] = set()
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
                        var_name: str) -> tuple[int, int] | None:
        """Reader for this call result, seeing through calls that fold away

        A call whose own result is folded into a later reader does not really
        separate this call from that reader - both end up in the same expression.
        Stepping over it turns a run of `reg = f()` statements into one nested
        expression, which is what the bytecode was written as.
        """
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

    def _find_reader(self, block_idx: int, instr_idx: int) -> tuple[int, int] | None:
        """Next real instruction after this call, or None

        Only nops and unconditional jumps may be skipped, and a following block
        must be entered from this call alone. Whether that instruction is the
        reader or merely folds away too is left to `_resolve_reader`.
        """
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
        """Check that nothing reads var_name after the reader before it is rewritten"""
        block = self.mlil_func.basic_blocks[block_idx]

        for idx in range(instr_idx + 1, len(block.instructions)):
            instr = block.instructions[idx]

            if var_name in self._read_names(instr):
                return False

            if self._written_name(instr) == var_name:
                return True

        return var_name not in self.live_out[block_idx]

    def _written_name(self, instr: MediumLevelILInstruction) -> str | None:
        """Variable this instruction assigns, if any"""
        if isinstance(instr, MLILSetVar):
            return instr.var.name

        if isinstance(instr, MediumLevelILCall) and instr.output is not None:
            return instr.output.name

        return None

    def _read_names(self, instr: MediumLevelILInstruction) -> set[str]:
        """Variable names this instruction reads"""
        return set(self._read_order(instr))

    def _read_order(self, instr: MediumLevelILInstruction) -> list[str]:
        """Variable names this instruction reads, in evaluation order

        Folding several calls into one expression makes that expression's
        operand order their execution order, so the two have to agree
        """
        return [node.var.name for node in walk(instr) if isinstance(node, MLILVar)]

    def _count_reads(self, node: MediumLevelILInstruction, var_name: str) -> int:
        """How often an instruction reads a variable"""
        return self._read_order(node).count(var_name)

    def _contains_impure_read(self, node: MediumLevelILInstruction) -> bool:
        """Whether node reads through a pointer, or reads REG[]/GLOBAL[], anywhere in its tree.

        Both are impure the same way: not SSA-tracked variables, and a call is conservatively
        assumed able to write either (see e.g. ir/mlil_ssa/passes/pass_reg_global_propagation.py's MLILCall
        handling, which drops every cached REG/GLOBAL value on a call).
        """
        return any(isinstance(sub, (MLILDeref, MLILLoadReg, MLILLoadGlobal)) for sub in walk(node))

    def _read_unsafe_to_fold(self, node: MediumLevelILInstruction, var_name: str) -> bool:
        """Whether replacing var_name's read inside node with its call changes what the call does.

        Folding moves the call to the read's position, and that position differs from the
        statement's when:
        - an impure read (pointer dereference or REG[]/GLOBAL[] load) sits earlier in node's
          evaluation order (e.g. MLILStoreDeref evaluates dest before value) - the call would now
          run after it instead of before, so the read could miss what the call changes
        - it is under MLILAddressOf - &var names the variable's storage, which a call has not got
        """
        if isinstance(node, MLILAddressOf):
            return self._count_reads(node.operand, var_name) > 0

        # Each operand in evaluation order: unsafe inside it, or reading var_name after an earlier impure operand
        seen_impure = False

        for operand in node.operands():
            if seen_impure and self._count_reads(operand, var_name) > 0:
                return True

            if self._read_unsafe_to_fold(operand, var_name):
                return True

            seen_impure = seen_impure or self._contains_impure_read(operand)

        return False
