#!/usr/bin/env python3
'''Unit tests for dereference opcodes (LOAD_STACK_DEREF/POP_TO_DEREF) - Step 3 of the
LLIL/MLIL hardening plan.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.llil.llil import LowLevelILLoad, LowLevelILStore, LowLevelILFrameLoad, WORD_SIZE
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.mlil.mlil_translator import FalcomLLILToMLILTranslator
from ir.mlil.mlil import (
    MediumLevelILFunction, MLILDeref, MLILStoreDeref, MLILSetVar, MLILVar, MLILVariable,
    MLILConst, MLILCall, MLILStoreReg, MLILLoadReg, MLILRet, MLILAddressOf, MLILIf, MLILGoto,
    MLILAdd, MLILEq,
)
from ir.mlil.mlil_ssa import MLILSetVarSSA, MLILVariableSSA, MLILVarSSA, MLILPhi
from ir.mlil.mlil_passes import SSAConversionPass, SSADeconstructionPass
from ir.mlil.mlil_optimizer import optimize_mlil
from ir.mlil.passes import (
    CopyPropagationPass, ExpressionInliningPass, SSADeadCodeEliminationPass,
    RegGlobalValuePropagationPass,
)
from ir.hlil.hlil import (
    HLILDeref, HLILVar, HLILVariable, HLILConst, HLILAssign, HLILBlock, HLILReturn,
)
from ir.hlil.passes.pass_control_flow_optimization import ControlFlowOptimizationPass
from ir.hlil.passes.pass_copy_propagation import CopyPropagationPass as HLILCopyPropagationPass


FUNC_START = 0x1000


def build_function_with_deref(num_params: int, offset: int, *, deref_write: bool,
                               with_ret: bool = False, name: str = 'deref_test'):
    '''1-param function: load_stack_deref(offset) if not deref_write, else push a marker then
    pop_to_deref(offset). Does not call finalize() unless with_ret - see
    test_llil_frame_store.py for why (MLIL finalize() requires a terminal instruction).'''
    builder = FalcomVMBuilder()
    builder.create_function(name, FUNC_START, num_params = num_params)
    entry = builder.create_basic_block(FUNC_START, name)
    builder.set_current_block(entry)

    if deref_write:
        builder.push_int(99)
        builder.pop_to_deref(offset)

    else:
        builder.load_stack_deref(offset)

    if with_ret:
        builder.ret()

    return builder.function, entry


class TestDerefLift(unittest.TestCase):
    '''LLIL-level shape: a dereference targeting a parameter slot builds a pointer expression
    exactly like load_stack (frame-relative), then wraps it in Load/Store.'''

    def test_load_stack_deref_wraps_frame_load(self):
        # 1 parameter (slot 0). offset=0 at entry (sp=1) -> absolute_pos = 1 + 0 = 1... use
        # -WORD_SIZE so absolute_pos = 1 - 1 = 0, the sole parameter slot.
        _, entry = build_function_with_deref(num_params = 1, offset = -WORD_SIZE, deref_write = False)

        # load_stack_deref pushes via stack_push(LowLevelILLoad(...)), i.e. a StackStore whose
        # value is the Load, followed by the push's own (visible) SpAdd.
        store_inst = entry.instructions[-2]
        self.assertIsInstance(store_inst.value, LowLevelILLoad)
        self.assertIsInstance(store_inst.value.src, LowLevelILFrameLoad)
        self.assertEqual(store_inst.value.src.offset, 0)

    def test_pop_to_deref_wraps_frame_load_as_store_target(self):
        # 1 parameter (slot 0). pop_to_deref(-WORD_SIZE) -> slot_index 0, the parameter.
        _, entry = build_function_with_deref(num_params = 1, offset = -WORD_SIZE, deref_write = True)

        inst = entry.instructions[-1]
        self.assertIsInstance(inst, LowLevelILStore)
        self.assertIsInstance(inst.dest, LowLevelILFrameLoad)
        self.assertEqual(inst.dest.offset, 0)

    def test_load_stack_deref_at_non_parameter_slot_raises(self):
        # 1 parameter (slot 0). offset=0 -> absolute_pos = 1, not a parameter slot.
        with self.assertRaises(NotImplementedError):
            build_function_with_deref(num_params = 1, offset = 0, deref_write = False)

    def test_pop_to_deref_at_non_parameter_slot_raises(self):
        # 1 parameter (slot 0). offset=0 after the push -> slot_index 1, not a parameter slot.
        with self.assertRaises(NotImplementedError):
            build_function_with_deref(num_params = 1, offset = 0, deref_write = True)


class TestDerefMLILTranslation(unittest.TestCase):
    '''LLIL Load/Store translate to MLILDeref/MLILStoreDeref, not plain variable access.'''

    def test_store_translates_to_store_deref(self):
        llil_func, _ = build_function_with_deref(num_params = 1, offset = -WORD_SIZE,
                                                   deref_write = True, with_ret = True)

        mlil_func = FalcomLLILToMLILTranslator().translate(llil_func)
        inst = mlil_func.basic_blocks[0].instructions[-2]  # last is the translated ret

        self.assertIsInstance(inst, MLILStoreDeref)
        self.assertEqual(inst.dest.var.name, 'arg1')

    def test_load_translates_to_deref(self):
        llil_func, _ = build_function_with_deref(num_params = 1, offset = -WORD_SIZE,
                                                   deref_write = False, with_ret = True)

        mlil_func = FalcomLLILToMLILTranslator().translate(llil_func)
        # load_stack_deref's StackStore -> MLIL SetVar(local, MLILDeref(arg1))
        set_var_inst = mlil_func.basic_blocks[0].instructions[-2]  # last is the translated ret

        self.assertIsInstance(set_var_inst, MLILSetVar)
        self.assertIsInstance(set_var_inst.value, MLILDeref)
        self.assertEqual(set_var_inst.value.operand.var.name, 'arg1')


class TestDerefStoreSurvivesDCE(unittest.TestCase):
    '''A store through a pointer is an observable side effect - DCE must not remove the
    definition feeding it, even though nothing else reads that variable (this was the
    actual bug this step fixed: SSAConstructor never versioned StoreDeref's operands, so
    downstream passes could not see the use at all).'''

    def test_definition_feeding_a_store_deref_is_kept(self):
        func = MediumLevelILFunction('dce_test')
        block = func.create_block(start = FUNC_START)
        ptr_param = func.get_or_create_parameter(1, 'arg1')
        temp = MLILVariable('var_s1')

        block.add_instruction(MLILSetVar(temp, MLILCall('side_effect', [], temp)))
        block.add_instruction(MLILStoreDeref(MLILVar(ptr_param), MLILVar(temp)))

        SSAConversionPass().run(func)
        SSADeadCodeEliminationPass().run(func)
        SSADeconstructionPass().run(func)

        kinds = [type(inst).__name__ for inst in block.instructions]
        self.assertIn('MLILStoreDeref', kinds)

        # The value stored through the pointer must still be defined somewhere before the
        # store, not a bare reference to a variable nobody assigns (the exact bug shape).
        store_inst = next(inst for inst in block.instructions if isinstance(inst, MLILStoreDeref))
        stored_name = store_inst.value.var.name
        earlier = block.instructions[:block.instructions.index(store_inst)]
        self.assertTrue(any(
            isinstance(inst, MLILSetVar) and inst.var.name == stored_name
            for inst in earlier
        ))


class TestDerefLoadNotInlinedAcrossCall(unittest.TestCase):
    '''A load through a pointer is impure (aliasing means it cannot be assumed unchanged) -
    the expression inliner must not move it past an intervening call.'''

    def test_deref_read_stays_put_across_a_call(self):
        func = MediumLevelILFunction('inline_test')
        block = func.create_block(start = FUNC_START)
        ptr_param = func.get_or_create_parameter(1, 'arg1')
        temp = MLILVariable('var_s1')
        result = MLILVariable('reg0')

        block.add_instruction(MLILSetVar(temp, MLILDeref(MLILVar(ptr_param))))
        block.add_instruction(MLILSetVar(result, MLILCall('unrelated_call', [], result)))
        block.add_instruction(MLILSetVar(MLILVariable('var_s2'), MLILVar(temp)))

        SSAConversionPass().run(func)
        CopyPropagationPass().run(func)
        ExpressionInliningPass().run(func)
        SSADeconstructionPass().run(func)

        # The deref read must still happen as its own statement before the call - it must
        # not have been inlined into the later var_s2 assignment, which would move the read
        # to after unrelated_call() executes.
        deref_index = next(i for i, inst in enumerate(block.instructions)
                            if isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILDeref))
        call_index = next(i for i, inst in enumerate(block.instructions)
                           if isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILCall))
        self.assertLess(deref_index, call_index)


class TestDerefMetadataPreservation(unittest.TestCase):
    '''SSA construction/deconstruction must preserve source tracking on MLILStoreDeref,
    the same guarantee test_mlil_metadata.py already covers for MLILSetVar.'''

    def test_ssa_roundtrip_preserves_store_deref_metadata(self):
        SOURCE_ADDRESS = 0x2000
        SOURCE_INST_INDEX = 7
        SOURCE_LLIL_INDEX = 3

        func = MediumLevelILFunction('metadata_test')
        block = func.create_block(start = FUNC_START)
        ptr_param = func.get_or_create_parameter(1, 'arg1')

        store_inst = MLILStoreDeref(MLILVar(ptr_param), MLILConst(42), address = SOURCE_ADDRESS)
        store_inst.inst_index = SOURCE_INST_INDEX
        store_inst.llil_index = SOURCE_LLIL_INDEX
        block.add_instruction(store_inst)

        SSAConversionPass().run(func)

        ssa_inst = block.instructions[0]
        self.assertIsInstance(ssa_inst, MLILStoreDeref)
        self.assertEqual(ssa_inst.address, SOURCE_ADDRESS)
        self.assertEqual(ssa_inst.inst_index, SOURCE_INST_INDEX)
        self.assertEqual(ssa_inst.llil_index, SOURCE_LLIL_INDEX)
        # The rename walk must have actually versioned the pointer operand, not left it as a
        # bare pre-SSA MLILVar (the exact bug this step fixed)
        self.assertIsInstance(ssa_inst.dest, MLILVarSSA)

        SSADeconstructionPass().run(func)

        restored_inst = block.instructions[0]
        self.assertIsInstance(restored_inst, MLILStoreDeref)
        self.assertEqual(restored_inst.address, SOURCE_ADDRESS)
        self.assertEqual(restored_inst.inst_index, SOURCE_INST_INDEX)
        self.assertEqual(restored_inst.llil_index, SOURCE_LLIL_INDEX)


class TestHLILDerefStoreReadsPointer(unittest.TestCase):
    '''Codex Rule 2 finding: a store through a pointer (*dest = value) reads dest's own value
    too, same as it reads value - ControlFlowOptimizationPass (the one HLIL pass actually wired
    into the live pipeline that inspects assignment reads/kills) must not treat the pointer
    variable as unread just because it only appears on the dest side of a deref-store.'''

    def test_deref_store_dest_counts_as_a_read_of_the_pointer(self):
        ptr = HLILVariable('arg1')
        block = HLILBlock([HLILAssign(HLILDeref(HLILVar(ptr)), HLILConst(1))])

        reads, killed, always_exits = ControlFlowOptimizationPass()._can_read_original_value(ptr, block)

        self.assertTrue(reads)
        self.assertFalse(killed)


class TestRegGlobalPropagationDerefInvalidation(unittest.TestCase):
    '''Codex Rule 2 second-pass finding: a cached REG/GLOBAL value that itself reads through a
    pointer (e.g. REG[0] = *arg1) must be invalidated by any later store through a pointer -
    otherwise the propagator re-evaluates the stale expression after the store instead of using
    the value that was actually captured into REG[0] beforehand.'''

    def test_cached_deref_value_is_invalidated_by_a_later_store_deref(self):
        func = MediumLevelILFunction('reg_global_test')
        block = func.create_block(start = FUNC_START)
        ptr_param = func.get_or_create_parameter(1, 'arg1')

        block.add_instruction(MLILStoreReg(0, MLILDeref(MLILVar(ptr_param))))
        block.add_instruction(MLILStoreDeref(MLILVar(ptr_param), MLILConst(1)))
        block.add_instruction(MLILRet(MLILLoadReg(0)))

        RegGlobalValuePropagationPass().run(func)

        # If wrongly propagated, this would become MLILDeref(arg1), re-reading *arg1 AFTER
        # the store instead of using REG[0]'s actual (pre-store) captured value.
        final_ret = block.instructions[-1]
        self.assertIsInstance(final_ret.value, MLILLoadReg)


class TestHLILCopyPropagationDerefStaleness(unittest.TestCase):
    '''Codex Rule 2 second-pass finding: an impure read (e.g. *p) must not be propagated past
    an intervening store through a pointer, even outside a loop - the read's value can change
    due to aliasing that _modifies_vars (which only tracks named variables) cannot see.'''

    def test_deref_read_is_not_propagated_across_an_intervening_deref_store(self):
        ptr = HLILVariable('arg1')
        temp = HLILVariable('var_s1')

        assign = HLILAssign(HLILVar(temp), HLILDeref(HLILVar(ptr)))
        store = HLILAssign(HLILDeref(HLILVar(ptr)), HLILConst(1))
        ret = HLILReturn(HLILVar(temp))
        block = HLILBlock([assign, store, ret])

        HLILCopyPropagationPass()._propagate_copies(block)

        # If wrongly propagated, `assign` would be removed and `ret.value` would become the
        # HLILDeref expression directly - re-reading *p AFTER the store instead of using the
        # value captured before it.
        self.assertIn(assign, block.statements)
        self.assertIsInstance(ret.value, HLILVar)


class TestDerefStoreVersionsAddressTakenLocal(unittest.TestCase):
    '''Codex Rule 2 round 6 finding: MLILStoreDeref never created an SSA version for the
    variable it might write through, even in straight-line code with no branching at all -
    a read after the store still saw the pre-store SSA version. The plan's own Step 3 design
    called for this defense explicitly ("have a deref store also clobber every address-taken
    local"); it had never actually been implemented.'''

    def test_read_after_deref_store_uses_a_new_ssa_version(self):
        # x = 1; *(&x) = 2; return x
        func = MediumLevelILFunction('addr_taken_store_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')

        block.add_instruction(MLILSetVar(x, MLILConst(1)))
        block.add_instruction(MLILStoreDeref(MLILAddressOf(MLILVar(x)), MLILConst(2)))
        block.add_instruction(MLILRet(MLILVar(x)))

        SSAConversionPass().run(func)

        set_inst = block.instructions[0]
        ret_inst = block.instructions[-1]
        self.assertIsInstance(set_inst, MLILSetVarSSA)
        self.assertIsInstance(ret_inst, MLILRet)
        self.assertIsInstance(ret_inst.value, MLILVarSSA)

        # The return must read a version created AFTER the store's pseudo-definition, not
        # the original `x = 1`'s version - proving the store's clobber was actually applied.
        self.assertNotEqual(ret_inst.value.var.version, set_inst.var.version)

    def test_deref_store_does_not_let_sccp_fold_a_stale_constant(self):
        # x = 1; *(&x) = 2; return x - full optimizer must not fold this to `return 1`
        func = MediumLevelILFunction('addr_taken_store_sccp_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')

        block.add_instruction(MLILSetVar(x, MLILConst(1)))
        block.add_instruction(MLILStoreDeref(MLILAddressOf(MLILVar(x)), MLILConst(2)))
        block.add_instruction(MLILRet(MLILVar(x)))

        optimize_mlil(func, infer_types_enabled = False)

        ret_inst = next(inst for inst in block.instructions if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 1)


class TestCallAddressTakenArgPhiPlacement(unittest.TestCase):
    '''Fable's independent review finding: the existing call-&arg pseudo-def mechanism
    (predates Step 3) created a pseudo-definition at rename time, but _collect_defs never
    knew about it - so no phi was placed at a merge point downstream of a conditional call,
    and the pre-call value could be folded in past the call entirely.'''

    def _build_diamond_with_addr_taken_call(self, name: str) -> MediumLevelILFunction:
        # var_s0 = 0; if (arg1 == 0) { f(&var_s0) } ; return var_s0 + 1
        func = MediumLevelILFunction(name)
        entry = func.create_block(start = FUNC_START)
        call_block = func.create_block(start = FUNC_START + 0x10)
        merge_block = func.create_block(start = FUNC_START + 0x20)

        arg1 = func.get_or_create_parameter(1, 'arg1')
        var_s0 = func.get_or_create_local('var_s0')

        entry.add_instruction(MLILSetVar(var_s0, MLILConst(0)))
        entry.add_instruction(MLILIf(MLILEq(MLILVar(arg1), MLILConst(0)), call_block, merge_block))
        entry.add_outgoing_edge(call_block)
        entry.add_outgoing_edge(merge_block)

        call_block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(var_s0))]))
        call_block.add_instruction(MLILGoto(merge_block))
        call_block.add_outgoing_edge(merge_block)

        merge_block.add_instruction(MLILRet(MLILAdd(MLILVar(var_s0), MLILConst(1))))

        return func

    def test_phi_placed_at_merge_after_conditional_call_with_addr_arg(self):
        func = self._build_diamond_with_addr_taken_call('addr_arg_phi_test')
        merge_block = func.basic_blocks[2]
        var_s0 = func.locals['var_s0']

        SSAConversionPass().run(func)

        phi = next((inst for inst in merge_block.instructions if isinstance(inst, MLILPhi)), None)
        self.assertIsNotNone(phi)
        self.assertEqual(phi.dest.base_var, var_s0)

    def test_optimizer_does_not_fold_past_the_conditional_call(self):
        func = self._build_diamond_with_addr_taken_call('addr_arg_phi_sccp_test')

        optimize_mlil(func, infer_types_enabled = False)

        ret_inst = next(inst for block in func.basic_blocks for inst in block.instructions
                         if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 1)


if __name__ == '__main__':
    unittest.main()
