#!/usr/bin/env python3
'''Unit tests for address-taken locals as memory during SSA - Step A of the Codex IR review
plan (independent-fix-steps A-K). Address-taken locals/parameters are lowered to explicit
*(&x) deref/store form during SSA construction (ir/mlil/mlil_ssa.py's
_lower_address_taken_vars) instead of being versioned like ordinary scalars - closing the
bug class where a call's real effect on an out-parameter was silently dropped (real examples:
mp0000_ev.EVENT_END_BTL, QSM410_00_01/QSM802_00_01).'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILFunction, MediumLevelILBasicBlock, MediumLevelILCall, MLILDeref,
    MLILStoreDeref, MLILSetVar, MLILVar, MLILVariable, MLILConst, MLILCall, MLILAddressOf,
    MLILIf, MLILGoto, MLILAdd, MLILSub, MLILEq, MLILGe, MLILRet, MLILStoreGlobal, MLILLoadGlobal,
)
from ir.mlil.mlil_ssa import SSAConstructor, SSADeconstructor
from ir.mlil.mlil_passes import SSAConversionPass
from ir.mlil.mlil_optimizer import optimize_mlil
from ir.mlil.passes import SSATypeInferencePass, RegGlobalValuePropagationPass
from ir.hlil.mlil_to_hlil import MLILToHLILConverter
from ir.hlil.hlil import (
    HLILDeref, HLILVar, HLILVariable, HLILConst, HLILAssign, HLILBlock, HLILAddressOf,
    HLILBinaryOp, BinaryOp, HighLevelILFunction, HLILIf, HLILCall, HLILExprStmt,
)
from ir.hlil.hlil_formatter import HLILFormatter
from ir.hlil.passes.pass_control_flow_optimization import ControlFlowOptimizationPass
from codegen.typescript import TypeScriptGenerator


FUNC_START = 0x1000


class TestStackTempOutParamNoStaleConstant(unittest.TestCase):
    '''EVENT_END_BTL's real shape: the address of a local is captured into a stack temp, the
    temp (not a literal &x) is passed to a call, and the local is read afterward. Cause 1 -
    _extract_addr_vars only ever recognized a literal AddressOf(Var) call argument, so this
    shape's call was never recorded as touching the local at all.'''

    def _build(self) -> MediumLevelILFunction:
        # var_s5 = 0; var_s14 = &var_s5; btl_get_area_pos(var_s14); return var_s5
        func = MediumLevelILFunction('event_end_btl_shape')
        block = func.create_block(start = FUNC_START)
        var_s5 = func.get_or_create_local('var_s5')
        var_s14 = func.get_or_create_local('var_s14')

        block.add_instruction(MLILSetVar(var_s5, MLILConst(0)))
        block.add_instruction(MLILSetVar(var_s14, MLILAddressOf(MLILVar(var_s5))))
        block.add_instruction(MLILCall('btl_get_area_pos', [MLILVar(var_s14)]))
        block.add_instruction(MLILRet(MLILVar(var_s5)))
        return func

    def test_does_not_fold_to_the_pre_call_constant(self):
        func = self._build()
        optimize_mlil(func, infer_types_enabled = False)

        ret_inst = next(inst for b in func.basic_blocks for inst in b.instructions
                         if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 0,
                          f'return folded to the pre-call constant: {ret_inst.value}')

    def test_ssa_gives_one_stable_address_no_second_version(self):
        func = self._build()
        SSAConversionPass().run(func)

        ret_inst = func.basic_blocks[0].instructions[-1]
        self.assertIsInstance(ret_inst.value, MLILDeref)
        ret_var = ret_inst.value.operand.operand.var
        self.assertEqual(ret_var.version, 0)


class TestSequentialOutParamCallsWithMidCopy(unittest.TestCase):
    '''x = 5; ptr = &x; f(ptr); old = x; f(ptr); return x - old - two distinct post-call
    values of x must never be conflated into `return 0`. Matches the example Codex's Rule 0
    root-cause review traced independently against real source.'''

    def _build(self) -> MediumLevelILFunction:
        func = MediumLevelILFunction('sequential_out_param_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')
        ptr = func.get_or_create_local('ptr')
        old = func.get_or_create_local('old')

        block.add_instruction(MLILSetVar(x, MLILConst(5)))
        block.add_instruction(MLILSetVar(ptr, MLILAddressOf(MLILVar(x))))
        block.add_instruction(MLILCall('f', [MLILVar(ptr)]))
        block.add_instruction(MLILSetVar(old, MLILVar(x)))
        block.add_instruction(MLILCall('f', [MLILVar(ptr)]))
        block.add_instruction(MLILRet(MLILSub(MLILVar(x), MLILVar(old))))
        return func

    def test_does_not_fold_to_zero(self):
        func = self._build()
        optimize_mlil(func, infer_types_enabled = False)

        ret_inst = next(inst for b in func.basic_blocks for inst in b.instructions
                         if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 0,
                          f'x - old folded to a constant 0: {ret_inst.value}')

    def test_no_minted_shadow_name_for_address_taken_locals(self):
        func = self._build()
        SSAConversionPass().run(func)
        SSADeconstructor(func).deconstruct()

        minted = [name for name in func.locals
                  if name.startswith(('x_v', 'ptr_v', 'old_v'))]
        self.assertEqual(minted, [], f'unexpected minted shadow names: {minted}')


class TestAddressTakenControlFlowShapes(unittest.TestCase):
    '''Address-taken locals need no phi at any merge point - not diamond joins, not loop
    back-edges - since they are never scalar-versioned in the first place.'''

    def test_both_arm_diamond_write_needs_no_phi(self):
        # if (arg1 == 0) { f(&x) } else { g(&x) }; return x
        func = MediumLevelILFunction('diamond_addr_taken')
        entry = func.create_block(start = FUNC_START)
        true_block = func.create_block(start = FUNC_START + 0x10)
        false_block = func.create_block(start = FUNC_START + 0x20)
        merge_block = func.create_block(start = FUNC_START + 0x30)

        arg1 = func.get_or_create_parameter(1, 'arg1')
        x = func.get_or_create_local('x')

        entry.add_instruction(MLILIf(MLILEq(MLILVar(arg1), MLILConst(0)), true_block, false_block))
        entry.add_outgoing_edge(true_block)
        entry.add_outgoing_edge(false_block)

        true_block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        true_block.add_instruction(MLILGoto(merge_block))
        true_block.add_outgoing_edge(merge_block)

        false_block.add_instruction(MLILCall('g', [MLILAddressOf(MLILVar(x))]))
        false_block.add_instruction(MLILGoto(merge_block))
        false_block.add_outgoing_edge(merge_block)

        merge_block.add_instruction(MLILRet(MLILVar(x)))

        SSAConversionPass().run(func)

        for block in func.basic_blocks:
            for inst in block.instructions:
                if inst.__class__.__name__ == 'MLILPhi':
                    self.assertNotEqual(inst.dest.base_var, x, 'address-taken x must never need a phi')

    def test_loop_carried_write_with_prev_copy_needs_no_phi(self):
        # x = 0; while (arg1 != 0) { prev = x; f(&x); arg1 = arg1 - 1 }; return x - prev
        func = MediumLevelILFunction('loop_addr_taken')
        entry = func.create_block(start = FUNC_START)
        loop_block = func.create_block(start = FUNC_START + 0x10)
        exit_block = func.create_block(start = FUNC_START + 0x20)

        arg1 = func.get_or_create_parameter(1, 'arg1')
        x = func.get_or_create_local('x')
        prev = func.get_or_create_local('prev')

        entry.add_instruction(MLILSetVar(x, MLILConst(0)))
        entry.add_instruction(MLILIf(MLILEq(MLILVar(arg1), MLILConst(0)), exit_block, loop_block))
        entry.add_outgoing_edge(exit_block)
        entry.add_outgoing_edge(loop_block)

        loop_block.add_instruction(MLILSetVar(prev, MLILVar(x)))
        loop_block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        loop_block.add_instruction(MLILSetVar(arg1, MLILSub(MLILVar(arg1), MLILConst(1))))
        loop_block.add_instruction(MLILIf(MLILEq(MLILVar(arg1), MLILConst(0)), exit_block, loop_block))
        loop_block.add_outgoing_edge(exit_block)
        loop_block.add_outgoing_edge(loop_block)

        exit_block.add_instruction(MLILRet(MLILSub(MLILVar(x), MLILVar(prev))))

        SSAConversionPass().run(func)

        for block in func.basic_blocks:
            for inst in block.instructions:
                if inst.__class__.__name__ == 'MLILPhi':
                    self.assertNotEqual(inst.dest.base_var, x, 'address-taken x must never need a phi')


class TestMultipleAddressTakenArgsAndParameter(unittest.TestCase):
    def test_constant_not_propagated_across_call(self):
        # x = 7; f(&x); return x - must not fold to `return 7`
        func = MediumLevelILFunction('const_prop_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')

        block.add_instruction(MLILSetVar(x, MLILConst(7)))
        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        block.add_instruction(MLILRet(MLILVar(x)))

        optimize_mlil(func, infer_types_enabled = False)

        ret_inst = next(inst for b in func.basic_blocks for inst in b.instructions
                         if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 7)

    def test_multiple_address_taken_args_to_one_call(self):
        # x = 1; y = 2; f(&x, &y); return x + y - must not fold to `return 3`
        func = MediumLevelILFunction('multi_addr_taken_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')
        y = func.get_or_create_local('y')

        block.add_instruction(MLILSetVar(x, MLILConst(1)))
        block.add_instruction(MLILSetVar(y, MLILConst(2)))
        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x)), MLILAddressOf(MLILVar(y))]))
        block.add_instruction(MLILRet(MLILAdd(MLILVar(x), MLILVar(y))))

        optimize_mlil(func, infer_types_enabled = False)

        ret_inst = next(inst for b in func.basic_blocks for inst in b.instructions
                         if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 3)

    def test_address_taken_parameter_stays_one_stable_identity(self):
        func = MediumLevelILFunction('addr_taken_param_test')
        block = func.create_block(start = FUNC_START)
        arg1 = func.get_or_create_parameter(1, 'arg1')

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(arg1))]))
        block.add_instruction(MLILRet(MLILVar(arg1)))

        SSAConstructor(func).construct()

        ret_inst = func.basic_blocks[0].instructions[-1]
        self.assertIsInstance(ret_inst.value, MLILDeref)
        self.assertEqual(ret_inst.value.operand.operand.var.version, 0)


class TestRegGlobalPropagationAddressTaken(unittest.TestCase):
    '''GLOBAL[n] = x; *(&x) = 5; use(GLOBAL[n]) - the value captured into GLOBAL[0] before
    the store must not be replaced by a re-read of *x after it. RegGlobalValuePropagator's
    deref-invalidation (Step 3) already defends this; Step A's lowering makes an address-
    taken local's ordinary reassignment go through exactly the same StoreDeref shape.'''

    def test_stale_global_copy_not_substituted_after_address_taken_reassignment(self):
        func = MediumLevelILFunction('reg_global_addr_taken_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')

        block.add_instruction(MLILStoreGlobal(0, MLILDeref(MLILAddressOf(MLILVar(x)))))
        block.add_instruction(MLILStoreDeref(MLILAddressOf(MLILVar(x)), MLILConst(5)))
        block.add_instruction(MLILCall('use', [MLILLoadGlobal(0)]))

        RegGlobalValuePropagationPass().run(func)

        call_inst = next(inst for b in func.basic_blocks for inst in b.instructions
                          if isinstance(inst, MLILCall))
        self.assertIsInstance(call_inst.args[0], MLILLoadGlobal)


class TestCallResultFolderRespectsAddressTakenDeref(unittest.TestCase):
    '''reg0 = f(&x); y = x + reg0 - CallResultFolder must not fold this into
    y = x + f(&x), which would read x through the pointer before f's call actually writes
    it. _reads_before_impure (ir/hlil/mlil_to_hlil.py) already defends a bare MLILDeref;
    Step A's lowering makes every address-taken read go through exactly that shape.'''

    def test_fold_is_blocked_by_the_intervening_deref_read(self):
        func = MediumLevelILFunction('call_result_fold_test', 0)
        block = MediumLevelILBasicBlock(0)
        x = MLILVariable('x')
        reg0 = MLILVariable('reg0')
        y = MLILVariable('y')
        func.locals['x'] = x
        func.locals['reg0'] = reg0
        func.locals['y'] = y

        block.instructions = [
            MLILCall('f', [MLILAddressOf(MLILVar(x))], reg0),
            MLILSetVar(y, MLILAdd(MLILDeref(MLILAddressOf(MLILVar(x))), MLILVar(reg0))),
            MLILRet(MLILVar(y)),
        ]
        func.basic_blocks = [block]

        hlil_func = MLILToHLILConverter(func).convert()

        # f() must remain reachable as a statement in its own right somewhere in the
        # function - never re-inlined so that only y's assignment calls it
        call_exprs = []

        def collect_calls(node):
            if isinstance(node, HLILCall):
                call_exprs.append(node)
            for attr in ('lhs', 'rhs', 'operand', 'src', 'dest', 'value', 'condition'):
                child = getattr(node, attr, None)
                if child is not None:
                    collect_calls(child)

        for stmt in hlil_func.body.statements:
            collect_calls(stmt)

        f_calls = [c for c in call_exprs if c.func_name == 'f']
        self.assertEqual(len(f_calls), 1)

        # y's own assignment source must NOT itself contain the call - it must read the
        # captured reg0 instead
        y_assigns = [s for s in hlil_func.body.statements
                     if isinstance(s, HLILAssign) and isinstance(s.dest, HLILVar) and s.dest.var.name == 'y']
        self.assertEqual(len(y_assigns), 1)

        def contains_call(node) -> bool:
            if isinstance(node, HLILCall):
                return True
            for attr in ('lhs', 'rhs', 'operand'):
                child = getattr(node, attr, None)
                if child is not None and contains_call(child):
                    return True
            return False

        self.assertFalse(contains_call(y_assigns[0].src),
                          f'f() was re-inlined into y = ...: {y_assigns[0].src}')


class TestCFORedundantElseAssignAddressTakenReload(unittest.TestCase):
    '''Codex Rule 0 correction, 2026-09-22: making the DISCRIMINANT itself address-taken
    would never reach _stmt_modifies_any at all - _remove_redundant_else_assign requires a
    plain HLILVar discriminant and returns immediately otherwise. Correct shape: keep the
    discriminant plain; make the reloaded value read a DIFFERENT, address-taken variable
    that the case body writes through *(&x).'''

    def test_reload_of_address_taken_source_is_not_removed(self):
        # if (selector == 1) { *(&addr_var) = 99 }
        # else { selector = *(&addr_var); if (selector == 2) { case_2() } }
        selector = HLILVariable('selector')
        addr_var = HLILVariable('addr_var')
        addr_read = HLILDeref(HLILAddressOf(HLILVar(addr_var)))

        case_body = HLILBlock([HLILAssign(addr_read, HLILConst(99))])
        inner_if = HLILIf(HLILBinaryOp(BinaryOp.EQ, HLILVar(selector), HLILConst(2)),
                           HLILBlock([HLILExprStmt(HLILCall('case_2', []))]), HLILBlock())
        reload_assign = HLILAssign(HLILVar(selector), addr_read)
        false_block = HLILBlock([reload_assign, inner_if])
        first_if = HLILIf(HLILBinaryOp(BinaryOp.EQ, HLILVar(selector), HLILConst(1)),
                           case_body, false_block)

        func = HighLevelILFunction('cfo_addr_taken_reload_test')
        func.add_statement(first_if)
        func = ControlFlowOptimizationPass().run(func)

        else_stmts = func.body.statements[0].false_block.statements
        # The reload must survive: the true-block's *(&addr_var) = 99 really did modify the
        # value source_expr reads, even though it is now wrapped in deref/addr_of form
        self.assertEqual(len(else_stmts), 2, f'reload was wrongly removed: {[str(s) for s in else_stmts]}')
        self.assertIsInstance(else_stmts[0], HLILAssign)


class TestAddressTakenBackwardTypeInference(unittest.TestCase):
    '''A pure out-parameter with no separate store, typed only via a later comparison use,
    must still get typed after lowering - _infer_from_comparison etc. must unwrap *(&x) the
    same as a direct MLILVarSSA. The comparison must sit as a bare top-level MLILIf
    condition - _infer_from_usage only dispatches on the top-level instruction per block,
    it does not recurse into nested expressions.'''

    def test_comparison_only_usage_still_types_the_address_taken_local(self):
        # f(&x); if (x >= 2) { return 1 } else { return 0 } - x has no separate store
        func = MediumLevelILFunction('backward_infer_test')
        block = func.create_block(start = FUNC_START)
        true_block = func.create_block(start = FUNC_START + 0x10)
        false_block = func.create_block(start = FUNC_START + 0x20)
        x = func.get_or_create_local('x')

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        block.add_instruction(MLILIf(MLILGe(MLILVar(x), MLILConst(2)), true_block, false_block))
        block.add_outgoing_edge(true_block)
        block.add_outgoing_edge(false_block)
        true_block.add_instruction(MLILRet(MLILConst(1)))
        false_block.add_instruction(MLILRet(MLILConst(0)))

        SSAConstructor(func).construct()
        SSATypeInferencePass().run(func)

        self.assertIn('x', func.var_types)
        self.assertTrue(func.var_types['x'].is_numeric(), f'x was not typed: {func.var_types.get("x")}')


class TestAddressTakenCodegenBooleanCoercion(unittest.TestCase):
    '''x = (a == b), for a numeric address-taken local x, must print x = int(a == b) - not
    a bare boolean - through the *(&x) fold-back path specifically, reusing the ordinary
    assignment branch's coercion rather than a second, unreimplemented copy.'''

    def test_boolean_assigned_to_numeric_address_taken_local_gets_int_wrapped(self):
        x = HLILVariable('x', 'int')
        a = HLILVariable('a')
        b = HLILVariable('b')
        bool_expr = HLILBinaryOp(BinaryOp.EQ, HLILVar(a), HLILVar(b))
        assign = HLILAssign(HLILDeref(HLILAddressOf(HLILVar(x))), bool_expr)

        lines = TypeScriptGenerator._generate_statement(assign)
        self.assertTrue(any('x = int(' in line for line in lines), f'{lines}')


class TestAddressTakenPrinting(unittest.TestCase):
    '''*(&x) and *(&x) = v must print as plain x and x = v - never deref(addr_of(x)) /
    deref_set(addr_of(x), v) - in both the TypeScript codegen and the debug HLIL formatter.'''

    def test_typescript_read_and_write_fold_back_to_plain_variable(self):
        x = HLILVariable('x', 'int')
        lowered_read = HLILDeref(HLILAddressOf(HLILVar(x)))

        self.assertEqual(TypeScriptGenerator._format_expr(lowered_read), 'x')

        assign_lines = TypeScriptGenerator._generate_statement(HLILAssign(lowered_read, HLILConst(5)))
        self.assertTrue(any('x = 5' in line for line in assign_lines))
        self.assertFalse(any('deref' in line for line in assign_lines))

    def test_hlil_formatter_read_folds_back_to_plain_variable(self):
        x = HLILVariable('x')
        lowered_read = HLILDeref(HLILAddressOf(HLILVar(x)))

        self.assertEqual(HLILFormatter._format_expr(lowered_read), 'x')


class TestRebuildOpsPreserveMetadata(unittest.TestCase):
    '''_rebuild_binary_op/_rebuild_unary_op must copy source metadata (address) onto the
    node they construct - previously silently dropped, and this step's lowering exercises
    that path far more often (every expression containing an address-taken read).'''

    def test_rebuilt_binary_op_keeps_source_address(self):
        # y = x + 1, where x is address-taken and the add carries its own source address
        func = MediumLevelILFunction('metadata_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')
        y = func.get_or_create_local('y')

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        add_expr = MLILAdd(MLILVar(x), MLILConst(1), address = 0x1234)
        block.add_instruction(MLILSetVar(y, add_expr))

        SSAConstructor(func).construct()

        set_inst = block.instructions[-1]
        self.assertEqual(set_inst.value.address, 0x1234,
                          'rebuilt MLILAdd must keep the source expression\'s address')


class TestCallOutputDecomposition(unittest.TestCase):
    '''A call whose own `output` field coincides with an address-taken local - synthetic,
    since the real ED9 translator cannot produce this shape today, but proves the
    structural fix (redirect through a fresh temp) actually closes the naming-split gap
    rather than merely asserting against it.'''

    def test_call_output_aliasing_address_taken_local_is_decomposed(self):
        # x = f(); g(&x); return x - x is both a call's own output AND address-taken
        func = MediumLevelILFunction('call_output_decompose_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')

        call1 = MLILCall('f', [], x)
        block.add_instruction(call1)
        block.add_instruction(MLILCall('g', [MLILAddressOf(MLILVar(x))]))
        block.add_instruction(MLILRet(MLILVar(x)))

        SSAConstructor(func).construct()

        self.assertTrue(call1.output.base_var.name.startswith('x__result'),
                         f'call output should be redirected to a fresh temp, got {call1.output}')

        ret_inst = block.instructions[-1]
        self.assertIsInstance(ret_inst.value, MLILDeref)


class TestAddressTakenStructuralInvariants(unittest.TestCase):
    '''Defensive invariants the address-taken lowering is designed to guarantee, checked
    directly rather than only inferred from behavior.'''

    def test_lowered_local_never_appears_as_a_scalar_ssa_target(self):
        func = MediumLevelILFunction('invariant_test')
        block = func.create_block(start = FUNC_START)
        x = func.get_or_create_local('x')

        block.add_instruction(MLILSetVar(x, MLILConst(1)))
        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(x))]))
        block.add_instruction(MLILSetVar(x, MLILConst(2)))
        block.add_instruction(MLILRet(MLILVar(x)))

        SSAConstructor(func).construct()

        for inst in block.instructions:
            if inst.__class__.__name__ == 'MLILSetVarSSA':
                self.assertNotEqual(inst.var.base_var, x)
            elif inst.__class__.__name__ == 'MLILPhi':
                self.assertNotEqual(inst.dest.base_var, x)
            elif isinstance(inst, MediumLevelILCall) and inst.output is not None:
                output_base = getattr(inst.output, 'base_var', inst.output)
                self.assertNotEqual(output_base, x)

    def test_address_of_register_raises(self):
        func = MediumLevelILFunction('addr_of_register_test')
        block = func.create_block(start = FUNC_START)
        reg0 = func.get_or_create_register_var(0)

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(reg0))]))
        block.add_instruction(MLILRet(MLILConst(0)))

        with self.assertRaises(NotImplementedError):
            SSAConstructor(func).construct()

    def test_address_of_global_raises(self):
        func = MediumLevelILFunction('addr_of_global_test')
        block = func.create_block(start = FUNC_START)
        global0 = func.get_or_create_global_var(0)

        block.add_instruction(MLILCall('f', [MLILAddressOf(MLILVar(global0))]))
        block.add_instruction(MLILRet(MLILConst(0)))

        with self.assertRaises(NotImplementedError):
            SSAConstructor(func).construct()


class TestAddressTakenFromRealLLIL(unittest.TestCase):
    '''End to end from real LLIL, built the same way the disassembler/lifter would (not
    hand-built MLIL): push_stack_addr + pop_to materializes the stack-temp shape, a fresh
    load_stack re-reads it for the syscall so the call sees the temp, not a literal &x.'''

    def test_syscall_through_stack_temp_pointer_does_not_fold(self):
        builder = FalcomVMBuilder()
        builder.create_function('addr_taken_repro', FUNC_START, num_params = 0)
        entry = builder.create_basic_block(FUNC_START, 'addr_taken_repro')
        builder.set_current_block(entry)

        builder.push_int(5)                    # var_s0 = 5; sp 0->1
        builder.push_stack_addr(-WORD_SIZE)     # push &var_s0 (slot 0); sp 1->2
        builder.pop_to(0)                       # var_s1 (slot 1) = &var_s0; sp 2->1
        builder.load_stack(0)                   # push var_s1's value fresh; sp 1->2
        builder.syscall(1, 1, 1)                # syscall(var_s1) - sp stays 2
        builder.load_stack(-2 * WORD_SIZE)      # push var_s0's value; sp 2->3
        builder.set_reg(0)                      # reg0 = var_s0's value; sp 3->2
        builder.ret()

        mlil_func = convert_falcom_llil_to_mlil(builder.function, optimize = True, infer_types = False)

        ret_inst = next(inst for b in mlil_func.basic_blocks for inst in b.instructions
                         if isinstance(inst, MLILRet))
        self.assertFalse(isinstance(ret_inst.value, MLILConst) and ret_inst.value.value == 5,
                          f'return folded to the pre-syscall constant: {ret_inst.value}')


if __name__ == '__main__':
    unittest.main()
