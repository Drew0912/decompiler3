#!/usr/bin/env python3
"""The logic check (tools/logic_check/), LLIL against MLIL: a bug planted in the MLIL of a small assembled function
shows up as its category, and the unchanged MLIL compares clean; an effect's values compared argument by argument; a
real script compares clean on both pairs"""

from pathlib import Path
import copy
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil.stack_translator import DEBUG_LOG_CALL_TARGET
from falcom.ed9.ir.mlil_ssa.mlil_converter import convert_falcom_llil_to_mlil_ssa
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILCall, MLILAdd, MLILAddressOf, MLILCall, MLILConst, MLILEq, MLILGe, MLILIf, MLILLoadGlobal,
    MLILLoadReg, MLILLt, MLILRet, MLILSetVar, MLILStoreDeref, MLILStoreGlobal, MLILStoreReg, MLILVar, MLILVariable,
    map_operands, walk,
)
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, GLOBAL_C, LOOP_LIMIT, MESSAGE, OUT_INITIAL, REG_INDEX, STORED, UNRELATED_ARG, branch_function,
    call, calls_function, categories, first, initialised_out_parameter_function, loop_call_function,
    optional_call_result_function, reference_and_mlil, return_nothing, statements,
)
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm
import logic_check
from logic_check.facts import Effect, Facts
from logic_check.state import PHI_DEPTH
from logic_check.trees import const
from logic_check.vm_effects import VMEffects

REG_OUT = 7
DEEP_INITIAL = 1
ENDLESS_TAIL_PARAMETERS = 2
TAIL_CALL_ARG = 6


# === Assembled functions ===

def two_results_function() -> tuple[Asm, int]:
    """x = callee(); y = callee(); GLOBAL[0] = callee() + (x - y): two results held across later calls"""
    asm = Asm()
    asm.push_raw(0); asm.push_raw(0)
    call(asm, 'x'); asm.get_reg(0); asm.pop_to(-2 * WORD_SIZE)
    call(asm, 'y'); asm.get_reg(0); asm.pop_to(-WORD_SIZE)
    call(asm, 'z'); asm.get_reg(0)
    asm.load_stack(-3 * WORD_SIZE); asm.load_stack(-3 * WORD_SIZE); asm.sub(); asm.add(); asm.set_global(0)
    asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 0


def out_parameter_function() -> tuple[Asm, int]:
    """v; callee(&v); GLOBAL[0] = v"""
    asm = Asm()
    asm.push_raw(0)
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('after'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def unrelated_call_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; callee(UNRELATED_ARG); GLOBAL[0] = v; callee(&v): the first call is given no pointer to v, so
    v holds its value across it"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    call(asm, 'first', UNRELATED_ARG)
    asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.push_raw(CALLER_ID); asm.push_raw('second'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('second'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def escaped_address_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; GLOBAL_A = &v; callee(); GLOBAL_B = v: the callee is given no pointer, but can reach v through
    the global"""
    asm = Asm()
    asm.push_int(OUT_INITIAL); asm.push_stack_offset(-WORD_SIZE); asm.set_global(GLOBAL_A)
    call(asm, 'back')
    asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_B)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def pointer_to_pointer_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; q = &v; callee(&q): the callee is given q's address, and reaches v through q"""
    asm = Asm()
    asm.push_int(OUT_INITIAL); asm.push_stack_offset(-WORD_SIZE)
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 1


def one_arm_register_function() -> tuple[Asm, int]:
    """if GLOBAL_A: REG = REG_OUT; returned: the other arm leaves the register's incoming value for the caller"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('end')
    asm.push_int(REG_OUT); asm.set_reg(REG_INDEX)
    asm.label('end'); return_nothing(asm)
    return asm, 0


def loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: i = i + 1; GLOBAL[0] = i"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('done'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def counter_loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: callee(UNRELATED_ARG); i = i + 1: only the loop's condition reads i"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_int(UNRELATED_ARG); asm.call(CALLEE_ID)
    asm.label('back'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def register_loop_function() -> tuple[Asm, int]:
    """r = 0; i = 0; while i < LOOP_LIMIT: r = r + 1; i = i + 1 (r register REG_INDEX, updated first): only the return
    reads r, among the registers it passes on"""
    asm = Asm()
    asm.push_int(0); asm.push_int(0); asm.set_reg(REG_INDEX)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.get_reg(REG_INDEX); asm.push_int(1); asm.add(); asm.set_reg(REG_INDEX)
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def saved_register_function() -> tuple[Asm, int]:
    """s = REG; if GLOBAL_A: callee() else: REG = REG_OUT; GLOBAL_B = REG; GLOBAL_C = s: s holds the register's value
    from before the call"""
    asm = Asm()
    asm.get_reg(REG_INDEX)
    asm.load_global(GLOBAL_A); asm.jz('other')
    call(asm, 'back')
    asm.jmp('join')
    asm.label('other'); asm.push_int(REG_OUT); asm.set_reg(REG_INDEX)
    asm.label('join'); asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_B)
    asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_C)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def saved_register_loop_function() -> tuple[Asm, int]:
    """s = REG; REG = REG_OUT; i = 0; while i < LOOP_LIMIT: callee(); i = i + 1; GLOBAL_B = REG; GLOBAL_C = s"""
    asm = Asm()
    asm.get_reg(REG_INDEX)
    asm.push_int(REG_OUT); asm.set_reg(REG_INDEX)
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    call(asm, 'back')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_B)
    asm.load_stack(-2 * WORD_SIZE); asm.set_global(GLOBAL_C)
    asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 0


def unwritten_register_function() -> tuple[Asm, int]:
    """s = REG; if GLOBAL_A: callee(); GLOBAL_B = REG; GLOBAL_C = s: no arm writes the register"""
    asm = Asm()
    asm.get_reg(REG_INDEX)
    asm.load_global(GLOBAL_A); asm.jz('join')
    call(asm, 'back')
    asm.label('join'); asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_B)
    asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_C)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def deep_join_function() -> tuple[Asm, int]:
    """v = DEEP_INITIAL; then PHI_DEPTH + 1 times: if GLOBAL[i]: v = DEEP_INITIAL + i + 1; GLOBAL[0] = v: the value
    stored merges more joins deep than a phi is spelled out"""
    asm = Asm()
    asm.push_int(DEEP_INITIAL)
    for index in range(PHI_DEPTH + 1):
        asm.load_global(index); asm.jz(f'skip{index}')
        asm.push_int(DEEP_INITIAL + index + 1); asm.pop_to(-WORD_SIZE)
        asm.label(f'skip{index}')
    asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def endless_tail_function() -> tuple[Asm, int]:
    """f(a, b): if b: { if a: REG = 1 else REG = 2; callee() } then loop forever: the call runs on the outer arm only,
    in a block the endless loop post-dominates. The branches read parameters, which a call does not change, and only
    the call is an effect, so a moved call differs in its guard alone"""
    asm = Asm()
    asm.load_stack(-WORD_SIZE); asm.jz('forever')
    asm.load_stack(-2 * WORD_SIZE); asm.jz('else')
    asm.push_int(1); asm.set_reg(REG_INDEX); asm.jmp('join')
    asm.label('else'); asm.push_int(2); asm.set_reg(REG_INDEX)
    asm.label('join'); call(asm, 'outer')
    asm.label('forever'); asm.jmp('forever')
    return asm, 0


def tail_call_function() -> tuple[Asm, int]:
    """callee(1); then a tail call (CALL_SCRIPT_NO_RETURN) of another script's function, which MLIL writes as the
    script call and the return of its result"""
    asm = Asm()
    call(asm, 'first', 1)
    asm.push_int(TAIL_CALL_ARG); asm.call_script_no_return(1)
    return asm, 1


def joined_slot_function() -> tuple[Asm, int]:
    """GLOBAL_A = 1 + (GLOBAL[0] ? 5 : 7), the joined slot read by offset: one local, written in each arm"""
    asm = Asm()
    asm.load_global(0); asm.jz('else')
    asm.push_int(5); asm.jmp('join')
    asm.label('else'); asm.push_int(7)
    asm.label('join'); asm.push_int(1); asm.load_stack(-2 * WORD_SIZE); asm.add(); asm.set_global(GLOBAL_A)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def sibling_out_parameters_function() -> tuple[Asm, int]:
    """v1 = OUT_INITIAL; callee(&v1); then v2 = STORED; callee(&v2): two out-parameter locals in sibling scopes, the
    second in the slot the first's scope left"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    asm.push_raw(CALLER_ID); asm.push_raw('first'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('first'); asm.pop(WORD_SIZE)
    asm.push_int(STORED)
    asm.push_raw(CALLER_ID); asm.push_raw('second'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('second'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def register_before_loop_function() -> tuple[Asm, int]:
    """REG = 5; i = 0; while i < LOOP_LIMIT: callee(i); i = i + 1: an entry block that only copies, before a loop"""
    asm = Asm()
    asm.push_int(5); asm.set_reg(REG_INDEX)
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


# === Mutations of the MLIL ===

def is_debug_log(inst) -> bool:
    return isinstance(inst, MLILCall) and inst.target == DEBUG_LOG_CALL_TARGET


def is_call(inst) -> bool:
    return isinstance(inst, MediumLevelILCall) and not is_debug_log(inst)


def rewrite(node, transform):
    """transform applied bottom-up to every expression under node"""
    return transform(map_operands(node, lambda operand: rewrite(operand, transform)))


def replace_reads(mlil, old, new, start: tuple):
    """Every read of variable old from the statement at start on (in its block) read as variable new instead"""
    block, index, _ = start
    for position in range(index, len(block.instructions)):
        block.instructions[position] = rewrite(
            block.instructions[position], lambda e: MLILVar(new) if isinstance(e, MLILVar) and e.var == old else e)


def sibling(var: MLILVariable, scope: int) -> MLILVariable:
    """var's slot under a sibling scope's name, `var_s<slot>_<scope>`, as the stack translator names them apart"""
    return MLILVariable(f'{var.name}_{scope}', var.slot_index)


def write_as(entry: tuple, var: MLILVariable):
    """The write at entry (block, index, MLILSetVar) made a write of var"""
    block, index, inst = entry
    block.instructions[index] = MLILSetVar(var, inst.value).copy_metadata_from(inst)


def joined_slot_writes_and_read(mlil) -> tuple:
    """joined_slot_function's MLIL: its two writes of the local and the statement reading it"""
    writes = [entry for entry in statements(mlil) if isinstance(entry[2], MLILSetVar)]
    return writes, first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))


def out_parameters_named_apart(mlil) -> list:
    """sibling_out_parameters_function's MLIL: each local's memory-form store and the call passed its address made
    those of its own sibling scope (var_s<slot>_0, _1); the stores, in order"""
    stores = [inst for _, _, inst in statements(mlil) if isinstance(inst, MLILStoreDeref)]
    calls = [inst for _, _, inst in statements(mlil) if is_call(inst)]
    local = stores[0].dest.operand.var
    for scope, (store, call_inst) in enumerate(zip(stores, calls)):
        store.dest = MLILAddressOf(MLILVar(sibling(local, scope)))
        call_inst.args[0] = MLILAddressOf(MLILVar(sibling(local, scope)))
    return stores


def restore_register_after_the_call(mlil):
    """REG = s after the call, s the register's value saved before it: a register read past a call as stale"""
    saved = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILLoadReg))[2]
    block, index, _ = first(mlil, is_call)
    block.instructions.insert(index + 1, MLILStoreReg(REG_INDEX, MLILVar(saved.var)))


class TestPlantedBugs(unittest.TestCase):
    """Each bug class a translator or a pass could bring, planted in real MLIL: the logic check reports its category"""

    def check(self, build, mutate, expected: str, argc: int = 0):
        reference, mlil = reference_and_mlil(build, argc)
        self.assertEqual(categories(reference, mlil), set(), 'the unchanged MLIL compares clean')
        mutate(mlil)
        self.assertIn(expected, categories(reference, mlil))

    def test_swapped_arguments(self):
        def mutate(mlil):
            inst = first(mlil, is_call)[2]
            inst.args[0], inst.args[1] = inst.args[1], inst.args[0]
        self.check(calls_function, mutate, 'arg_differs')

    def test_changed_constant(self):
        def mutate(mlil):
            inst = first(mlil, is_call)[2]
            inst.args[0] = MLILConst(inst.args[0].value + 1)
        self.check(calls_function, mutate, 'arg_differs')

    def test_dropped_effect(self):
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))
            del block.instructions[index]
        self.check(calls_function, mutate, 'missing_effect')

    def test_duplicated_effect(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_call)
            block.instructions.insert(index, inst.rebuild(*inst.args))
        self.check(calls_function, mutate, 'added_effect')

    def test_two_calls_swapped(self):
        def mutate(mlil):
            calls = [entry for entry in statements(mlil) if is_call(entry[2])]
            (block, a, call_a), (_, b, call_b) = calls[0], calls[1]
            block.instructions[a], block.instructions[b] = call_b, call_a
        self.check(calls_function, mutate, 'order_differs')

    def test_debug_log_argument_changed(self):
        def mutate(mlil):
            inst = first(mlil, is_debug_log)[2]
            inst.args[1] = MLILConst(MESSAGE + '!')
        self.check(calls_function, mutate, 'arg_differs')

    def test_debug_log_dropped(self):
        def mutate(mlil):
            block, index, _ = first(mlil, is_debug_log)
            del block.instructions[index]
        self.check(calls_function, mutate, 'missing_effect')

    def test_debug_log_duplicated(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_debug_log)
            block.instructions.insert(index, inst.rebuild(*inst.args))
        self.check(calls_function, mutate, 'added_effect')

    def test_flipped_branch(self):
        def mutate(mlil):
            branch = first(mlil, lambda inst: isinstance(inst, MLILIf))[2]
            branch.true_target, branch.false_target = branch.false_target, branch.true_target
        self.check(branch_function, mutate, 'branch_targets_differ')

    def test_changed_condition(self):
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            condition = rewrite(branch.condition,
                                lambda e: MLILLoadGlobal(GLOBAL_C) if isinstance(e, MLILLoadGlobal) else e)
            block.instructions[index] = MLILIf(condition, branch.true_target, branch.false_target) \
                .copy_metadata_from(branch)
        self.check(branch_function, mutate, 'condition_differs')

    def test_call_moved_under_a_branch(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_call)
            branch = block.instructions[-1]
            del block.instructions[index]
            branch.false_target.instructions.insert(0, inst)
        self.check(branch_function, mutate, 'guard_differs')

    def test_stale_register_read(self):
        """x = callee() held across later calls, its copy reading the register instead of the call's temporary: no MLIL
        statement wrote the register, so a printed REGS[0] would be stale"""
        def mutate(mlil):
            temporary = first(mlil, is_call)[2].output
            block, index, copy = first(mlil, lambda inst: isinstance(inst, MLILSetVar)
                                       and isinstance(inst.value, MLILVar) and inst.value.var == temporary)
            block.instructions[index] = MLILSetVar(copy.var, MLILLoadReg(VMEffects.RESULT_REGISTER)) \
                .copy_metadata_from(copy)
        self.check(two_results_function, mutate, 'arg_differs')

    def test_reused_temporary(self):
        """The second held result given the first one's variable"""
        def mutate(mlil):
            copies = [entry for entry in statements(mlil)
                      if isinstance(entry[2], MLILSetVar) and isinstance(entry[2].value, MLILVar)]
            (_, _, x), (block, index, y) = copies[0], copies[1]
            block.instructions[index] = MLILSetVar(x.var, y.value).copy_metadata_from(y)
            replace_reads(mlil, y.var, x.var, (block, index + 1, None))
        self.check(two_results_function, mutate, 'arg_differs')

    def test_out_parameter_read_before_its_call(self):
        """GLOBAL[0] = v moved before callee(&v): the read no longer sees what the call wrote"""
        def mutate(mlil):
            block, index, store = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))
            call_index = first(mlil, is_call)[1]
            del block.instructions[index]
            block.instructions.insert(call_index, store)
        self.check(out_parameter_function, mutate, 'arg_differs')

    def test_value_behind_a_pointer_changed(self):
        """v's initial value changed before callee(&v): only the callee can read it, and v after the call is the call's
        leaf"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(initialised_out_parameter_function, mutate, 'arg_differs')

    def test_value_merged_past_the_phi_depth_changed(self):
        """v's initial value changed: it reaches the store only through more joins than a phi spells out"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILConst)
                         and inst.value.value == DEEP_INITIAL)[2]
            init.value = MLILConst(DEEP_INITIAL + PHI_DEPTH + 2)
        self.check(deep_join_function, mutate, 'arg_differs')

    def test_register_written_before_the_return(self):
        """A register the bytecode leaves alone written before the return: the caller can read it after the call"""
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions.insert(index, MLILStoreReg(REG_INDEX, MLILConst(1)))
        self.check(calls_function, mutate, 'return_differs')

    def test_value_held_across_an_unrelated_call_changed(self):
        """v's initial value changed: read after a call that is given no pointer to v, which a later call is"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(unrelated_call_function, mutate, 'arg_differs')

    def test_read_after_a_call_that_reaches_it_through_a_global_made_stale(self):
        """GLOBAL_B = v after the call read as v's value before it: the call can write v through GLOBAL_A"""
        def mutate(mlil):
            store = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal) and inst.index == GLOBAL_B)[2]
            store.value = MLILConst(OUT_INITIAL)
        self.check(escaped_address_function, mutate, 'arg_differs')

    def test_value_behind_a_pointer_to_a_pointer_changed(self):
        """v's initial value changed before callee(&q), q = &v: the callee can read v through q"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(pointer_to_pointer_function, mutate, 'arg_differs')

    def test_register_one_arm_leaves_changed(self):
        """The arm's write changed; the other arm's incoming value compares clean (both layers leave it)"""
        def mutate(mlil):
            write = first(mlil, lambda inst: isinstance(inst, MLILStoreReg) and isinstance(inst.value, MLILConst)
                          and inst.value.value == REG_OUT)[2]
            write.value = MLILConst(REG_OUT + 1)
        self.check(one_arm_register_function, mutate, 'return_differs')

    def test_call_hoisted_out_of_an_endless_tail(self):
        """The outer arm's second call moved before the branch: it now runs on both arms"""
        def mutate(mlil):
            block, index, inst = [entry for entry in statements(mlil) if is_call(entry[2])][-1]
            del block.instructions[index]
            mlil.basic_blocks[0].instructions.insert(0, inst)
        self.check(endless_tail_function, mutate, 'guard_differs', ENDLESS_TAIL_PARAMETERS)

    def test_loop_update_changed(self):
        """i = i + 1 made i = i + 3: the value after the loop is the same leaf, the value carried round differs; also
        where only the loop's condition reads it, or only the return's registers"""
        def mutate(mlil):
            block, index, update = first(mlil, lambda inst: isinstance(inst, MLILSetVar)
                                         and isinstance(inst.value, MLILAdd))
            block.instructions[index] = MLILSetVar(update.var, MLILAdd(update.value.lhs, MLILConst(3))) \
                .copy_metadata_from(update)
        for build in (loop_function, counter_loop_function, register_loop_function):
            with self.subTest(build.__name__):
                self.check(build, mutate, 'loop_value_differs')

    def test_register_restored_after_a_call_on_one_arm(self):
        """The arm with the call reads the register after it; the other writes it, so the join merges the two"""
        self.check(saved_register_function, restore_register_after_the_call, 'arg_differs')

    def test_register_restored_in_a_loop_after_a_call(self):
        """The value carried round the loop is the register's after the call, which the loop entered written"""
        self.check(saved_register_loop_function, restore_register_after_the_call, 'loop_value_differs')

    def test_unwritten_register_restored_after_an_optional_call(self):
        """No arm writes the register: the join merges the arm reading it after the call with the one reading it as it
        came in"""
        self.check(unwritten_register_function, restore_register_after_the_call, 'arg_differs')

    def test_tail_call(self):
        """The tail call compares clean with MLIL's script call and return; the call's result not returned differs"""
        def mutate(mlil):
            block, index, ret = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions[index] = MLILRet(MLILConst(0)).copy_metadata_from(ret)
        self.check(tail_call_function, mutate, 'return_differs')

    def test_ordering_inverted(self):
        """(i < LIMIT) == 0 written i >= LIMIT: equal but for NaN, its own category; a call inside the loop runs under
        the inverted branch, its arm read against the condition's representative core, so it is no guard difference"""
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            negated = next(node for node in walk(branch.condition) if isinstance(node, MLILEq)
                           and isinstance(node.rhs, MLILConst) and node.rhs.value == 0)
            ordering = negated.lhs
            self.assertIsInstance(ordering, MLILLt)
            block.instructions[index] = MLILIf(MLILGe(ordering.lhs, ordering.rhs), branch.true_target,
                                               branch.false_target).copy_metadata_from(branch)
        for build in (loop_function, loop_call_function):
            with self.subTest(function=build.__name__):
                reference, mlil = reference_and_mlil(build)
                mutate(mlil)
                self.assertEqual(categories(reference, mlil), {'condition_ordering_inverted'})

    def test_sibling_read_from_the_other_scope(self):
        """The joined slot's two writes named apart as sibling scopes, the read given one arm's name (an arbitrary push
        picked at a join): the other arm's value never reaches it"""
        def mutate(mlil):
            (then_write, else_write), read = joined_slot_writes_and_read(mlil)
            local = then_write[2].var
            write_as(then_write, sibling(local, 1))
            write_as(else_write, sibling(local, 0))
            replace_reads(mlil, local, sibling(local, 0), read)
        self.check(joined_slot_function, mutate, 'arg_differs')

    def test_address_taken_sibling_value_changed(self):
        """Two out-parameter locals named apart in one slot, the second's stored value changed: the call passed its
        address reaches it, with the changed value"""
        def mutate(mlil):
            second = out_parameters_named_apart(mlil)[1]
            second.value = MLILConst(UNRELATED_ARG)
        self.check(sibling_out_parameters_function, mutate, 'arg_differs')

    def test_call_result_never_captured(self):
        """The result's store after the call dropped, the result read after the join as the register: no MLIL write
        puts the result there, so a printed REGS[0] would be stale"""
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILStoreReg)
                                    and inst.index == VMEffects.RESULT_REGISTER)
            del block.instructions[index]
        self.check(optional_call_result_function, mutate, 'arg_differs')


class TestTranslatorShapes(unittest.TestCase):
    """MLIL in shapes the symbolic-stack translator gives (IR rewrite part 2), planted in the SSA path's MLIL: the check
    reads them as the LLIL's storage"""

    @classmethod
    def reference_and_ssa_mlil(cls, build) -> tuple:
        return reference_and_mlil(build, convert=lambda llil: convert_falcom_llil_to_mlil_ssa(llil, infer_types=False))

    def test_sibling_scopes_named_apart(self):
        """The joined slot's writes and read all named as one sibling scope's local: storage of its own, read where it
        was written"""
        reference, mlil = self.reference_and_ssa_mlil(joined_slot_function)
        writes, read = joined_slot_writes_and_read(mlil)
        local = writes[0][2].var
        for write in writes:
            write_as(write, sibling(local, 1))
        replace_reads(mlil, local, sibling(local, 1), read)
        self.assertEqual(categories(reference, mlil), set())

    def test_address_taken_siblings_in_one_slot(self):
        """Two out-parameter locals named apart in one slot: one neutral key, two addresses, so each call reaches the
        local it was passed, not both"""
        reference, mlil = self.reference_and_ssa_mlil(sibling_out_parameters_function)
        out_parameters_named_apart(mlil)
        self.assertEqual(categories(reference, mlil), set())

    def test_register_stored_before_a_loop_at_the_start(self):
        """The entry block's register write as a register store, not the SSA path's register variable: the block still
        only copies, so the loop's entry edge is named as the LLIL names it"""
        reference, mlil = self.reference_and_ssa_mlil(register_before_loop_function)
        registers = list(mlil.register_vars.values())
        block, index, inst = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and inst.var in registers)
        block.instructions[index] = MLILStoreReg(REG_INDEX, inst.value).copy_metadata_from(inst)
        self.assertEqual(categories(reference, mlil), set())


class TestEffectValues(unittest.TestCase):
    """An effect's values compared LLIL against MLIL (compare.value_differences): a difference for each argument or
    storage key that differs, the arguments left out where the two pass different counts"""

    ADDRESS = 0x10
    KEY     = (ADDRESS, 'call')

    @classmethod
    def differences(cls, expected: tuple, found: tuple) -> list:
        """The differences of one call passing expected on the reference and found on the checked side"""
        sides = [Facts(effects={cls.KEY: [Effect(cls.ADDRESS, 'call', CALLEE_ID, args)]}) for args in (expected, found)]
        return logic_check.compare_facts(*sides)

    def test_unequal_argument_counts(self):
        """The first argument dropped: the count differs, and the arguments left are not compared by index"""
        self.assertEqual(self.differences((const(1), const(2)), (const(2),)),
                         [logic_check.Difference('argc_differs', self.KEY, (2, 1))])

    def test_two_arguments_differing(self):
        self.assertEqual([(difference.category, difference.detail[0])
                          for difference in self.differences((const(1), const(2)), (const(3), const(4)))],
                         [('arg_differs', 0), ('arg_differs', 1)])


class TestRealScript(unittest.TestCase):
    """A real script with loops and branches: its LLIL and MLIL, and its MLIL and HLIL, compare clean in every
    function"""

    def test_btlsys(self):
        path = require(SORA2_SCRIPTS / 'battle' / 'btlsys.dat')
        results = logic_check.check_script(path, 'sora2')
        self.assertTrue(results)
        for result in results:
            with self.subTest(function=result.name):
                self.assertIsNone(result.internal_error)
                self.assertIsNone(result.decompile_error)
                self.assertEqual(result.mlil_differences, [])
                self.assertEqual(result.hlil_differences, [])


if __name__ == '__main__':
    unittest.main()
