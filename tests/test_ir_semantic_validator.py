#!/usr/bin/env python3
'''Unit tests for tools/ir_semantic_validator.py: HLIL global/register operands, do-while flattening,
missing_write_anchor detection for dropped global writes, and layer-tagged provenance keys'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from ir.hlil import (
    HighLevelILFunction,
    HLILAssign,
    HLILCall,
    HLILConst,
    HLILDoWhile,
    HLILBlock,
    HLILExprStmt,
    HLILExternCall,
    HLILVar,
    HLILVariable,
    VariableKind,
)
from ir.llil import LowLevelILConst
from ir.mlil import (
    MLILAddressOf,
    MLILCall,
    MLILConst,
    MLILLoadGlobal,
    MLILStoreDeref,
    MLILStoreGlobal,
    MLILVar,
    MLILVariable,
)
from falcom.ed9.ir.llil.llil_ext import LowLevelILGlobalStore
from ir_semantic_validator import (
    EFFECT_CATEGORY_CALL,
    EFFECT_CATEGORY_WRITE_GLOBAL,
    IRLayer,
    SemanticOperand,
    _extract_hard_fail_category,
    _match_atoms_provenance_first,
    _extract_hlil_operands,
    build_cfg_from_hlil,
    normalize_hlil_operation,
    normalize_llil_operation,
    normalize_mlil_operation,
    semantic_op_to_effect_event,
    semantic_operation_to_atom,
    validate_hard_fail_semantics,
)

GLOBAL_INDEX = 5
REG_INDEX = 0
STORED_VALUE = 7
MISSING_WRITE_ANCHOR = 'missing_write_anchor'
LLIL_INDEX = 3
CALL_TARGET = 'get_value'
MLIL_INDEX = 8


def hlil_global_var() -> HLILVariable:
    return HLILVariable(kind = VariableKind.GLOBAL, index = GLOBAL_INDEX)


def hlil_global_store_op():
    return normalize_hlil_operation(HLILAssign(HLILVar(hlil_global_var()), HLILConst(STORED_VALUE)))


def mlil_global_store_op(llil_index: int = -1, inst_index: int = -1):
    store = MLILStoreGlobal(GLOBAL_INDEX, MLILConst(STORED_VALUE))
    store.llil_index = llil_index
    store.inst_index = inst_index
    return normalize_mlil_operation(store)


def llil_global_store_op(inst_index: int = -1):
    store = LowLevelILGlobalStore(GLOBAL_INDEX, LowLevelILConst(STORED_VALUE))
    store.inst_index = inst_index
    return normalize_llil_operation(store)


def hard_fail_categories(source_ops, target_ops, source_layer, target_layer) -> list[str]:
    violations = validate_hard_fail_semantics(source_ops, target_ops, source_layer, target_layer)
    return [_extract_hard_fail_category(violation.explanation) for violation in violations]


class TestHLILVariableOperands(unittest.TestCase):
    '''HLIL globals and registers have no name - they must normalize by kind and slot index'''

    def test_global_read_is_global_operand(self):
        operands = _extract_hlil_operands(HLILVar(hlil_global_var()))
        self.assertIn(SemanticOperand(kind = 'global', value = f'GLOBALS[{GLOBAL_INDEX}]'), operands)

    def test_register_read_is_register_operand(self):
        reg_var = HLILVariable(kind = VariableKind.REG, index = REG_INDEX)
        operands = _extract_hlil_operands(HLILVar(reg_var))
        self.assertIn(SemanticOperand(kind = 'reg', value = f'REGS[{REG_INDEX}]'), operands)

    def test_local_read_keeps_its_name(self):
        operands = _extract_hlil_operands(HLILVar(HLILVariable('var_s0')))
        self.assertIn(SemanticOperand(kind = 'var', value = 'var_s0'), operands)

    def test_global_assignment_is_global_write_event(self):
        event = semantic_op_to_effect_event(hlil_global_store_op())
        self.assertIsNotNone(event)
        self.assertEqual(event.category, EFFECT_CATEGORY_WRITE_GLOBAL)
        self.assertEqual(event.target_key, f'GLOBALS[{GLOBAL_INDEX}]')


class TestGlobalWriteAnchors(unittest.TestCase):
    def test_intact_global_write_matches_mlil_to_hlil(self):
        categories = hard_fail_categories(
            [mlil_global_store_op()], [hlil_global_store_op()], IRLayer.MLIL, IRLayer.HLIL,
        )
        self.assertEqual(categories, [])

    def test_global_write_dropped_in_hlil_is_missing(self):
        categories = hard_fail_categories([mlil_global_store_op()], [], IRLayer.MLIL, IRLayer.HLIL)
        self.assertEqual(categories, [MISSING_WRITE_ANCHOR])

    def test_intact_global_write_matches_llil_to_mlil(self):
        categories = hard_fail_categories(
            [llil_global_store_op()], [mlil_global_store_op()], IRLayer.LLIL, IRLayer.MLIL,
        )
        self.assertEqual(categories, [])

    def test_global_write_dropped_in_mlil_is_missing(self):
        categories = hard_fail_categories([llil_global_store_op()], [], IRLayer.LLIL, IRLayer.MLIL)
        self.assertEqual(categories, [MISSING_WRITE_ANCHOR])


class TestGlobalAssignedCallResult(unittest.TestCase):
    '''`GLOBALS[n] = f()` both calls f and writes the global - the call runs first'''

    def build_events(self, call) -> list[tuple[str, str]]:
        func = HighLevelILFunction('f')
        func.add_statement(HLILAssign(HLILVar(hlil_global_var()), call))
        cfg = build_cfg_from_hlil(func)
        ops = [op for node_id in sorted(cfg.nodes) for op in cfg.nodes[node_id].operations]
        events = [semantic_op_to_effect_event(op) for op in ops]
        return [(event.category, event.target_key) for event in events if event is not None]

    def test_call_then_global_write(self):
        events = self.build_events(HLILCall('get_value', []))
        self.assertEqual(events, [
            (EFFECT_CATEGORY_CALL, 'var:get_value'),
            (EFFECT_CATEGORY_WRITE_GLOBAL, f'GLOBALS[{GLOBAL_INDEX}]'),
        ])

    def test_extern_call_then_global_write(self):
        events = self.build_events(HLILExternCall('module:get_value', []))
        self.assertEqual([category for category, _ in events], [EFFECT_CATEGORY_CALL, EFFECT_CATEGORY_WRITE_GLOBAL])

    def test_register_assigned_call_result_stays_one_call(self):
        func = HighLevelILFunction('f')
        reg_var = HLILVariable(kind = VariableKind.REG, index = REG_INDEX)
        func.add_statement(HLILAssign(HLILVar(reg_var), HLILCall('get_value', [])))
        cfg = build_cfg_from_hlil(func)
        operators = [op.operator for node in cfg.nodes.values() for op in node.operations]
        self.assertEqual(operators, ['CALL'])


class TestGlobalReadIsNotWrite(unittest.TestCase):
    '''A store whose value reads a global is not a global write'''

    def test_deref_store_of_global_read(self):
        local = MLILVariable('var_s2')
        store = MLILStoreDeref(MLILAddressOf(MLILVar(local)), MLILLoadGlobal(GLOBAL_INDEX))
        event = semantic_op_to_effect_event(normalize_mlil_operation(store))
        self.assertIsNone(event)


class TestDoWhileFlattening(unittest.TestCase):
    '''A do-while body runs before its condition, and both must reach the HLIL CFG'''

    def build_ops(self, condition) -> list[str]:
        func = HighLevelILFunction('f')
        body = HLILBlock([HLILExprStmt(HLILCall('body_call', []))])
        func.add_statement(HLILDoWhile(condition, body))
        cfg = build_cfg_from_hlil(func)
        return [
            (op.operator, op.operands[0].value if op.operands else None)
            for node_id in sorted(cfg.nodes)
            for op in cfg.nodes[node_id].operations
        ]

    def test_body_effects_come_before_condition(self):
        ops = self.build_ops(HLILVar(HLILVariable('var_s0')))
        self.assertEqual([operator for operator, _ in ops], ['CALL', 'DO_WHILE'])

    def test_condition_call_runs_after_body(self):
        ops = self.build_ops(HLILCall('cond_call', []))
        calls = [target for operator, target in ops if operator == 'CALL']
        self.assertEqual(calls, ['body_call', 'cond_call'])


class TestProvenanceKeys(unittest.TestCase):
    '''Provenance keys are tagged by layer: LLIL->MLIL matches on the LLIL index, MLIL->HLIL on the MLIL index,
    and equal numbers of different layers never match'''

    def provenance_match_count(self, source_op, target_op) -> int:
        source, target = semantic_operation_to_atom(source_op), semantic_operation_to_atom(target_op)
        _, provenance_matches, _ = _match_atoms_provenance_first([source], [target])
        return provenance_matches

    def test_mlil_operation_carries_both_layers(self):
        atom = semantic_operation_to_atom(mlil_global_store_op(LLIL_INDEX, MLIL_INDEX))
        self.assertEqual(atom.provenance_keys, [(IRLayer.LLIL.name, LLIL_INDEX), (IRLayer.MLIL.name, MLIL_INDEX)])

    def test_llil_to_mlil_matches_on_the_llil_index(self):
        source = llil_global_store_op(LLIL_INDEX)
        self.assertEqual(self.provenance_match_count(source, mlil_global_store_op(LLIL_INDEX, MLIL_INDEX)), 1)

    def test_equal_index_of_another_layer_does_not_match(self):
        source = llil_global_store_op(MLIL_INDEX)
        self.assertEqual(self.provenance_match_count(source, mlil_global_store_op(LLIL_INDEX, MLIL_INDEX)), 0)

    def test_mlil_to_hlil_matches_on_the_mlil_index(self):
        mlil_call = MLILCall(CALL_TARGET, [])
        mlil_call.llil_index = LLIL_INDEX
        mlil_call.inst_index = MLIL_INDEX
        hlil_call = HLILExprStmt(HLILCall(CALL_TARGET, []))
        hlil_call.mlil_index = MLIL_INDEX
        source, target = normalize_mlil_operation(mlil_call), normalize_hlil_operation(hlil_call)
        self.assertEqual(self.provenance_match_count(source, target), 1)


if __name__ == '__main__':
    unittest.main()
