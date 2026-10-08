#!/usr/bin/env python3
'''Unit tests for the ED9 stack effects: the table's invariants (what a call's setup pushes, the call pops; a
slot-addressing opcode pops a fixed count); the agreement test - the parser's stack simulation, the lifter's builder and
the debug-record tracker change the stack as the opcode table says, take a call's arguments as it says, and reject a
value left on the stack exactly at the instructions it says exit; a local call's argument count through each walker's
lookup; the parser fed what decoding never gives it; and the table's lookup of an opcode without a row.'''

from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple
from unittest import mock
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from falcom.ed9.disasm import ED9_INSTRUCTION_TABLE, ED9Opcode, Instruction
from falcom.ed9.disasm.ed9_optable import ED9_OPCODE_TABLE
from falcom.ed9.disasm.instruction import SYNTHETIC_INSTRUCTION_SIZE
from falcom.ed9.disasm.stack_effects import STACK_EFFECTS, InstructionKind, StackEffect
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.vm_lifter import ED9LiftError
from falcom.ed9.parser.scp import OPCODE_SIZE, CallDebugInfoTracker, ScpDisassemblyError, ScpParser
from falcom.ed9.parser.types_parser import Function, FunctionParam
from falcom.ed9.parser.types_scp import ScpParamFlags, Value32
from ir.llil.llil import LowLevelILCall, LowLevelILSyscall, WORD_SIZE
from test_scp_stack_simulation import (
    CALLER_ID, CALLEE_ID, FLOAT_VALUE, FUNC_NAME, GLOBAL_INDEX, LEFT_VALUE, MODULE_NAME, REG_INDEX, RIGHT_VALUE,
    SYSCALL_FUNC, SYSCALL_SUBSYSTEM, Asm, Func, Program, main_function, returning_callee,
)


LINE = 1
BINARY_OPERATORS = (
    'add', 'sub', 'mul', 'div', 'mod', 'eq', 'ne', 'gt', 'ge', 'lt', 'le',
    'bitwise_and', 'bitwise_or', 'logical_and', 'logical_or',
)
UNARY_OPERATORS = ('neg', 'ez', 'not_')
CALL_KINDS = {InstructionKind.CALL, InstructionKind.CALL_SCRIPT, InstructionKind.TAIL_CALL, InstructionKind.SYSCALL}
TABLE_OPCODES = {ED9Opcode(entry.opcode) for entry in ED9_OPCODE_TABLE}
NEVER_SEEN = {
    'parser'    : {ED9Opcode.PUSH, ED9Opcode.PUSH_CURRENT_FUNC_ID, ED9Opcode.PUSH_RET_ADDR},    # decoded as PUSH_RAW etc.
    'lifter'    : {ED9Opcode.PUSH},
    'tracker'   : {ED9Opcode.PUSH},     # only the writer feeds a raw PUSH (test_call_records.TestWriterOnlyInputs)
}


def constants_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.push_raw(LEFT_VALUE); asm.push_int(LEFT_VALUE); asm.push_float(FLOAT_VALUE); asm.push_str(MODULE_NAME)
    asm.pop(4 * WORD_SIZE); asm.ret()                                   # the 4 constants
    return (main_function(asm),)


def slots_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.push_int(LEFT_VALUE)
    asm.load_stack(-WORD_SIZE)                                          # sp 1: slot 0
    asm.push_stack_offset(-2 * WORD_SIZE)                               # sp 2: slot 0
    asm.push_int(RIGHT_VALUE)
    asm.pop_to(-WORD_SIZE)                                              # sp 4, 3 after its pop: slot 2
    asm.pop(3 * WORD_SIZE); asm.ret()
    return (main_function(asm),)


def deref_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.load_stack_deref(-WORD_SIZE)                                    # through the parameter in slot 0
    asm.push_int(LEFT_VALUE)
    asm.pop_to_deref(-2 * WORD_SIZE)                                    # sp 3, 2 after its pop: slot 0
    asm.pop(2 * WORD_SIZE); asm.ret()                                   # the loaded value and the parameter
    return (Func(FUNC_NAME, 1, asm),)


def globals_and_registers_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.load_global(GLOBAL_INDEX); asm.set_global(GLOBAL_INDEX)
    asm.get_reg(REG_INDEX); asm.set_reg(REG_INDEX); asm.ret()
    return (main_function(asm),)


def operators_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.push_int(LEFT_VALUE)
    for operator in BINARY_OPERATORS:
        asm.push_int(RIGHT_VALUE); getattr(asm, operator)()

    for operator in UNARY_OPERATORS:
        getattr(asm, operator)()

    asm.pop(WORD_SIZE); asm.ret()
    return (main_function(asm),)


def branches_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.get_reg(REG_INDEX); asm.jz('else')
    asm.push_int(LEFT_VALUE); asm.set_reg(REG_INDEX)
    asm.label('else'); asm.get_reg(REG_INDEX); asm.jnz('end')
    asm.jmp('end')
    asm.label('end'); asm.ret()
    return (main_function(asm),)


def local_call_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.debug_set_lineno(LINE)                                          # the tracker records calls after line info
    asm.push_raw(CALLER_ID); asm.push_raw('return')
    asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE); asm.call(CALLEE_ID)
    asm.label('return'); asm.ret()
    return main_function(asm), returning_callee(argc = 2)                # the 2 values pushed


def script_call_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.debug_set_lineno(LINE)
    asm.frame('return'); asm.push_int(LEFT_VALUE); asm.call_script(1)  # the 1 value pushed
    asm.label('return'); asm.ret()
    return (main_function(asm),)


def tail_call_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.debug_set_lineno(LINE)
    asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE); asm.call_script_no_return(2)     # the 2 values pushed
    return (main_function(asm),)


def syscall_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.debug_set_lineno(LINE)
    asm.push_int(LEFT_VALUE); asm.push_int(RIGHT_VALUE)
    asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2)                     # the 2 values pushed
    asm.pop(2 * WORD_SIZE); asm.ret()                                   # its arguments, left on the stack
    return (main_function(asm),)


def debug_log_program() -> tuple[Func, ...]:
    asm = Asm()
    asm.push_str(MODULE_NAME); asm.push_int(LEFT_VALUE); asm.debug_log(2); asm.ret()      # logs the 2 values pushed
    return (main_function(asm),)


PROGRAMS = (
    constants_program, slots_program, deref_program, globals_and_registers_program, operators_program,
    branches_program, local_call_program, script_call_program, tail_call_program, syscall_program, debug_log_program,
)


class Step(NamedTuple):
    '''One instruction as a walker handled it'''
    opcode  : ED9Opcode
    values  : tuple                 # operand values
    offset  : int | None
    before  : int                   # stack depth before it
    after   : int                   # and after it
    argc    : int | None = None     # the arguments a call took, as the walker saw them


def effect_of(opcode: int) -> StackEffect:
    return ED9_INSTRUCTION_TABLE.get_descriptor(opcode).effect


def is_call(opcode: int) -> bool:
    return ED9_INSTRUCTION_TABLE.get_descriptor(opcode).kind in CALL_KINDS


def operand_values(inst) -> tuple:
    return tuple(operand.value for operand in inst.operands)


@contextmanager
def tracing_the_parser(steps: list[Step]):
    '''Records each decoded instruction's simulated stack depth and, for a call, its argument count. A wrapper, not a
    subclass: ScpParser is a StrictBase, which lets a subclass set only the attributes it annotates itself.'''
    decoded = ScpParser.on_instruction_decoded

    def on_instruction_decoded(parser, context, inst, block):
        opcode, values, before = ED9Opcode(inst.opcode), operand_values(inst), len(context.stack_simulation)
        argc = context.call_argc(inst) if is_call(opcode) else None
        targets = decoded(parser, context, inst, block)
        steps.append(Step(opcode, values, inst.offset, before, len(context.stack_simulation), argc))
        return targets

    with mock.patch.object(ScpParser, 'on_instruction_decoded', on_instruction_decoded):
        yield


class TracingLifter(ED9VMLifter):
    '''Records the builder's sp around each lifted instruction'''

    def __init__(self, *, parser: ScpParser):
        super().__init__(parser = parser)
        self.steps: list[Step] = []

    def _translate_instruction(self, builder, inst, block, block_map, llil_blocks):
        if inst.size == SYNTHETIC_INSTRUCTION_SIZE:         # a split block's fall-through JMP, not in the bytecode
            return super()._translate_instruction(builder, inst, block, block_map, llil_blocks)

        before = builder.sp_get()
        super()._translate_instruction(builder, inst, block, block_map, llil_blocks)
        self.steps.append(Step(ED9Opcode(inst.opcode), operand_values(inst), inst.offset, before, builder.sp_get()))


class TracingTracker(CallDebugInfoTracker):
    '''Records the tracked stack's depth around each opcode and the arguments of each call it records'''

    def __init__(self, get_param_count):
        super().__init__(get_param_count)
        self.steps: list[Step] = []

    def on_opcode(self, opcode, operands, payload = None):
        before, calls = len(self.stack), len(self.calls)
        super().on_opcode(opcode, operands, payload)
        argc = len(self.calls[-1].args) if len(self.calls) > calls else None
        self.steps.append(Step(ED9Opcode(opcode), tuple(operands), None, before, len(self.stack), argc))


def disassemble(functions: tuple[Func, ...], steps: list[Step]) -> tuple[ScpParser, list[Function]]:
    '''The parser's steps go to steps, also when it rejects the program'''
    parser = Program(*functions).parser()
    with tracing_the_parser(steps):
        return parser, parser.disasm_all_functions(quiet = True)


def lift(parser: ScpParser, decoded: list[Function]) -> list[Step]:
    '''Every function lifted; a call's argument count is its LLIL call node's'''
    steps, call_nodes = [], {}
    for func in decoded:
        lifter = TracingLifter(parser = parser)
        llil = lifter.lift_function(func)
        steps += lifter.steps
        for block in llil.basic_blocks:
            call_nodes.update((node.address, node) for node in block.instructions
                              if isinstance(node, (LowLevelILCall, LowLevelILSyscall)))

    return [step._replace(argc = len(call_nodes[step.offset].args)) if is_call(step.opcode) else step for step in steps]


def track(parser: ScpParser, decoded: list[Function]) -> list[Step]:
    '''Every function's decoded instructions fed in address order, as replay does (without the constants' payloads,
    which don't move the stack)'''
    steps = []
    for func in decoded:
        tracker = TracingTracker(parser.get_func_argc)
        for inst in parser.get_instructions(func):
            tracker.on_opcode(inst.opcode, list(operand_values(inst)))

        steps += tracker.steps

    return steps


def table_change(step: Step, parser: ScpParser) -> int:
    '''The stack change the table gives for step; a local call's arguments are its callee's declared parameters, from
    the function table every walker reads'''
    effect = effect_of(step.opcode)
    return effect.pushes - effect.pop_count(step.values, parser.get_func_argc) - effect.setup_pops


def table_argc(step: Step, parser: ScpParser) -> int:
    '''A call's arguments, popped or read in place'''
    effect = effect_of(step.opcode)
    return effect.pop_count(step.values, parser.get_func_argc) + effect.read_count(step.values)


class TableInvariantTests(unittest.TestCase):
    def test_local_call_pops_its_setup(self):
        setup_pushes = STACK_EFFECTS[InstructionKind.PUSH_FUNC_ID].pushes + STACK_EFFECTS[InstructionKind.PUSH_RET_ADDR].pushes
        self.assertEqual(STACK_EFFECTS[InstructionKind.CALL].setup_pops, setup_pushes)

    def test_script_call_pops_the_caller_frame(self):
        self.assertEqual(STACK_EFFECTS[InstructionKind.CALL_SCRIPT].setup_pops,
                         STACK_EFFECTS[InstructionKind.PUSH_CALLER_FRAME].pushes)

    def test_slot_addressing_kinds_pop_a_fixed_count(self):
        '''The parser counts their offset from sp after a fixed number of pops (addressed_slot)'''
        addressing = {kind: effect for kind, effect in STACK_EFFECTS.items() if effect.addresses_slot}
        self.assertTrue(addressing, 'no kind addresses a slot')
        for kind, effect in addressing.items():
            with self.subTest(kind = kind.name):
                self.assertIsInstance(effect.pops, int)


class TestLocalCallArgumentCount(unittest.TestCase):
    '''A local CALL pops its callee's declared parameters, which each walker looks up with its own function table'''
    DECLARED_PARAMS = 3

    def test_counted_with_the_walkers_lookup(self):
        params = {CALLEE_ID: self.DECLARED_PARAMS}
        self.assertEqual(STACK_EFFECTS[InstructionKind.CALL].pop_count([CALLEE_ID], params.__getitem__),
                         self.DECLARED_PARAMS)

    def test_without_a_lookup_it_raises(self):
        with self.assertRaises(ValueError) as caught:
            STACK_EFFECTS[InstructionKind.CALL].pop_count([CALLEE_ID])

        self.assertEqual(str(caught.exception),
                         "a local CALL pops its callee's parameter count, which needs the walker's lookup")


class TestParserInputsDecodingNeverGives(unittest.TestCase):
    '''The decoder hands the parser a typed push for every PUSH, and the setup pseudo-ops only come from the parser's own
    rewrite of a PUSH_RAW: fed anyway, a setup pseudo-op raises and a raw PUSH pushes its value, as the table says'''

    def setUp(self):
        asm = Asm()
        asm.ret()
        self.parser = Program(main_function(asm)).parser()
        self.context = self.parser.disasm_context(self.parser.functions[0], code_end = None)

    def decode(self, opcode: ED9Opcode) -> Instruction:
        inst = Instruction(offset = 0, opcode = opcode, descriptor = ED9_INSTRUCTION_TABLE.get_descriptor(opcode),
                           size = OPCODE_SIZE)
        self.parser.on_instruction_decoded(self.context, inst, None)
        return inst

    def test_setup_pseudo_ops_raise(self):
        for opcode, kind in ((ED9Opcode.PUSH_CURRENT_FUNC_ID, 'PUSH_FUNC_ID'), (ED9Opcode.PUSH_RET_ADDR, 'PUSH_RET_ADDR')):
            with self.subTest(opcode = opcode.name):
                with self.assertRaises(NotImplementedError) as caught:
                    self.decode(opcode)

                self.assertEqual(str(caught.exception), f'the parser never simulates {kind}')

    def test_raw_push_pushes_its_value(self):
        inst = self.decode(ED9Opcode.PUSH)
        self.assertEqual(len(self.context.stack_simulation), 1)
        self.assertIs(self.context.stack_simulation[0], inst)


class TestDescriptorLookup(unittest.TestCase):
    '''An opcode without a row: UNKNOWN_28's operand format is unknown, any other opcode is unknown itself; neither
    error is chained to anything'''

    def assert_unchained(self, error: Exception):
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)

    def test_unknown_28_is_not_implemented(self):
        with self.assertRaises(NotImplementedError) as caught:
            ED9_INSTRUCTION_TABLE.get_descriptor(ED9Opcode.UNKNOWN_28)

        self.assertEqual(str(caught.exception), f'opcode 0x{ED9Opcode.UNKNOWN_28:02X} decoded - never seen in a sample '
                                                'script, operand format unknown')
        self.assert_unchained(caught.exception)

    def test_an_opcode_without_a_row_is_unknown(self):
        opcode = max(ED9_INSTRUCTION_TABLE.descriptors) + 1
        with self.assertRaises(ValueError) as caught:
            ED9_INSTRUCTION_TABLE.get_descriptor(opcode)

        self.assertEqual(str(caught.exception), f'Unknown opcode: 0x{opcode:02X}')
        self.assert_unchained(caught.exception)


class TestWalkersAgreeWithTheTable(unittest.TestCase):
    '''Every program through the parser, the lifter and the tracker, each instruction checked against its effect'''

    @classmethod
    def setUpClass(cls):
        cls.runs = []           # (program, parser, {walker: steps})
        for program in PROGRAMS:
            parser_steps = []
            parser, decoded = disassemble(program(), parser_steps)
            steps = {'parser': parser_steps, 'lifter': lift(parser, decoded), 'tracker': track(parser, decoded)}
            cls.runs.append((program.__name__, parser, steps))

    def test_every_opcode_is_covered(self):
        for walker, never_seen in NEVER_SEEN.items():
            seen = {step.opcode for _, _, steps in self.runs for step in steps[walker]}
            self.assertEqual(seen, TABLE_OPCODES - never_seen, walker)

    def test_each_instruction_changes_the_stack_as_the_table_says(self):
        for program, parser, walkers in self.runs:
            for walker, steps in walkers.items():
                for step in steps:
                    with self.subTest(program = program, walker = walker, opcode = step.opcode.name):
                        expected = table_change(step, parser)
                        if walker == 'tracker':
                            # It starts each function empty, without the caller's parameters: a POP reaching into
                            # them pops only what it holds
                            expected = max(expected, -step.before)

                        self.assertEqual(step.after - step.before, expected)

    def test_each_call_takes_the_tables_argument_count(self):
        calls = 0
        for program, parser, walkers in self.runs:
            for walker, steps in walkers.items():
                for step in steps:
                    if not is_call(step.opcode):
                        continue

                    calls += 1
                    with self.subTest(program = program, walker = walker, opcode = step.opcode.name):
                        self.assertEqual(step.argc, table_argc(step, parser))

        self.assertGreater(calls, 0)

    def test_only_exiting_instructions_reject_a_value_left_below(self):
        '''Each program again with one more parameter than it pops - a value below everything else, so no offset moves.
        The parser and the builder must reject it at the first exiting instruction and nowhere before. The builder gets
        the clean disassembly with the parameter added: the parser would reject the program first.'''
        seen = {'parser': set(), 'lifter': set()}
        for program in PROGRAMS:
            functions = program()
            with self.subTest(program = program.__name__, walker = 'parser'):
                main, *others = functions
                steps = []
                with self.assertRaises(ScpDisassemblyError) as caught:
                    disassemble((main._replace(argc = main.argc + 1), *others), steps)

                seen['parser'] |= self.assert_rejected_at_an_exit(steps, caught.exception)

            with self.subTest(program = program.__name__, walker = 'lifter'):
                parser, decoded = disassemble(functions, [])
                main = next(func for func in decoded if func.name == FUNC_NAME)
                main.params = [FunctionParam(ScpParamFlags(Value32)), *main.params]
                lifter = TracingLifter(parser = parser)
                with self.assertRaises(ED9LiftError) as caught:
                    lifter.lift_function(main)

                seen['lifter'] |= self.assert_rejected_at_an_exit(lifter.steps, caught.exception)

        for walker, opcodes in seen.items():
            self.assertEqual(opcodes, TABLE_OPCODES - NEVER_SEEN[walker], walker)

    def assert_rejected_at_an_exit(self, steps: list[Step], error) -> set[ED9Opcode]:
        '''No instruction handled before the rejection exits; the rejecting one does. Returns the opcodes checked.'''
        rejecting = ED9Opcode[error.mnemonic]
        self.assertEqual([step.opcode.name for step in steps if effect_of(step.opcode).exits], [], str(error))
        self.assertTrue(effect_of(rejecting).exits, str(error))
        return {step.opcode for step in steps} | {rejecting}


if __name__ == '__main__':
    unittest.main()
