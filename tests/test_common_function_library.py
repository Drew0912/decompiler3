#!/usr/bin/env python3
'''Unit tests for the common-function library generator (scp_writer_gen_common_funcs.py) and the library it
generates. Generator: the facts that decide a function's inclusion and module, and a function rendered from
hand-built bytecode. Library: compiling a label-heavy generated function twice in one process, each time on a fresh
writer against the same cached module, must fingerprint identically to the corpus canonical both times - proving
genLabel() names are allocated per execution, not baked in once at module import time.'''

import importlib
import inspect
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.parser.types_parser import Function
from falcom.ed9.writer import scp_writer
from falcom.ed9.writer import scp_writer_gen_common_funcs as gen
from falcom.ed9.writer.metadata import COMMON_LIBRARY_PACKAGE
from falcom.ed9.writer.metadata.common_index import COMMON_FUNCTIONS
from falcom.ed9.writer.metadata.signature import function_fingerprint, fingerprint_digest
from ir.llil.llil import WORD_SIZE
from scp_writer_test_utils import fresh_writer
from test_scp_stack_simulation import (
    Asm, Func, Program, CALLEE_ID, CALLEE_NAME, CALLER_ID, FUNC_NAME, GLOBAL_INDEX, LEFT_VALUE, returning_callee,
)

CHECK_SBREAK = 'CheckSBreak'  # forward and backward branches
SUBSYSTEM = 5
SYSCALL_FUNC = 0
SYSCALL_ARGC = 0
OWN_MODULE = f'{gen.MODULE_PREFIX}{SUBSYSTEM}'


def disassemble(asm: Asm, argc: int = 0) -> tuple[ScpParser, dict[str, Function]]:
    '''FUNC_NAME assembled from asm, calling a callee that returns at once'''
    parser, functions = Program(Func(FUNC_NAME, argc, asm), returning_callee()).disassemble()
    return parser, {func.name: func for func in functions}


def defined_functions(module) -> list:
    '''Functions actually defined in module (not opcode primitives/genLabel/other common modules
    reaching it through the helper star-import or a cross-module "import ... as common_N")'''
    return [obj for obj in vars(module).values() if inspect.isfunction(obj) and obj.__module__ == module.__name__]


def compile_and_fingerprint(name: str) -> str:
    '''Registers every generated common function through one CommonImports() manifest - the
    generator already asserts every CALL target is included, so this always resolves - compiles to
    a throwaway .dat, then re-disassembles it and fingerprints the requested function.'''
    module_keys = sorted({module_key for module_key, _digest in COMMON_FUNCTIONS.values()})
    modules = [importlib.import_module(f'{COMMON_LIBRARY_PACKAGE}.{key}') for key in module_keys]
    functions = [func for module in modules for func in defined_functions(module)]

    with tempfile.TemporaryDirectory() as tmp:
        dat_path = Path(tmp) / 'test_output.dat'

        fresh_writer()
        writer = scp_writer.create_scp_writer(str(dat_path))

        @writer.CommonImports()
        def commonImports():
            return functions

        writer.run(globals())

        parser, disasm_functions = ScpParser.load(dat_path, round_trip = False, keep_unreachable_code = False)

        func = next(f for f in disasm_functions if f.name == name)
        return fingerprint_digest(function_fingerprint(parser, func))


class TestGenerator(unittest.TestCase):
    def test_facts_from_the_instructions(self):
        asm = Asm()
        asm.syscall(SUBSYSTEM, SYSCALL_FUNC, SYSCALL_ARGC); asm.syscall(SUBSYSTEM + 1, SYSCALL_FUNC, SYSCALL_ARGC)
        asm.load_global(GLOBAL_INDEX); asm.pop(WORD_SIZE)
        asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.call(CALLEE_ID); asm.label('return'); asm.ret()
        parser, functions = disassemble(asm)

        facts = {name: gen.function_facts(parser, parser.get_instructions(func)) for name, func in functions.items()}
        self.assertEqual(facts, {
            FUNC_NAME   : gen.FunctionFacts(touches_global = True, call_targets = {CALLEE_NAME}, subsystem = SUBSYSTEM),
            CALLEE_NAME : gen.FunctionFacts(touches_global = False, call_targets = set(), subsystem = None),
        })

    def render(self, callee_module: str) -> list[str]:
        asm = Asm()
        asm.load_stack(-WORD_SIZE); asm.jz('skip')
        asm.push_raw(CALLER_ID); asm.push_raw('return'); asm.call(CALLEE_ID); asm.label('return')
        asm.push_int(LEFT_VALUE); asm.pop(WORD_SIZE)
        asm.label('skip'); asm.pop(WORD_SIZE); asm.ret()
        parser, functions = disassemble(asm, argc = 1)

        func = functions[FUNC_NAME]
        digest = fingerprint_digest(function_fingerprint(parser, func))
        return gen.render_function(parser, func, Path('test.dat'), digest, {FUNC_NAME: OWN_MODULE, CALLEE_NAME: callee_module})

    def test_function_rendered_from_its_instructions(self):
        self.assertEqual(self.render(callee_module = OWN_MODULE), [
            f'def {FUNC_NAME}(arg1: Value32):',
            '    L0 = genLabel()',
            '    L1 = genLabel()',
            '    LOAD_STACK(-4)',
            '    POP_JMP_ZERO(L1)',
            '    PUSH_CURRENT_FUNC_ID()',
            '    PUSH_RET_ADDR(L0)',
            f'    CALL({CALLEE_NAME})',
            '    label(L0)',
            f'    PUSH_INT({LEFT_VALUE})',
            '    POP(4)',
            '    label(L1)',
            '    POP(4)',
            '    RETURN()',
        ])

    def test_callee_in_another_module_is_qualified(self):
        lines = self.render(callee_module = gen.NO_SYSCALL_MODULE)
        self.assertIn(f'    CALL({gen.module_alias(gen.NO_SYSCALL_MODULE)}.{CALLEE_NAME})', lines)


class TestGeneratedLibraryFingerprintStable(unittest.TestCase):
    def test_check_sbreak_matches_canonical_across_two_independent_compiles(self):
        self.assertIn(CHECK_SBREAK, COMMON_FUNCTIONS, 'corpus canonical index has no CheckSBreak - did the generator run?')
        _module_key, expected_digest = COMMON_FUNCTIONS[CHECK_SBREAK]

        for attempt in (1, 2):
            digest = compile_and_fingerprint(CHECK_SBREAK)
            self.assertEqual(digest, expected_digest, f'attempt {attempt}: fingerprint diverged from the corpus canonical')


if __name__ == '__main__':
    unittest.main()
