#!/usr/bin/env python3
'''Unit test for the generated common-function library (scp_writer_gen_common_funcs.py): compiling a
label-heavy generated function twice in one process, each time on a fresh writer against the same
cached module, must fingerprint identically to the corpus canonical both times - proving genLabel()
names are allocated per execution, not baked in once at module import time.'''

import importlib
import inspect
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer import scp_writer
from falcom.ed9.writer.metadata import COMMON_LIBRARY_PACKAGE
from falcom.ed9.writer.metadata.common_index import COMMON_FUNCTIONS
from falcom.ed9.writer.metadata.signature import function_fingerprint, fingerprint_digest
from scp_writer_test_utils import fresh_writer

CHECK_SBREAK = 'CheckSBreak'  # forward and backward branches


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


class TestGeneratedLibraryFingerprintStable(unittest.TestCase):
    def test_check_sbreak_matches_canonical_across_two_independent_compiles(self):
        self.assertIn(CHECK_SBREAK, COMMON_FUNCTIONS, 'corpus canonical index has no CheckSBreak - did the generator run?')
        _module_key, expected_digest = COMMON_FUNCTIONS[CHECK_SBREAK]

        for attempt in (1, 2):
            digest = compile_and_fingerprint(CHECK_SBREAK)
            self.assertEqual(digest, expected_digest, f'attempt {attempt}: fingerprint diverged from the corpus canonical')


if __name__ == '__main__':
    unittest.main()
