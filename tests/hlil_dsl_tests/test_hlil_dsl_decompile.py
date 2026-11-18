#!/usr/bin/env python3
"""The HLIL DSL's decompile side on real sora2 scripts: with write_hlil_py on, <stem>.py holds each function whose DSL
text is exact as @scena.HLILCode() and the rest in the LLIL DSL, <stem>.llil.py is the LLIL listing, and the two
compile to the same game logic (the HLIL functions without their line markers); real functions' printed text"""

from itertools import pairwise
from pathlib import Path
from typing import Callable
import runpy
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from dc3.logging import log
from falcom.ed9.formatter.generated_imports import game_writer_helper_import, hlil_dsl_helper_import
from falcom.ed9.formatter.hlil_dsl.function_formatter import INDENT
from falcom.ed9.formatter.hlil_dsl.script_formatter import HLILScriptFormatter
from falcom.ed9.games.sora2.writer.scp_writer import Sora2ScpWriter
from falcom.ed9.ir.hlil.hlil_converter import convert_ed9_mlil_to_hlil
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_ed9_llil_to_mlil_stack
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.scp2py_base import process_file
from falcom.ed9.scp2py_config import ScpDecompileConfig
from falcom.ed9.structs.fingerprint import (body_fingerprint, body_fingerprint_without_line_markers,
                                            signature_fingerprint)
from tests.shared.corpus import SORA2_SCRIPTS, require, require_library
from tests.shared.scp_writer_test_utils import fresh_writer

GAME = 'sora2'


def compiled(path: Path) -> bytes:
    """path's .dat bytes, compiled on a fresh writer of the game's"""
    fresh_writer(writer_class=Sora2ScpWriter)
    namespace = runpy.run_path(str(path), run_name=path.stem)
    return namespace['scena'].build(namespace)


def fingerprints(data: bytes, keyed: Callable) -> dict[str, tuple]:
    """Each function's body fingerprint (keyed: body_fingerprint or body_fingerprint_without_line_markers) and its
    signature"""
    parser, functions = ScpParser.load_bytes(data, 'test.dat', round_trip=False, keep_unreachable_code=False,
                                             game=GAME, quiet=True)
    return {func.name: (keyed(func.reachable_instructions(), func.offset, parser.get_func_name_from_func_id,
                              parser.get_global_name_from_index), signature_fingerprint(func))
            for func in functions}


def printed(relative_path: str, name: str) -> list[str] | str:
    """The DSL lines of one function of a script, or the reason it stays LLIL"""
    path = require(SORA2_SCRIPTS / relative_path)
    parser, [func] = ScpParser.load(path, round_trip=False, keep_unreachable_code=False, game=GAME,
                                    filter_func=lambda f: f.name == name)
    dsl = HLILScriptFormatter(parser, {})
    llil = ED9VMLifter(parser=parser).lift_function(func)
    dsl.add(func, convert_ed9_mlil_to_hlil(convert_ed9_llil_to_mlil_stack(llil)))
    return dsl.lines.get(name) or dsl.reasons[name]


class TestMixedScript(unittest.TestCase):
    def test_the_mixed_file_and_the_listing_compile_to_one_dat(self):
        require_library(GAME)
        path = require(SORA2_SCRIPTS / 'obj' / 'brk_obj.dat')
        with tempfile.TemporaryDirectory() as folder:
            config = ScpDecompileConfig()
            config.output_dir = Path(folder)
            config.write_hlil_py = True
            config.write_ts = config.write_hlil_ts = config.write_mlil_asm = False
            with self.assertLogs(log, 'INFO'):
                process_file(path, config, game=GAME)

            mixed_path = Path(folder) / 'brk_obj' / 'brk_obj.py'
            listing_path = mixed_path.with_suffix('.llil.py')
            mixed = mixed_path.read_text(encoding='utf-8').splitlines()
            listing = listing_path.read_text(encoding='utf-8').splitlines()

            writer_import = mixed.index(game_writer_helper_import(GAME))
            self.assertEqual(mixed[writer_import + 1], hlil_dsl_helper_import(GAME))
            self.assertIn('    import brk_obj_hook', mixed)
            start = mixed.index('def AniSwitchOnWait():') - 1
            self.assertEqual(mixed[start:start + 7], [
                '@scena.HLILCode()',
                'def AniSwitchOnWait():',
                f"{INDENT}var_s0 = Local('var_s0')",
                f'{INDENT}map_obj_play_animeclip("", "switch_on", 0.0, 0, 0)',
                f'{INDENT}Let(var_s0, map_obj_get_animeclip_frame_length("", 0))',
                f'{INDENT}map_obj_set_animeclip_frame("", var_s0, 0)',
                f'{INDENT}Return()',
            ])
            self.assertEqual(mixed[mixed.index('def AniWait():') - 1], '@scena.LLILCode()')    # an if

            self.assertEqual(listing[0], '# The LLIL listing of brk_obj.dat: it compiles to the same game logic as '
                                         'brk_obj.py (line markers aside), without its hooks')
            self.assertNotIn(hlil_dsl_helper_import(GAME), listing)
            self.assertNotIn('    import brk_obj_hook', listing)
            self.assertNotIn('@scena.HLILCode()', listing)

            # The same game logic: the HLIL functions write no line markers, the LLIL ones the same bytes
            mixed_data, listing_data = compiled(mixed_path), compiled(listing_path)
            self.assertEqual(fingerprints(mixed_data, body_fingerprint_without_line_markers),
                             fingerprints(listing_data, body_fingerprint_without_line_markers))
            full_mixed = fingerprints(mixed_data, body_fingerprint)
            full_listing = fingerprints(listing_data, body_fingerprint)
            hlil_names = {definition.removeprefix('def ').partition('(')[0]
                          for line, definition in pairwise(mixed) if line == '@scena.HLILCode()'}
            self.assertIn('AniSwitchOnWait', hlil_names)
            for name in full_listing.keys() - hlil_names:
                self.assertEqual(full_mixed[name], full_listing[name], name)


class TestRealFunctions(unittest.TestCase):
    def test_floats_printed_short_and_calls(self):
        self.assertEqual(printed('ani/chr5001.dat', 'AniFall'), [
            '@scena.HLILCode()',
            'def AniFall(arg1: Nullable32 = 0.11, arg2: Nullable32 = 1.0, arg3: Nullable32 = 0):',
            f'{INDENT}Set(arg2, AdjustSpeed(arg2))',
            f'{INDENT}Set(arg1, AdjustBlend(arg1, 0.1))',
            f'{INDENT}Syscall(6, 35, 65534, 0, 0, 0, 0, 1529, 1417, 1418)',
            f'{INDENT}chr_play_animeclip(65534, "fall", arg1, 1, 0)',
            f'{INDENT}chr_set_animeclip_speed(65534, arg2, 0)',
            f'{INDENT}chr_wait_animeclip(65534, 0)',
            f'{INDENT}Return()',
        ])

    def test_a_global_and_a_literal_left_of_an_operator(self):
        self.assertEqual(printed('ani/chr0005.dat', 'GetCookCount'), [
            '@scena.HLILCode()',
            'def GetCookCount():',
            f'{INDENT}Set(this.cook_count, 1 - this.cook_count)',
            f'{INDENT}Return(this.cook_count)',
        ])


if __name__ == '__main__':
    unittest.main()
