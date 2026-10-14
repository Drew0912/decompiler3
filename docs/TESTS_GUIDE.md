# Tests Guide

> Status: current. Written 2026-10-09 with the split of `tests/` into one folder per part of the decompiler. Plain
> `unittest`, standard library only.

## Running

From the repo root. No `PYTHONPATH` is needed: every test file puts the repo root on `sys.path` itself.

- Everything: `python -m unittest discover -s tests`. Always pass `-s tests`: a bare `python -m unittest` walks every
  package and fails on the unused `falcom.ed9.signatures` package's `yaml` import.
- One folder: `python -m unittest discover -s tests/hlil_tests`
- One file: `python -m unittest tests.hlil_tests.test_hlil_traversal`, or
  `python tests/hlil_tests/test_hlil_traversal.py`
- One class or test: `python -m unittest tests.hlil_tests.test_hlil_traversal.TestChildrenCoverEveryNode`

## Layout

A test sits in the folder of the code it tests. Each folder is named after that code with a `_tests` suffix.

| Folder | Tests of |
|---|---|
| `llil_tests/` | the LLIL builder and the ED9 lifter (`ir/llil/`, `falcom/ed9/ir/llil/`), and what they hand to MLIL |
| `mlil_tests/` | the LLIL->MLIL translator, MLIL SSA and the optimizer passes (`ir/mlil/`, `falcom/ed9/ir/mlil/`) |
| `hlil_tests/` | MLIL->HLIL structuring and the HLIL passes (`ir/hlil/`, `falcom/ed9/ir/hlil/`) |
| `parser_tests/` | reading a `.dat` (`falcom/ed9/parser/`, `falcom/ed9/disasm/`): stack simulation, string pool, call records, listings, the opcode table's stack effects, and the `.py` text scena2py writes |
| `writer_tests/` | `ScpWriter` (`falcom/ed9/writer/`): compiling the LLIL DSL, hooks, the compile check |
| `common_functions_tests/` | the shared common-function library (`falcom/ed9/metadata/`): fingerprints, matching, what a script imports, and its generator (the facts, rendering, the closure and input checks) |
| `tools_tests/` | the scripts in `tools/`: the validators, the line-order report, the HLIL path check |
| `dc3_tests/` | `dc3/`: logging, file I/O, the GC policy |
| `codegen_tests/` | the TypeScript code generator (`codegen/`) |
| `ir_core_tests/` | the `ir/core` values every layer shares: `is_int_zero`, `SourceFloat` |
| `shared/` | helpers for the tests above; no tests |

## Shared helpers

Import them as `from tests.shared.<module> import ...`. A test never imports another test file: code that two files
need goes in `tests/shared/`.

| Module | Gives |
|---|---|
| `corpus.py` | `SORA2_SCRIPTS`, the `sora2_1.0` scripts folder (a script is `SORA2_SCRIPTS / 'ai/x.dat'`), and `require(path)` for the corpus skip (below) |
| `llil_utils.py` | `make_builder(num_params)`: a `FalcomVMBuilder` with one function and its entry block open; `lift_asm(asm)`: `scp_asm` bytecode disassembled and lifted; `instructions_of(func, kind)` |
| `ir_utils.py` | `connect(func)`: an MLIL function's edges from its blocks' last instructions; `concrete_subclasses(base)` |
| `hlil_cfg_utils.py` | `build_function` and `structure`: small MLIL CFGs from a block spec, and their HLIL; `classify` and `hlil_run`: an oracle that runs MLIL and HLIL side by side |
| `scp_asm.py` | `Asm` and `Program`: hand-written ED9 bytecode for a real `ScpParser` |
| `scp_writer_test_utils.py` | `fresh_writer(dat)` (a clean `ScpWriter` for `dat`), `body_writer()` (one inside a function body, to emit opcodes one at a time), `WriterTestCase` (compiles `test.dat` in a temp folder), `load_module` (a hook or library file as a fresh module), `marked_line`/`location`/`at` for `file:line` messages, and `HEX`, an address in a writer message as a regex |

## Corpus and generated files

- A test that reads a real script passes its path through `require(path)`, which skips the test when the file is
  missing (no `sora2_1.0/`).
- A few tests need the generated common-function library (`falcom/ed9/metadata/common/`, gitignored); without it they
  fail (one class skips). Make it with `python falcom/ed9/metadata/gen_common_library.py sora2_1.0/script_en`. It
  also rewrites the tracked `falcom/ed9/metadata/common_index.py` and `common_all.py`, so run it on
  `sora2_1.0/script_en` only.

## Adding tests

- Set the file up like its neighbours:

  ```python
  REPO_ROOT = Path(__file__).resolve().parents[2]
  sys.path.insert(0, str(REPO_ROOT))

  ...

  if __name__ == '__main__':
      unittest.main()
  ```

  Without the last two lines, `python tests/<folder>/<file>.py` runs nothing and still exits cleanly. A test that
  imports a `tools/` script also adds `sys.path.insert(0, str(REPO_ROOT / 'tools'))` and imports the script by its
  plain module name.
- A new folder needs an empty `__init__.py`; without one, `unittest` discovery skips it without an error.
