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
| `mlil_tests/` | the decompile path's MLIL: the stack translator and its passes, the nodes, builder and formatter (`ir/mlil/`, `falcom/ed9/ir/mlil/`) |
| `mlil_ssa_tests/` | the SSA path, kept and never called: its LLIL->MLIL translator, MLIL SSA and the optimizer passes (`ir/mlil_ssa/`, `falcom/ed9/ir/mlil_ssa/`); no test outside this folder reads them |
| `hlil_tests/` | MLIL->HLIL structuring and the HLIL passes (`ir/hlil/`, `falcom/ed9/ir/hlil/`) |
| `parser_tests/` | reading a `.dat` (`falcom/ed9/parser/`, `falcom/ed9/structs/`, `falcom/ed9/disasm/`, `assembler/`): stack simulation, string pool, call records, listings, the opcode table's stack effects, and the `.py` text scp2py writes; reading and rebuilding a `.tbl` (`falcom/ed9/parser/tbl.py`) |
| `writer_tests/` | `ScpWriter` (`falcom/ed9/writer/`): compiling the LLIL DSL, hooks, the compile check |
| `common_functions_tests/` | the shared common-function library (`falcom/ed9/tools/`, `falcom/ed9/structs/`): fingerprints, matching, what a script imports, and its generator (the facts, rendering, the closure and input checks) |
| `tools_tests/` | the scripts in `tools/`: the validators, the logic check, the line-order report |
| `dc3_tests/` | `dc3/`: logging, file I/O, the GC policy |
| `codegen_tests/` | the TypeScript code generator (`codegen/`) |
| `ir_core_tests/` | the `ir/core` values every layer shares: `is_int_zero`, `SourceFloat`, `reverse_post_order` |
| `shared/` | helpers for the tests above; no tests |

## Shared helpers

Import them as `from tests.shared.<module> import ...`. A test never imports another test file: code that two files
need goes in `tests/shared/`.

| Module | Gives |
|---|---|
| `corpus.py` | `SORA2_SCRIPTS`, sora2's scripts folder `falcom/ed9/games/sora2/extracted/script_en` (a script is `SORA2_SCRIPTS / 'ai/x.dat'`), `require(path)` for the corpus skip and `require_library(game)` for the library skip (below) |
| `llil_utils.py` | `make_builder(num_params)`: a `FalcomVMBuilder` with one function and its entry block open; `lift_asm(asm)`: `scp_asm` bytecode disassembled and lifted; `instructions_of(func, kind)`; `build_function_with_deref` and `build_call_function`: small LLIL functions; `llil_instructions(llil)`, and `ProvenanceTestCase`, whose `check_contract(mlil, llil)` checks each statement against the LLIL it names |
| `ir_utils.py` | `connect(func)`: an MLIL function's edges from its blocks' last instructions; `concrete_subclasses(base)`; `c()`, `expression_fields(node)` and `replaced(value, replacements)` for a walker's coverage tests; `set_metadata` and `with_metadata` (the `SOURCE_*` values) stamp an instruction's source, and `MetadataTestCase`'s `assert_metadata` reads it back |
| `hlil_cfg_utils.py` | `build_function` and `structure`: small MLIL CFGs from a block spec, and their HLIL; `classify` and `hlil_run`: an oracle that runs MLIL and HLIL side by side |
| `scp_asm.py` | `Asm` and `Program`: hand-written ED9 bytecode for a real `ScpParser` |
| `scp_writer_test_utils.py` | `fresh_writer(dat)` (a clean `ScpWriter` for `dat`), `body_writer()` (one inside a function body, to emit opcodes one at a time), `WriterTestCase` (compiles `test.dat` in a temp folder), `load_module` (a hook or library file as a fresh module), `marked_line`/`location`/`at` for `file:line` messages, and `HEX`, an address in a writer message as a regex |
| `logic_check_functions.py` | the logic check's test files' shared assembled functions (`calls_function`, `branch_function`, ...) and pairs: `reference_and_mlil` (a function's LLIL facts and the decompile path's MLIL), `mlil_and_hlil`, and `categories` / `hlil_categories`, what each pair's comparison reports; it imports `logic_check`, so the test puts `tools/` on `sys.path` first |
| `stack_translator_checks.py` | the stack translator's test files' checks: its invariants (`temporaries_misused`, `reads_before_definition`), `statements(mlil)`, `translated(llil)` (the translator's own pipeline, no shaping pass), and `StackTranslationTestCase`, whose `checked_translation(llil, convert=translated)` converts (the decompile path whole: `convert=convert_falcom_llil_to_mlil_stack`) after checking both pairs clean and both invariants; it imports `logic_check`, so the test puts `tools/` on `sys.path` first |
| `switch_chains.py` | dispatch chains as the compiler writes them, assembled: `SWITCH_SHAPES` and `IF_SHAPES`, and each path's checks: `hlil_and_differences(build, argc, convert)`, `switches(hlil)`, `case_labels(switch)`; it imports `logic_check`, so the test puts `tools/` on `sys.path` first |

## Corpus and generated files

- A test that reads a real script passes its path through `require(path)`, which skips the test when the file is
  missing (no `falcom/ed9/games/sora2/extracted/`).
- A few tests need sora2's generated common-function library (`falcom/ed9/games/sora2/metadata/common/`,
  `common_index.py`, `common_all.py`, all gitignored): they call `require_library('sora2')`, which skips the test
  without it and returns the index. Make it with
  `python falcom/ed9/tools/gen_common_library.py falcom/ed9/games/sora2/extracted/script_en` (it writes only into
  `falcom/ed9/games/sora2/metadata/`).

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
- A test that searches a whole HLIL, MLIL or LLIL subtree uses the shared walkers (named in `docs/hlil/HLIL_DESIGN.md`
  and `docs/mlil/MLIL_DESIGN.md`, "Operations & Node Types", and `docs/llil/LLIL_DESIGN.md`, "Node Model"), so it
  changes with them. A test that checks direct children
  or top-level statements on purpose may index them directly. A test of a walker takes its expected answer from
  reflection over every field (`vars(node)`), as the coverage tests' own helpers do (`held_nodes` in
  `tests/hlil_tests/test_hlil_traversal.py`, `expression_fields` in `tests/shared/ir_utils.py`), never
  from the walker under test.

## Moving tests or the corpus path

Gate the move on a diff of (test id, outcome) pairs before and after, never on a list of test names: a corpus path
that no longer resolves turns passes into skips under the same names (`require(path)`, above).
