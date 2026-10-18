# Docs Index

> Start here. Read this file, then only the docs for the part being worked on. Docs are the first stop, not ground
> truth: check a claim against the source before acting on it.

## Where to read

Work on one part goes straight to its row below. Read `docs/ARCHITECTURE.md` only when a task crosses layers or
languages, touches the generic / Falcom boundary, or the pipeline is not known yet.

| Path | Covers | Read for |
|---|---|---|
| `ARCHITECTURE.md` | the pipeline and its data flow, one summary per layer, the generic / Falcom boundary, status | cross-layer work, boundary questions, a first look |
| `ROUND_TRIP_POLICY.md` | what every change must keep: the logic round trip (required), byte-exact (medium), `round_trip` flags, every function stays | any change to the parser, the writer, an IR pass or an output |
| `HARDENING_POLICY.md` | which inputs deserve a test, a guard or a finding (threat model) | tests, guards, reviews, bug hunts |
| `TESTS_GUIDE.md` | running the tests, layout, shared helpers, the corpus skip, moving tests | test work |
| `VALIDATOR_GUIDE.md` | `tools/ir_semantic_validator.py` HARD_FAIL categories: known noise vs real signal | judging validator output |
| `FUTURE_WORK.md` | the index of future work, and the ideas that span folders | proposing or planning new work |
| `falcom/ed9/` | the ED9 script format: parser, disassembler, opcode table, per-game differences | `falcom/ed9/parser/`, `falcom/ed9/disasm/` |
| `llil/` | LLIL design | `ir/llil/`, `falcom/ed9/ir/llil/` |
| `mlil/` | MLIL design, guide, future work | `ir/mlil/`, `falcom/ed9/ir/mlil/` |
| `hlil/` | HLIL design, guide (with the TypeScript codegen), future work | `ir/hlil/`, `falcom/ed9/ir/hlil/`, `codegen/` |
| `dsl/` | the editing interface: the LLIL DSL and its writer, hooks, the planned HLIL DSL | `falcom/ed9/writer/`, `falcom/ed9/metadata/`, generated `.py` scripts, hook files |

## Running the decompiler

`python falcom/ed9/scena2py.py <file or folder>` decompiles `.dat` scripts (folders are searched recursively) with the
settings in `falcom/ed9/scena2py_config.py` (`ScenaDecompileConfig`: which outputs, the parser flags) into
`falcom/ed9/out/<stem>/`, or `<folder>/<stem>/` with `-o <folder>`. It runs the real pipeline, so it is the way to check
a decompile: write the outputs before a change, again after it, and diff them.

A test or verification run writes nothing inside the repo:
- `scena2py`: `python falcom/ed9/scena2py.py <file or folder> -o <scratch folder>`. A run that needs other settings
  (e.g. `round_trip = True`) uses a driver script in a scratch folder:

  ```python
  import sys
  from pathlib import Path
  sys.path.insert(0, r'<repo root>')
  from falcom.ed9.scena2py import process_file
  from falcom.ed9.scena2py_config import ScenaDecompileConfig

  config = ScenaDecompileConfig()
  config.output_dir = Path(r'<scratch folder>')
  process_file(Path(r'<script>.dat'), config)
  ```

- `tools/scp_roundtrip_validator.py --round-trip` / `--logic-round-trip`: `--work-dir <scratch folder>` (the default
  is a new temp folder); `tools/ir_semantic_validator.py --output-dir <scratch folder>` when it writes files.
- IR checks: `tools/ir_semantic_validator.py <dat> --export-regression <scratch folder>/before.json` before a change,
  `--compare-regression <scratch folder>/before.json` after; judge the output with `VALIDATOR_GUIDE.md`.
- A generated script writes its `.dat` to a relative name: run it from a scratch folder.
- Use absolute paths; afterwards `git status --ignored` shows nothing new (the outputs' file types and `out/` are
  gitignored, so plain `git status` cannot see them). It cannot see new files inside an already-ignored folder such as
  `falcom/ed9/out/`.
