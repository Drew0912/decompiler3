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
| `CODING_STYLE.md` | the house style: code, line endings, commit messages (imported by `CLAUDE.md`) | all code |
| `TESTS_GUIDE.md` | running the tests, layout, shared helpers, the corpus skip, moving tests | test work |
| `VALIDATOR_GUIDE.md` | `tools/ir_semantic_validator.py` (the logic check): its categories, the known findings, the regression workflow | judging validator output |
| `FUTURE_WORK.md` | the index of future work, and the ideas that span folders | proposing or planning new work |
| `falcom/ed9/` | the ED9 script format: parser, disassembler, opcode table, per-game differences (`ED9_FORMAT.md`); the VM's rules, from the game exe (`ED9_VM.md`); the `.tbl` game tables and how to add one (`TBL_FORMAT.md`) | `falcom/ed9/parser/`, `falcom/ed9/structs/`, `falcom/ed9/disasm/`, `assembler/`; what the VM does with a script; `parser/tbl.py`, `games/<game>/tbl/` |
| `llil/` | LLIL design | `ir/llil/`, `falcom/ed9/ir/llil/` |
| `mlil/` | MLIL design, guide, future work | `ir/mlil/`, `falcom/ed9/ir/mlil/` |
| `hlil/` | HLIL design, guide (with the TypeScript codegen), future work | `ir/hlil/`, `falcom/ed9/ir/hlil/`, `codegen/` |
| `dsl/` | the editing interface: the LLIL DSL and its writer, hooks, the planned HLIL DSL | `falcom/ed9/writer/`, `falcom/ed9/games/<game>/writer/`, `falcom/ed9/tools/`, generated `.py` scripts, hook files |

## Running the decompiler

Each game has its own launcher, as in decompiler2: `python falcom/ed9/games/<game>/scp2py.py <file or folder>`
decompiles that game's `.dat` scripts (folders are searched recursively; the game's own are in
`falcom/ed9/games/<game>/extracted/`) with the settings in `falcom/ed9/scp2py_config.py` (`ScpDecompileConfig`:
which outputs, the parser flags; one config for every game) into the game's `out/<stem>/`, or `<folder>/<stem>/` with
`-o <folder>`, matching common functions against the game's own library once it is generated (`dsl/LLIL_DSL.md` §3).
Every launcher runs the shared pipeline in `falcom/ed9/scp2py_base.py`, so it is the way to check a decompile: write
the outputs before a change, again after it, and diff them. Like the tests and generated scripts, the launchers and the
`tools/` and `demos/` scripts put the repo root on `sys.path` themselves: no `PYTHONPATH`.

`sora1` and `sora2` also have `falcom/ed9/games/<game>/tbl2py.py <file or folder>`, which reads `.tbl` tables into
Python `entries` lists in the game's `out/tbl/`, or `<folder>/` with `-o <folder>`. Running one of those scripts
writes its `.tbl` to the current folder. `python falcom/ed9/tools/gen_tables.py sora2` writes `sora2`'s character table
into its `metadata/`.

A test or verification run writes nothing inside the repo:
- `tbl2py`: `python falcom/ed9/games/<game>/tbl2py.py <file or folder> -o <scratch folder>`; run a generated table
  script from a scratch folder.
- `gen_tables`: `python falcom/ed9/tools/gen_tables.py sora2 -o <scratch file>`.
- `scp2py`: `python falcom/ed9/games/<game>/scp2py.py <file or folder> -o <scratch folder>`. A run that needs
  other settings (e.g. `round_trip = True`) uses a driver script in a scratch folder:

  ```python
  import sys
  from pathlib import Path
  sys.path.insert(0, r'<repo root>')
  from falcom.ed9.scp2py_base import process_file
  from falcom.ed9.scp2py_config import ScpDecompileConfig

  config = ScpDecompileConfig()
  config.output_dir = Path(r'<scratch folder>')
  process_file(Path(r'<script>.dat'), config, game='sora2')
  ```

- `tools/scp_roundtrip_validator.py --round-trip` / `--logic-round-trip`: `--work-dir <scratch folder>` (the default
  is a new temp folder), `--game <game>` to decompile with that game's library (without it none: every common
  function inline); `tools/ir_semantic_validator.py --output-dir <scratch folder>` when it writes files.
- IR checks: `tools/ir_semantic_validator.py <dat> --export-regression <scratch folder>/before.json` before a change,
  `--compare-regression <scratch folder>/before.json` after; judge the output with `VALIDATOR_GUIDE.md`.
- A generated script writes its `.dat` to a relative name: run it from a scratch folder.
- `demos/disasm_all.py` writes `<stem>.py` next to each input: run it on a scratch copy of the scripts.
- `demos/llil_demo.py` writes `cfg.dot` next to itself and imports through its `sys.path` line: run it from a scratch
  copy of the repo's tracked files (`git ls-files`, layout kept; or just `demos/llil_demo.py` with the packages it
  imports).
- Use absolute paths; afterwards `git status --ignored` shows nothing new (the outputs' file types and `out/` are
  gitignored, so plain `git status` cannot see them). It cannot see new files inside an already-ignored folder such as
  a game's `out/`.
