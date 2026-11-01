# Falcom ED9 Decompiler Architecture

> Note on this revision: the previous version of this document included illustrative code samples
> for the opcode table, instruction dataclasses, disassembler, and lifter. Those samples used old
> or fictionalized APIs that no longer match the real implementation (e.g. the real lifter is
> `ED9VMLifter` under `falcom/ed9/ir/llil/`, not a `BytecodeLifter` class taking `func.bytecode`).
> They've been removed rather than left in place or replaced with unverified guesses — this
> document now describes responsibilities and points at real files/classes instead of showing code
> that may not match them.

## Overview

Layered architecture with two directions: **decompilation** (bytecode → readable output) and
**recompilation** (a Python DSL source file → bytecode). See `docs/llil/LLIL_DESIGN.md` for LLIL,
`docs/mlil/MLIL_DESIGN.md` / `docs/mlil/MLIL_GUIDE.md` for MLIL, `docs/hlil/HLIL_GUIDE.md` for HLIL, and `docs/dsl/LLIL_DSL.md` for the
recompilation pipeline in detail.

```
Decompilation:   SCP File → Parser → Disassembler → Lifter → LLIL → MLIL → HLIL → Codegen (TypeScript)

DSL extraction (optional — only needed to round-trip-check an existing script):
                 SCP File → Parser → Disassembler → LLIL DSL (.py)

Compilation (the actual recompilation direction — needs only a DSL file, not an SCP file):
                 LLIL DSL (.py) → exec() → ScpWriter → SCP bytecode
```

## Layer 1: Parser — Done

**Location:** `falcom/ed9/parser/`, and `falcom/ed9/structs/` for what it shares with the writer (the value and
header types, the string pool, the call debug records)

Reads the SCP file: the header, the function table with parameters and defaults, call-site debug records, global
variables and the string pool (`ScpParser`). While the disassembler decodes a function, the parser simulates the VM
stack to find each call's setup, and rejects code it cannot trust: overlapping instructions, a branch target inside an
instruction, code running into the string pool, a join whose edges disagree on stack height. The layout the writer
reproduces (table order, string pool, debug records) is checked by `tools/scp_roundtrip_validator.py`. Detail:
`docs/falcom/ed9/ED9_FORMAT.md`.

## Layer 2: Disassembler — Done

**Location:** `assembler/` (generic) + `falcom/ed9/disasm/` (Falcom-specific)

Decodes bytecode into instructions and basic blocks: the generic recursive descent disassembler (`assembler/`), driven
by the ED9 opcode table, which also gives each opcode's kind and stack effect (`stack_effects.py`). Detail:
`docs/falcom/ed9/ED9_FORMAT.md`.

## Layer 3: Lifter — Done

**Location:** `falcom/ed9/ir/llil/` (`ED9VMLifter` and related classes), building on `ir/llil/`
(generic LLIL infrastructure)

Lifts disassembled instructions to LLIL: manages virtual stack and register state, and resolves VM
semantics such as calls, branches, and CFG shape. It does **not** recover `if`/`else`, loops, or
switch structure — that recovery is entirely HLIL's job, several layers up. The LLIL `Function`
assigns every instruction a global `inst_index`; each MLIL statement records the one it comes from
as its `llil_index`. Which opcodes are binary and how many arguments a local `CALL` pops
come from the opcode table's kinds and stack effects. The stack model, slot lifetimes, call setups and
per-edge stack state are in `docs/llil/LLIL_DESIGN.md`.

## Layer 4: MLIL — Implemented

**Location:** `ir/mlil/` (generic) + `falcom/ed9/ir/mlil/` (Falcom-specific)

Erases the explicit operand stack — every temporary becomes a named variable — and exposes
control/data flow suitable for SSA and optimizer passes, while retaining Falcom-specific semantics
(syscall IDs, `CALL_SCRIPT` metadata). Includes a full SSA optimizer pipeline — construction/
deconstruction, critical-edge splitting, type inference, and further optimization passes
(constant/copy propagation, dead-code elimination; none computes a value the bytecode does not hold). Beside it, not
yet on the decompile path, the symbolic-stack translator (`convert_falcom_llil_to_mlil_stack`) gives non-SSA MLIL
straight from the LLIL's stack layout, registers as storage (IR rewrite part 2). See
`docs/mlil/MLIL_DESIGN.md` for the node model and pipeline shape, `docs/mlil/MLIL_GUIDE.md` for a practical
usage guide.

## Layer 5: HLIL — Implemented, active development

**Location:** `ir/hlil/` (generic) + `falcom/ed9/ir/hlil/hlil_converter.py` (Falcom-specific)

Recovers high-level structure from MLIL — `if`/`else`, `while`/`do-while`, `switch`,
`break`/`continue` — via structural analysis and a pipeline of cleanup passes (branch-order
normalization, loop recovery, dead-code elimination, and others). Substantially implemented with
real tests, but still the layer under the most active structural iteration — pass order, arm
ordering, and chain-flattening heuristics are expected to keep changing fastest here. See
`docs/hlil/HLIL_GUIDE.md` for the full breakdown.

## Codegen: TypeScript — Done

**Location:** `codegen/typescript.py`

Converts HLIL into readable TypeScript-flavored pseudocode: typed signatures, `GLOBALS`/`REGS`
arrays, and its own print-time peephole simplification.

Game-specific output, unlike `ir/`: it reads only HLIL, and nothing in `ir/` depends on it, so it may follow
the game's conventions ("Generic/Falcom Boundary" below).

## Recompilation Pipeline — Core mechanism implemented, extensions planned

**Location:** `falcom/ed9/writer/` (`scp_writer.py`, `scp_writer_opcode_handler.py`,
`scp_writer_helper.py`, `scp_writer_hooks.py`, `scp_writer_hook_registry.py`, `scp_compile_check.py`) and
`falcom/ed9/metadata/` (the common-function library, its generator `gen_common_library.py` and the fingerprints
in `fingerprint.py`), driven by each game's `scena2py.py` (`falcom/ed9/scena2py_base.py`), validated by
`tools/scp_roundtrip_validator.py`.

A `.py` source file — sequential calls to per-opcode functions, one per VM opcode — executed
against a `ScpWriter` to emit bytecode. Compilation itself only needs that `.py` file. The Parser
and Disassembler come into play when *generating* a `.py` file from an existing script (e.g. for a
round-trip check), and in the compile check, which parses and lifts the compiled bytes again so a
stack mistake fails the compile with the `.py` line that caused it (`ScpWriter.check_compiled`).
An automated byte-exact round-trip check exists and works; fidelity settings are opt-in rather
than default. A shared common-function library per game
(`falcom/ed9/games/<game>/metadata/common/`, generated from that game's scripts) is implemented and active by
default, so generated `.py` files import shared game functions instead of embedding full copies of
them. A `<stem>_hook.py` next to a script can replace or add functions and rewrite opcodes when it
compiles (`scp_writer_hooks.py`; `docs/dsl/HOOKS.md`). Compiling from MLIL/HLIL DSL forms instead of
just LLIL DSL is still future work, loosely sketched rather than fully designed. Full detail in `docs/dsl/LLIL_DSL.md`; not-yet-started extensions
(MLIL/HLIL DSL, mixed-IR-level compilation, knowledge-driven typing for common functions) are in
`docs/dsl/DSL_FUTURE_WORK.md`.

## Data Flow (Decompilation)

```
1. SCP File
   ↓
2. ScpParser.parse() (ScpParser.load() runs this and step 4)
   ↓
3. Function objects (with bytecode)
   ↓
4. ScpParser.disasm_all_functions() → Disassembler.disasm_function()
   ↓
5. Basic blocks of instructions
   ↓
6. Lifter (ED9VMLifter.lift_function) → LowLevelILFunction
   ↓
7. MLIL (convert_falcom_llil_to_mlil)
   ↓
8. HLIL (convert_falcom_mlil_to_hlil)
   ↓
9. TypeScript (generate_typescript)
```

## Generic/Falcom Boundary

`ir/`, `assembler/` and `dc3/` are meant to be generic, with game code under `falcom/`, and nothing generic imports
`falcom/`. `codegen/` is game output (user, 2026-10-02): it reads only HLIL and nothing in `ir/` depends on it, so
game knowledge there can't spread back into the IR. The opcode table (`falcom/ed9/disasm/`) holds no IR node classes:
it gives opcode kinds and stack effects, and the LLIL lifter maps them to nodes.

## Key Design Principles

1. **Separation of concerns:** Parser only cares about file format; Disassembler only cares about
   bytecode-to-instruction; Lifter only cares about instruction-to-LLIL; structural recovery
   (if/else, loops, switch) happens only at HLIL, not earlier.
2. **Testability:** each layer is independently testable, with clearly defined interfaces. The tests are
   grouped the same way under `tests/` (`docs/TESTS_GUIDE.md`).
3. **Extensibility:** opcode-table-driven design — new instructions only need a table entry.
4. **Type safety:** dataclasses, type annotations, explicit enum types throughout.

## Implementation Status

1. Done — Parser
2. Done — Disassembler
3. Done — Lifter / LLIL
4. Implemented — MLIL
5. Implemented, active development — HLIL
6. Done — Codegen (TypeScript)
7. Core mechanism implemented, fidelity opt-in — Recompilation: LLIL DSL round trip, common-function shared library (`docs/dsl/LLIL_DSL.md`)
8. Future work, loosely sketched — Recompilation: MLIL/HLIL DSL, mixed-IR-level compilation
   (`docs/dsl/DSL_FUTURE_WORK.md`)
