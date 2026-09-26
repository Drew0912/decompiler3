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
**recompilation** (a Python DSL source file → bytecode). See `docs/MLIL_DESIGN.md` /
`docs/MLIL_GUIDE.md` for MLIL, `docs/HLIL_GUIDE.md` for HLIL, and `docs/LLIL_DSL.md` for the
recompilation pipeline in detail.

```
Decompilation:   SCP File → Parser → Disassembler → Lifter → LLIL → MLIL → HLIL → Codegen (TypeScript)

DSL extraction (optional — only needed to round-trip-check an existing script):
                 SCP File → Parser → Disassembler → LLIL DSL (.py)

Compilation (the actual recompilation direction — needs only a DSL file, not an SCP file):
                 LLIL DSL (.py) → exec() → ScpWriter → SCP bytecode
```

## Layer 1: Parser — Done

**Location:** `falcom/ed9/parser/`

Parses the SCP file format; extracts functions, global variables, strings, and other metadata;
provides access to raw bytecode. Key components: `ScpParser` (main parser), `ScpHeader` (file
header), `Function` (function metadata), `GlobalVar` (global variables).

## Layer 2: Disassembler — Done

**Location:** `falcom/ed9/disasm/`

Converts bytecode into a readable instruction sequence, identifies basic block boundaries, and
parses operands. Instruction encoding/decoding is table-driven (an opcode table maps each opcode to
its mnemonic and operand format), so adding a new instruction is a table entry rather than new
parsing code.

While the disassembler decodes a function, `ScpParser` simulates the VM stack to find each call's
setup: the two pushes a `CALL` consumes (rewritten to `PUSH_CURRENT_FUNC_ID` / `PUSH_RET_ADDR`) and
the caller frame a `CALL_SCRIPT` consumes. Each call's return edge comes from the address it
encodes. The simulation records the stack on every CFG edge - branch, fall-through and block split
- and every edge into a block must carry the same stack height. Pushes that meet at one stack
position on a join form one group, and a call checks and rewrites every push in its setup groups.
A push that an ordinary consumer reads, discards or overwrites cannot also be a call setup. The
parser also rejects overlapping instructions, targets inside an instruction, and code that runs
into the string pool. The pool's start is known only from references (function names, and the
strings the decoded code references), so a string referenced only by undecoded dead code does not
bound it. See `tests/test_scp_stack_simulation.py`.

## Layer 3: Lifter — Done

**Location:** `falcom/ed9/ir/llil/` (`ED9VMLifter` and related classes), building on `ir/llil/`
(generic LLIL infrastructure)

Lifts disassembled instructions to LLIL: manages virtual stack and register state, and resolves VM
semantics such as calls, branches, and CFG shape. It does **not** recover `if`/`else`, loops, or
switch structure — that recovery is entirely HLIL's job, several layers up. The LLIL `Function`
assigns every instruction a global `inst_index`, queryable via `get_instruction_by_index()`,
`get_instruction_block_by_index()`, and `iter_instructions()`, which later MLIL/HLIL passes use for
data-flow analysis.

## Layer 4: MLIL — Implemented

**Location:** `ir/mlil/` (generic) + `falcom/ed9/ir/mlil/` (Falcom-specific)

Erases the explicit operand stack — every temporary becomes a named variable — and exposes
control/data flow suitable for SSA and optimizer passes, while retaining Falcom-specific semantics
(syscall IDs, `CALL_SCRIPT` metadata). Includes a full SSA optimizer pipeline — construction/
deconstruction, critical-edge splitting, type inference, and further optimization passes
(constant/copy propagation, dead-code elimination, register/global propagation). See
`docs/MLIL_DESIGN.md` for the node model and pipeline shape, `docs/MLIL_GUIDE.md` for a practical
usage guide.

## Layer 5: HLIL — Implemented, active development

**Location:** `ir/hlil/` (generic) + `falcom/ed9/ir/hlil/hlil_converter.py` (Falcom-specific)

Recovers high-level structure from MLIL — `if`/`else`, `while`/`do-while`, `switch`,
`break`/`continue` — via structural analysis and a pipeline of cleanup passes (branch-order
normalization, loop recovery, dead-code elimination, and others). Substantially implemented with
real tests, but still the layer under the most active structural iteration — pass order, arm
ordering, and chain-flattening heuristics are expected to keep changing fastest here. See
`docs/HLIL_GUIDE.md` for the full breakdown.

## Codegen: TypeScript — Done

**Location:** `codegen/typescript.py`

Converts HLIL into readable TypeScript-flavored pseudocode: typed signatures, `GLOBALS`/`REGS`
arrays, per-syscall wrapper functions, and its own print-time peephole simplification.

## Recompilation Pipeline — Core mechanism implemented, extensions planned

**Location:** `falcom/ed9/writer/` (`scp_writer.py`, `scp_writer_opcode_handler.py`,
`scp_writer_helper.py`, `scp_writer_gen_common_funcs.py`, `metadata/`), driven by
`falcom/ed9/scena2py.py`, validated by `tools/scp_roundtrip_validator.py`.

A `.py` source file — sequential calls to per-opcode functions, one per VM opcode — executed
against a `ScpWriter` to emit bytecode. Compilation itself only needs that `.py` file; it does not
involve the Parser or Disassembler, which only come into play when *generating* a `.py` file from
an existing script (e.g. for a round-trip check). An automated byte-exact round-trip check exists
and works; fidelity settings are opt-in rather than default. A shared common-function library
(`falcom/ed9/writer/metadata/common/`, generated from the corpus) is implemented and active by
default, so generated `.py` files import shared game functions instead of embedding full copies of
them. Compiling from MLIL/HLIL DSL forms instead of just LLIL DSL is still future work, loosely
sketched rather than fully designed. Full detail in `docs/LLIL_DSL.md`; not-yet-started extensions
(MLIL/HLIL DSL, mixed-IR-level compilation, knowledge-driven typing for common functions) are in
`docs/FUTURE_WORK.md`.

## Data Flow (Decompilation)

```
1. SCP File
   ↓
2. ScpParser.parse()
   ↓
3. Function objects (with bytecode)
   ↓
4. Disassembler.disassemble()
   ↓
5. Instruction list
   ↓
6. Lifter (ED9VMLifter) → LowLevelILFunction
   ↓
7. MLIL (translate_llil_to_mlil)
   ↓
8. HLIL (convert_falcom_mlil_to_hlil)
   ↓
9. TypeScript (generate_typescript)
```

## Key Design Principles

1. **Separation of concerns:** Parser only cares about file format; Disassembler only cares about
   bytecode-to-instruction; Lifter only cares about instruction-to-LLIL; structural recovery
   (if/else, loops, switch) happens only at HLIL, not earlier.
2. **Testability:** each layer is independently testable, with clearly defined interfaces.
3. **Extensibility:** opcode-table-driven design — new instructions only need a table entry.
4. **Type safety:** dataclasses, type annotations, explicit enum types throughout.

## Implementation Status

1. Done — Parser
2. Done — Disassembler
3. Done — Lifter / LLIL
4. Implemented — MLIL
5. Implemented, active development — HLIL
6. Done — Codegen (TypeScript)
7. Core mechanism implemented, fidelity opt-in — Recompilation: LLIL DSL round trip, common-function shared library (`docs/LLIL_DSL.md`)
8. Future work, loosely sketched — Recompilation: MLIL/HLIL DSL, mixed-IR-level compilation
   (`docs/FUTURE_WORK.md`)
