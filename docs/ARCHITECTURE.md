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
**recompilation** (a Python DSL source file → bytecode). See `docs/LLIL_DESIGN.md` for LLIL,
`docs/MLIL_DESIGN.md` / `docs/MLIL_GUIDE.md` for MLIL, `docs/HLIL_GUIDE.md` for HLIL, and `docs/LLIL_DSL.md` for the
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
header), `Function` (function metadata), `GlobalVar` (global variables). `string_pool.py` groups the
pool's strings by what references them, in pool order (code, function names, parameter defaults,
debug-only, global var names); the round-trip validator checks the pool with it. `call_records.py` compares a
call-site debug record with the record its call gets (content only: call type, callee, arguments), the calls coming
from `CallDebugInfoTracker.replay` in record order with their instruction offsets; `code_layout.py` gives the code
order, each function's byte range and the ranges no instruction covers. The validator's code, debug-record,
source-precondition and reachability checks use them.

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

Each disassembled function keeps the simulated stack as `Function.stack_layout` (`StackLayout`, for
the `.py` comments): the depth before every reachable real instruction (not the synthetic
fall-through jumps), and for each of the 5 opcodes that address a slot by offset (`LOAD_STACK`,
`LOAD_STACK_DEREF`, `PUSH_STACK_OFFSET`, `POP_TO`, `POP_TO_DEREF`) the absolute slot and what may
be in it - parameter `argN`, a local, a caller-frame slot or a call setup, or nothing (outside the
live stack). What a slot may hold is solved per block start over every recorded edge,
not from the join groups, which span the whole function: a value that reaches a slot only at a
later join doesn't count for an earlier read. A `POP_TO` stands for the value it overwrote, so a
reassigned parameter is still the parameter. `STACK_OFFSET_OPS` holds the one slot rule the
simulation and the layout share: the byte offset counts from sp after the opcode's pops. A slot that
holds anything but one parameter or a local (`SlotRef.unusual`) is logged as a warning. The layout also
numbers each call's arguments (`arg_numbers`, the opt-in call-argument comments): the pushes that may
stand in the call's top `argc` slots, solved the same way, `arg1` being the last push; the simulation
and the numbering take `argc` from one rule (`call_argc`: the callee's parameters for `CALL`, the count
operand otherwise).

## Layer 3: Lifter — Done

**Location:** `falcom/ed9/ir/llil/` (`ED9VMLifter` and related classes), building on `ir/llil/`
(generic LLIL infrastructure)

Lifts disassembled instructions to LLIL: manages virtual stack and register state, and resolves VM
semantics such as calls, branches, and CFG shape. It does **not** recover `if`/`else`, loops, or
switch structure — that recovery is entirely HLIL's job, several layers up. The LLIL `Function`
assigns every instruction a global `inst_index` (see `get_instruction_by_index()`,
`get_instruction_block_by_index()`, `iter_instructions()`); each MLIL statement records the one it
comes from as its `llil_index`. The stack model, slot lifetimes, call setups and per-edge stack state
are in `docs/LLIL_DESIGN.md`.

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

Game-specific output, unlike `ir/`: it reads only HLIL, and nothing in `ir/` depends on it, so it may follow
the game's conventions (`docs/FUTURE_WORK.md`, "Generic/Falcom Boundary").

## Recompilation Pipeline — Core mechanism implemented, extensions planned

**Location:** `falcom/ed9/writer/` (`scp_writer.py`, `scp_writer_opcode_handler.py`,
`scp_writer_helper.py`, `scp_writer_hooks.py`, `scp_writer_hook_registry.py`, `scp_compile_check.py`,
`scp_writer_gen_common_funcs.py`, `metadata/`), driven by `falcom/ed9/scena2py.py`, validated by
`tools/scp_roundtrip_validator.py`.

A `.py` source file — sequential calls to per-opcode functions, one per VM opcode — executed
against a `ScpWriter` to emit bytecode. Compilation itself only needs that `.py` file. The Parser
and Disassembler come into play when *generating* a `.py` file from an existing script (e.g. for a
round-trip check), and in the compile check, which parses and lifts the compiled bytes again so a
stack mistake fails the compile with the `.py` line that caused it (`ScpWriter.check_compiled`).
An automated byte-exact round-trip check exists and works; fidelity settings are opt-in rather
than default. A shared common-function library
(`falcom/ed9/writer/metadata/common/`, generated from the corpus) is implemented and active by
default, so generated `.py` files import shared game functions instead of embedding full copies of
them. A `<stem>_hook.py` next to a script can replace or add functions and rewrite opcodes when it
compiles (`scp_writer_hooks.py`; `docs/LLIL_DSL.md` §4). Compiling from MLIL/HLIL DSL forms instead of
just LLIL DSL is still future work, loosely sketched rather than fully designed. Full detail in `docs/LLIL_DSL.md`; not-yet-started extensions
(MLIL/HLIL DSL, mixed-IR-level compilation, knowledge-driven typing for common functions) are in
`docs/FUTURE_WORK.md`.

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
