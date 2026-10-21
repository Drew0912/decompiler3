# ED9 Format: Parser and Disassembler

> Status: current. How `falcom/ed9/parser/`, `falcom/ed9/structs/` and `falcom/ed9/disasm/` read an ED9 script
> (`.dat`), and how the games on this format differ.

## Layer 1: Parser — Done

**Location:** `falcom/ed9/parser/`, and `falcom/ed9/structs/` for the structures the writer shares with it
(`scp_types.py`, `string_pool.py`, `call_debug_records.py`, `crc32.py`)

Parses the SCP file format; extracts functions, global variables, strings, and other metadata;
provides access to raw bytecode. Key components: `ScpParser` (main parser), `ScpHeader` (file
header), `Function` (function metadata), `GlobalVar` (global variables). `string_pool.py` groups the
pool's strings by what references them, in pool order (code, function names, parameter defaults,
debug-only, global var names); the round-trip validator checks the pool with it. `call_debug_records.py` holds
`CallDebugInfoTracker`, which rebuilds the call-site debug records a function's calls get from its opcodes (a call
tree in source pre-order, values carried through registers; shared by the parser, the writer, the listing and the
validator), and compares a record with the record its call gets (content only: call type, callee, arguments; a
script call's callee id and name come from `script_call_identity`, the writer's rule too), the calls coming from
`CallDebugInfoTracker.replay` in record order with their instruction offsets; its `record_view` lets the validator's
`--round-trip` name each function's first record difference between the original and the rebuilt file.
`code_layout.py` gives the code order, each function's byte range and the ranges no instruction covers. The
validator's code, debug-record, source-precondition and reachability checks use them.

## Layer 2: Disassembler — Done

**Location:** `falcom/ed9/disasm/`

Converts bytecode into a readable instruction sequence, identifies basic block boundaries, and parses operands.
Instruction encoding/decoding is table-driven (an opcode table maps each opcode to its mnemonic and operand format), so
adding a new instruction is a table entry rather than new parsing code. Each row also has a kind, and each kind a stack
effect (`falcom/ed9/disasm/stack_effects.py`: the values it pops, a call's setup slots, the values it reads in place,
the values it pushes, whether it addresses a slot, whether the stack must be empty after it). The parser's simulation
and the debug-record tracker (`CallDebugInfoTracker`, `structs/call_debug_records.py`) dispatch on the kind and read the
effects; the LLIL lifter takes only which opcodes are binary and a local `CALL`'s argument count from the table
(`docs/ARCHITECTURE.md`, Layer 3). `tests/parser_tests/test_stack_effects.py` checks all three walkers of the VM stack
against the table.

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
bound it. See `tests/parser_tests/test_scp_stack_simulation.py`.

Each disassembled function keeps the simulated stack as `Function.stack_layout` (`StackLayout`, for
the `.py` comments): the depth before every reachable real instruction (not the synthetic
fall-through jumps), and for each of the 5 opcodes that address a slot by offset (`LOAD_STACK`,
`LOAD_STACK_DEREF`, `PUSH_STACK_OFFSET`, `POP_TO`, `POP_TO_DEREF`) the absolute slot and what may
be in it - parameter `argN`, a local, a caller-frame slot or a call setup, or nothing (outside the
live stack). What a slot may hold is solved per block start over every recorded edge,
not from the join groups, which span the whole function: a value that reaches a slot only at a
later join doesn't count for an earlier read. A `POP_TO` stands for the value it overwrote, so a
reassigned parameter is still the parameter. `addressed_slot` holds the one slot rule the
simulation and the layout share: the byte offset counts from sp after the opcode's pops (its stack
effect's `pops` in the opcode table, `falcom/ed9/disasm/stack_effects.py`). A slot that
holds anything but one parameter or a local (`SlotRef.unusual`) is logged as a warning. The layout also
numbers each call's arguments (`arg_numbers`, the opt-in call-argument comments): the pushes that may
stand in the call's top `argc` slots, solved the same way, `arg1` being the last push; the simulation
and the numbering take `argc` from one rule (`call_argc`, from the call's stack effect: the callee's
parameters for `CALL`, the count operand otherwise).

## Games on This Format

`sora2_1.0`, `sora1` and `kuro1` scripts share one format: all 45 decoded instruction forms of the opcode table (`PUSH`
decodes into its typed forms; the unknown 0x28 never occurs), the same header (`dword_14` is 0, the function table at
0x18), value encoding and table field values (a census of every file, 2026-10-18). They differ in:
- **Call debug records:** `kuro1`'s older compiler writes each function's records twice and gives a call without a line
  marker a record, so 26 of 634 `kuro1` files rebuild byte-identical (`docs/FUTURE_WORK.md`, "kuro1 Byte-Exact Debug
  Records").
- **Syscalls:** each game has its own command set: of the 991 `(subsystem, command)` pairs used, 540 occur in all three,
  89 only in `sora2_1.0`, 12 only in `sora1` and 147 only in `kuro1`.

`kuro1`'s `ani/mon9996_c00.dat` is a broken script (`byte06` 147 in its function table) and is not supported.
