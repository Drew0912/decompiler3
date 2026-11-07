# ED9 Format: Parser and Disassembler

> Status: current. How `falcom/ed9/parser/`, `falcom/ed9/structs/` and `falcom/ed9/disasm/` (on the generic
> `assembler/`) read an ED9 script (`.dat`), what its call-site debug records hold, and how the games on this format
> differ. What the VM does with a script:
> `docs/falcom/ed9/ED9_VM.md`. Game tables (`.tbl`): `docs/falcom/ed9/TBL_FORMAT.md`.

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

**Location:** `assembler/` (the generic instructions, operand descriptors, basic blocks and recursive descent
disassembler) + `falcom/ed9/disasm/` (the ED9 opcode table, stack effects and formatter)

Converts bytecode into a readable instruction sequence, identifies basic block boundaries, and parses operands.
Instruction encoding/decoding is table-driven (an opcode table maps each opcode to its mnemonic and operand format), so
adding a new instruction is a table entry rather than new parsing code. Each row also has a kind, and each kind a stack
effect (`falcom/ed9/disasm/stack_effects.py`: the values it pops, a call's setup slots, the values it reads in place,
the values it pushes, whether it addresses a slot, whether the stack must be empty after it). A `POP` counts bytes: each
walker counts them through its own `PopCarry`, which carries the bytes past the last whole slot into the `POP` right
after it (a split pop). The parser's simulation and the debug-record tracker (`CallDebugInfoTracker`,
`structs/call_debug_records.py`) dispatch on the kind and read the effects; the LLIL lifter takes only which opcodes are
binary and a local `CALL`'s argument count from the table (`docs/ARCHITECTURE.md`, Layer 3).
`tests/parser_tests/test_stack_effects.py` checks all three walkers of the VM stack against the table.

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

## Call-Site Debug Records

Each function's table entry points to its records, one per call. What reads them: `ED9_VM.md`, Who reads the call-site
records. The rules below are the compilers', worked out from the bytes of every script of the five games; each exception
is named, and nothing else breaks them.

Every file comes from one of two compilers, and their traits never mix within a file:

| | Newer compiler | Older compiler |
|---|---|---|
| Common functions | no records | records |
| Which calls | all but a few (rule 2) | every call |
| A record's String | the code's own pool entry | its own debug-only pool entry |
| Doubled record lists | never | rule 8 |

Which file came from which: Games on This Format, below. What the writer does with these rules, per game:
`docs/dsl/LLIL_DSL.md`, Each game's writer.

1. **Which functions.** Newer: every non-common function that makes a call; a common function never. Older: every
   function that makes a call.
2. **Which calls.** Older: every call, `CALL`, `CALL_SCRIPT`, the tail call and `SYSCALL`. Newer: every call but some
   statement-level `btl_ai_skill` calls in the `SkillTable` functions of `ai/` scripts, most before the function's first
   line marker, a few right after an `if`. The bytes cannot tell them from a recorded call: `if (c) f();` on one line
   shares the `if`'s marker and is recorded. What they are in the source is not known.
3. **Line markers.** `DEBUG_SET_LINENO` is written only when the line changes: two markers in a row never hold the same
   line. Every non-common function has one. A common function that has one has it after its last call.
4. **Order.** Functions in table order. In a function, statements in address order, each statement's call tree in
   pre-order: the outer call, then the calls in its arguments in parameter order. A value carried in a register keeps
   its origin.
5. **A record** is 12 bytes: `func_id` u32, `call_type` u16, `arg_count` u16, the arguments' file offset u32.
   - Local (0): `func_id` is the callee's table index.
   - Script (1): `func_id` 0xFFFFFFFF; the first argument is a constant String, `module.func`, always dotted.
   - Tail call (2), module `''`: the bare name, and the table index if the script defines the function, else 0xFFFFFFFF.
     Any other module: as a script call.
   - Syscall (3): `func_id` 0xFFFFFFFF; two constant Integers lead, the subsystem and the command.
6. **Argument count.** A syscall, script call or tail call keeps every argument. A local call keeps them up to the last
   one the author wrote: only trailing constants equal to the callee's defaults can be left out. No record keeps fewer
   than that, and the bytes cannot tell which kept defaults the author wrote out: identical pushes, different records.
7. **An argument** is 8 bytes: a value word, then its kind. Kind 0 Constant holds the pushed word; every other kind
   holds 0. `PUSH_*` is Constant; `LOAD_STACK`, `PUSH_STACK_OFFSET`, `LOAD_STACK_DEREF` and `LOAD_GLOBAL` are Variable
   (2); `GET_REG` of a call's result is CallResult (1); a binary or unary op is Expression (3).
8. **Doubling (older compiler).** A non-common function gets its whole list twice, each copy with its own strings,
   exactly when a function placed earlier reaches it through local `CALL`s, directly or through other functions:
   compiling a function compiles each callee not yet compiled, and the callee is compiled again at its definition. A
   tail call does not trigger it. A common function is never doubled, and no list is written more than twice.
9. **Strings.** A script or tail call's leading name is always a debug-only pool entry. Debug-only strings sit after the
   defaults and before the global names.
10. **Where.** Header, function table, defaults, parameter flags, the records in table order, all their arguments in the
    same order, global variables, code, string pool, with no gaps. A function with no records stores the running
    position.
11. **Dead code.** Compiled dead code has records like any other. The parser does not decode all of it, so a few
    functions have records with no decoded call: three in `sora1`'s and `sora2`'s `chr5110`, `StopRunningTestWork` and
    `StopWalkingTestWork` in `kai1`'s `a1004` and `a1019`.

## Games on This Format

`sora2` (game version 1.5.0.0, the version of the exe `ED9_VM.md` was read from), `sora1` and `kuro1` scripts share
one format: all 45 decoded instruction forms of the opcode table (`PUSH` decodes into its typed forms; 0x28
`DEBUG_INT` never occurs), the same header (`dword_14` is 0: none is compiled with
`-s`; the function table at 0x18), value encoding and table field values. They differ in:
- **Call debug records:** the older compiler (Call-Site Debug Records) built `kuro1`, `kuro2`, `kai1`, `sora2`'s `chr0000`,
  `chr5001`, `chr5003` and `chr5007`, and in `sora1` those and `chr5107`; the newer one every other `sora` file. To
  find them again after a game update: a file whose common functions have records is older-built. A file with no
  common call and no String argument shows neither.
- **Syscalls:** each game has its own command set; most `(subsystem, command)` pairs occur in all three. Chr 47's third
  argument holds `Ani*` names in all five games, but the message commands differ: most text goes through Mes 19, Mes 0
  and Mes 6 in `sora2`, Mes 0 and Mes 6 in `sora1`, and Mes 6 in `kuro1`, `kuro2` and `kai1`.

`kuro1`'s `ani/mon9996_c00.dat` is a broken script (`byte06` 147 in its function table) and is not supported. The VM
does not read `byte06` (`ED9_VM.md`, File-format fields), but the parser refuses a non-zero one.
