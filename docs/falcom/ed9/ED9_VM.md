# ED9 VM

> Status: current. The rules of the ED9 script VM: what each opcode does, the stack and its frames, registers,
> syscalls, arithmetic, truth, calls by name, the functions the engine calls and what reads the call-site records. The
> file format and how decompiler3 reads it: `docs/falcom/ed9/ED9_FORMAT.md`.

**Source.** A static read of `sora_2nd.exe` 1.5.0.0 (Trails in the Sky 2nd Chapter, the game of the `sora2` corpus;
SHA-256 `CEAED8DA75BC1B1A32BAB2694D2CFF816DFB58A4AB16693041DCD7EEE0E258F4`), 2026-10-30 to 2026-11-06, most rules
confirmed by a second, independent read. Nothing here is traced in the running game, and the other four games' exes are
unread (their scripts share the format, `ED9_FORMAT.md`). The reads, with instruction addresses, are kept outside the
repo. The exe's log messages are quoted in translation: the exe holds them in Japanese.

**Tags.** Each rule ends in one:
- `[exe]`: read in the exe.
- `[scripts]`: read in the exe, and the bytecode of every `sora2` script agrees with it.
- `[compiler]`: not a VM rule but what the compiled scripts do, which decompiler3 relies on; a hand-edited script can
  break it and the VM still runs it.

**Terms.** A slot is 4 bytes. sp is a byte offset into the thread's stack, growing upwards. Argument k of a call is
the slot at sp - 4k before the call: argument 1 is the value pushed last.

## Values

Every value is a 32-bit word; its top 2 bits are the tag [exe]:

| Tag | Kind | Payload |
|---|---|---|
| 0 | Raw | the word as it is (untagged) |
| 1 | Integer | 30-bit two's complement, sign-extended from bit 29; stored as `(v & 0x3FFFFFFF) \| 0x40000000` |
| 2 | Float | the float32 bits shifted right by 2 (the 2 lowest mantissa bits dropped); stored as `(bits >> 2) \| 0x80000000` |
| 3 | String | an offset into the *current* script's file; offset 0 is `""` (`0xC0000000`) |

- A String means its text only inside the script that holds it: passed to another script's function, as an argument,
  a result or a shared global, it is read as an offset into that file [exe].
- +inf, -inf and NaN store and decode like any other Float [exe].

## The thread and its loop

- A thread holds 16 registers of 4 bytes, a stack of slots (512 bytes for a script thread), PC (an offset into the
  script file) and flags: bit 0 running, bit 2 syscall pending, bit 3 inside `CALL_SCRIPT`. A set bit 1 also makes the
  loop stop, with no finished hook if bit 0 is set; nothing read sets it. Flags 0 means stopped, and the thread's
  finished hook then runs [exe].
- The loop fetches one opcode byte at PC and dispatches over 0x00-0x28. It goes on while the thread runs, no syscall
  is pending and PC is below the file's size [exe].
- An opcode above 0x28 stops the thread *without* the finished hook; every other error runs the hook [exe].
- PC is checked only at the loop's head and after each instruction, against the size of the whole file, not the end
  of the code: a jump into the string pool runs data. Operand bytes are not checked, so a truncated last instruction
  reads past the code, or past the file at its very end [exe].
- Pushes are bound-checked (an overflow stops the thread); pops are never checked for underflow [exe].
- An operation on types it cannot handle logs a type error ("trying to operate on types that can't be operated on")
  and execution goes on [exe].
- While a syscall is pending (flags bit 2), each run of the thread calls the syscall handler again instead of
  fetching an opcode. If the handler leaves bit 2 set the run returns; if it clears it the run goes on with the next
  opcode [exe].

## Opcodes and operands

- 41 opcodes, 0x00-0x28. Their operand formats and stack effects are decompiler3's opcode table
  (`falcom/ed9/assembler/ed9_optable.py`, `falcom/ed9/assembler/stack_effects.py`), but for the lines below [scripts].
- 0x27 `POPN`: a u8 count; it pops that many slots and does nothing else (nothing is logged) [exe].
- 0x28 `DEBUG_INT`: a u32 operand, 5 bytes in all; it calls the logger at level 0, which drops everything below level
  2, so it does nothing at runtime [exe].
- decompiler3's opcode table reads 0x28's operand as signed, as the logger's `%d` prints it.
- 0x20 `EZ` is the logical not, 0x21 `NOT` the bitwise not [exe].
- 0x26 `DEBUG_SET_LINENO` stores its u16 in the thread and does nothing else; nothing in the VM reads it [exe].
- `PUSH` (0x00): a size byte, then a 4-byte word. It checks `sp + size <= stack size`, copies `size` bytes from the
  word and adds `size` to sp; PC always advances by 6. Size 0 pushes nothing, 1-3 push part of the word and leave sp
  misaligned, above 4 copy bytes from beyond the operand [exe]. The compiled scripts always use size 4 [compiler].

## Stack and slots

- The slot-addressing opcodes (`LOAD_STACK`, `LOAD_STACK_DEREF`, `PUSH_STACK_OFFSET`, `POP_TO`, `POP_TO_DEREF`)
  take a signed 32-bit byte offset added to sp. The first three pop nothing first, so they count from sp as it is;
  `POP_TO` and `POP_TO_DEREF` pop first and count from the new sp [exe].
- The addressed offset must lie in 0..size, size included, so an offset equal to the stack size reads or writes the 4
  bytes past the end [exe].
- Nothing checks alignment: an offset that is not a multiple of 4 reads or writes the 4 bytes at that byte position,
  across two slots [exe]. The compiled scripts address whole slots only [compiler].
- `POP`'s operand is an unsigned byte count: `POP 255` lowers sp by 255 bytes (63 slots and 3 bytes). Nothing rounds
  or checks it; sp can even go negative [exe].
- The compiler pops whole slots; a pop of more than 255 bytes is split into `POP 255` and a `POP` that completes the
  slots, right after it (seen in `kuro2` and `kai1` scripts) [compiler].

## Pointers

- A pointer is an Integer whose payload is a byte offset from the stack's base: absolute, not relative to sp or to a
  frame. `PUSH_STACK_OFFSET i` pushes `Integer((sp + i) & 0x3FFFFFFF)`, sp being its value before the push, with no
  range check [exe].
- `LOAD_STACK_DEREF` and `POP_TO_DEREF` accept any Integer. A Float is truncated toward zero; a String or Raw word
  counts as offset 0 [exe].
- Bounds: the slot holding the pointer must lie in 0..size, and then the check tests `sp + ref <= size`, not `ref`.
  So a valid pointer to a high slot stops the thread once sp grows past `size - ref`, and nothing checks the 4 bytes
  at `ref` itself [exe].
- A decoded value with any of bits 24-27 set takes a global branch (index `value & 0xF0FFFFFF`; past the global count
  a load gives Integer 0 and a store is dropped). No value reaches a real global through it: a positive one that large
  fails the bounds check first, a negative one keeps its sign bits through the mask. The branch is dead in practice
  [exe].
- Pointers stay valid in every frame: a callee can read and write its caller's slots through one, and any Integer can
  be used as a pointer to any slot [exe].
- The compiled scripts take a slot's address only as a call argument, and dereference only parameters [compiler].

## Calls and frames

**Local call** (`CALL`):
- `CALL` reads only its u16 operand, the function index: it checks it against the function count (at or above it the
  thread stops) and sets PC to the entry's code offset. Unless the entry's `is_common_func` byte is set, it records the
  index and name as the current function. It pushes and pops nothing, ignores `param_count` and the defaults, and does
  not read the pushed function id [exe].
- The compiled call pushes the caller's function index and the return address (both Raw), then the arguments, then
  `CALL`. Inside the callee the stack reads, bottom to top: function id, return address, the arguments, the callee's
  locals [compiler].
- The VM pops no arguments, and `RETURN` needs the two setup slots on top: the callee pops its own arguments [exe].

**Script call** (`PUSH_CALLER_FRAME`, `CALL_SCRIPT`):
- `PUSH_CALLER_FRAME` pushes, in order: the current function index (Raw), its operand (the return PC, Raw), the
  8-byte script pointer (two slots) and the marker `0xF0000000`. Each push is bound-checked; a failed check stops the
  thread, but the remaining pushes still run [exe].
- `CALL_SCRIPT module function argc`: both name operands must be String-tagged; any other word, or offset 0, becomes
  `""`. It sets flags bit 3 and calls the thread's call-by-name with (module, function, argc) [exe].
- On success it pops nothing, and entering the function has already cleared bit 3 and set flags = 1; the callee pops
  the arguments, and its `RETURN` pops the 5-slot frame [exe].
- On failure it pops argc slots, clears bit 3 and runs `RETURN`, which pops the caller frame and resumes at the
  frame's return PC: a failed call is skipped, and `REG[0]` is unchanged [exe].

**Tail call** (`CALL_SCRIPT_NO_RETURN`):
- It copies the top argc values (at most 32 are kept), sets sp = 0, pushes `0x0FFFFFFF`, re-pushes the arguments in
  their original order and calls call-by-name. It does not touch flags bit 3, so entering the function runs the
  finished hook once, after the arguments are fitted and before the new function starts [exe].
- sp = 0 discards everything below the arguments; that part of the stack need not be empty [exe]. The compiled
  scripts leave nothing below them [compiler].
- With a stack below 4 bytes it stops the thread and skips the marker, but still re-pushes (bound-checked) and still
  calls [exe].
- On failure it pops the arguments and runs `RETURN`, which pops the marker and ends the thread [exe].
- More than 32 arguments: the re-push reads past its 32-entry buffer [exe].

## Returns

`RETURN` reads the word on top of the stack [exe]:
- `0xF0000000`, a script call's frame: it restores the script pointer, PC and the current function index, with no PC
  bound check and no `is_common_func` check, then the current function's name from the restored script's table; an
  index out of range stops the thread.
- `0x0FFFFFFF`, the marker of a tail call or a thread start: it sets flags = 0 and runs the finished hook; the loop
  then sees flags = 0 and runs the hook again, so the hook runs twice unless its first call restarts the thread.
- Any other word, a bare frame: it pops the return address, which becomes PC (a value above the file's size stops the
  thread), then the function id, which must be below the function count or the thread stops, and restores the
  current function's index and name from it unless that function is common. So the id slot holds the caller's own
  index as a Raw word: a tagged word fails the count check.

- `RETURN` does not need an empty stack: it takes whatever word is on top as the marker or the return address, so a
  leftover value is misread [exe]. The compiled scripts pop every value of the function before it [compiler].
- No return path touches the registers [exe].

## Registers

- 16 registers of 4 bytes, `REG[0]`..`REG[15]`. `GET_REG` / `SET_REG` take a u8 and stop the thread on 16 or above
  (`SET_REG` then pops nothing) [exe].
- Nothing saves, restores or clears them: not `CALL`, `RETURN`, `PUSH_CALLER_FRAME`, `CALL_SCRIPT`, the tail call or
  the syscall dispatcher. So `REG[1]`..`REG[15]` survive every call [exe].
- A call's result travels in `REG[0]` by the compiler's convention only, and the tail call's other arguments pass
  through registers (`SET_REG n; POP; GET_REG n`) [compiler].
- A new thread's registers are all Raw 0, not Integer 0. Thread start and script calls do not touch them, so a thread
  reused for another run keeps its old values [exe].

## Syscalls

- `SYSCALL subsystem command argc` stores the three in the thread, marks the thread as inside a syscall and calls the
  dispatcher. It pops nothing [exe].
- The subsystem is the index of one of 28 command objects; N is how many commands each has [exe]:

  | # | Subsystem | N | | # | Subsystem | N |
  |---|---|---|---|---|---|---|
  | 0 | Sys | 43 | | 14 | Effect | 40 |
  | 1 | Chr | 232 | | 15 | Menu | 12 |
  | 2 | Camera | 50 | | 16 | Item | 19 |
  | 3 | Event | 52 | | 17 | SaveData | 6 |
  | 4 | Fade | 3 | | 18 | Portrait | 14 |
  | 5 | Mes | 21 | | 19 | Screen | 31 |
  | 6 | Sound | 46 | | 20 | AVoice | 6 |
  | 7 | Pad | 1 | | 21 | MapJump | 18 |
  | 8 | Movie | 3 | | 22 | UI | 44 |
  | 9 | Trophy | 1 | | 23 | Quest | 18 |
  | 10 | Debug | 20 | | 24 | ChrStatus | 25 |
  | 11 | Map | 134 | | 25 | Shop | 10 |
  | 12 | Party | 26 | | 26 | Minigame | 2 |
  | 13 | Btl | 144 | | 27 | Game | 22 |

- The dispatcher reads only the subsystem and the command; argc reaches a handler only through the thread. An unknown
  subsystem does nothing. A command runs only if its mask AND the thread's command mask is non-zero; threads start
  with every bit set. As the constructors build them, 1,002 of the 1,043 commands have mask 1. These are 2: Sys 17; Chr
  28, 33, 35, 37, 72, 172 and 192; Event 30; Btl 16, 24, 38 and 133; Effect 0, 34 and 35; Portrait 0 and 9. Event 2, 13
  and 15 are 3, so they run if the thread's mask has either bit. All 20 of Debug are 0 (Debug has no handlers). The
  command objects also have a function that adds bits to a command's mask, but nothing is seen calling it [exe].
- Handlers read their arguments in place: argument k at sp - 4k. No handler pops; a later `POP` removes them [exe].
  The compiled scripts pop them right after the syscall [compiler].
- argc is checked per argument: a missing argument gets a default (Integer 0 in the handlers read) [exe].
- Each handler decodes its own arguments (tag tests, then float / int conversion); Strings resolve in the current
  script [exe].
- A handler's result is a word written to `REG[0]`, tagged by the handler (Sys 12 copies a stored word as it is), only
  from inside a `SYSCALL`, and only when it has a result: a handler with none leaves `REG[0]` holding an older value (in
  the handlers read) [exe].
- A handler can suspend the thread: while flags bit 2 is set, each run of the thread re-calls the handler instead of
  fetching an opcode, and other threads and the engine run in between. Handlers set the bit themselves (Sys 17 does,
  while the thread's "job posted" flag is set) [exe].
- The five handlers read for their effects write no script global and nothing through a pointer argument (Sys 17's
  queued callbacks and two helpers were not read). Sys 12 reads the engine's 256-entry "global work" array, engine-wide
  variables separate from script globals (an index above 0xFF logs and reads entry 0) [exe].

## Arithmetic

- **Width:** both payloads are sign-extended to 32 bits, `ADD` / `SUB` / `MUL` compute in 32 bits, and the result is
  stored as a 30-bit Integer: it wraps modulo 2^30, with no overflow check [exe].
- **`DIV`:** two Integers divide truncating toward zero, wrapping to 30 bits (-2^29 / -1 gives -2^29). There is no
  zero check: an Integer division by zero is a CPU divide error; a String or Raw divisor counts as 0 and divides by
  zero too. With a Float operand both sides become float32 (an Integer converted, a non-number 0.0) and the division
  is float32: `400 / 30.0` gives 13.333333 with its 2 lowest bits dropped (13.333332), never 13.0; x / 0.0 gives
  +-inf or NaN, unchecked [exe].
- **`MOD`:** C's truncating remainder (the dividend's sign: -7 % 3 = -1), wrapping to 30 bits. At least one operand
  must be an Integer: a Float operand is truncated first, a String or Raw word counts as 0; with no Integer operand
  (Float % Float) it logs a type error and pushes the left operand back unchanged. No zero check; x % 0.5 is x % 0
  [exe].
- **Floats:** float32 only, no double. Every computed Float is stored like a constant, its 2 lowest mantissa bits cut
  (truncation, not rounding). If either operand is a Float, an Integer operand is converted (round to nearest, exact
  up to 2^24) and a non-number becomes 0.0. Nothing checks for non-finite values. Float to Integer (the jumps, `MOD`,
  bitwise ops, derefs) truncates toward zero [exe].
- **`NOT` and `NEG`:** `NOT` is bitwise, `~payload` masked to 30 bits, Integer only (anything else logs a type error
  and stays). `NEG` negates an Integer, wrapping at 30 bits (-2^29 stays -2^29); flips a Float's sign bit (0.0 to
  -0.0, NaN flips too); a String or Raw word logs a type error and stays [exe].
- **`BITWISE_AND` / `BITWISE_OR`:** at least one Integer operand, else a type error and the left operand pushed back.
  A Float operand is truncated first; a String or Raw word counts as 0. The op runs on the 32-bit sign-extended
  payloads and the result is masked to 30 bits, so no mask reaches past 30 bits: `536870911 * 8 + 7` wraps to
  Integer -1, all 30 bits set [exe].
- **`LOGICAL_AND` / `LOGICAL_OR`:** eager (both operands are popped before either is tested); the result is Integer
  0/1, never an operand. Their own truth: an Integer if its payload is not 0; a Float compared with 0.0, so 0.5 is
  true (unlike in a jump) and -0.0 false; NaN true; String and Raw false [exe].
- **Mixed tags:** no concatenation and no string arithmetic. `ADD` / `SUB` / `MUL` / `DIV`: a String or Raw operand
  counts as 0, or 0.0 if the other side is a Float; the result is an Integer unless an operand is a Float
  (`"a" + "b"` is Integer 0; `x / "a"` divides by zero). `MOD` and the bitwise ops need at least one Integer, `NOT` and
  `EZ` an Integer, and `NEG` an Integer or a Float; else a type error and the operand unchanged. Comparisons treat
  non-numbers as 0, except `EQ` / `NE` between two Strings [exe].

## Truth

How a value tests in a conditional jump (`POP_JMP_ZERO`, `POP_JMP_NOT_ZERO`) [exe]:

| Value | Tests | Why |
|---|---|---|
| Integer | its payload: `0x40000000` is false | |
| Float 0.5, -0.5, -0.0 | false | truncated toward zero |
| Float NaN, +-inf, beyond +-2^31 | true | the truncation gives `0x80000000` |
| String, even non-empty | false | `POP_JMP_NOT_ZERO` never jumps on it, `POP_JMP_ZERO` always does |
| Raw word | false | |

- `EZ` accepts only an Integer and gives Integer 0/1. Any other operand logs a type error and is pushed back
  unchanged, so `EZ` on a Float leaves the Float, and a following jump tests the Float itself, not its negation [exe].
- `LOGICAL_AND` / `LOGICAL_OR` have their own truth (Arithmetic) [exe].

## Comparisons

- The result is always Integer 0/1 [exe].
- `GT` / `GE` / `LT` / `LE`: with a Float operand both sides go to float32 and an ordered compare decides, so all four
  are false when either side is NaN, and -0.0 equals 0.0. Otherwise a signed compare of the payloads, non-numbers as
  0: Strings are not ordered (`"a" < "b"` is false, `"abc" < 1` is true) [exe].
- `EQ` / `NE`: two Strings compare by content (resolved in the current script; offset 0 is `""`). Anything else gets
  the same numeric promotion, non-numbers as 0, so a Raw word equals 0 and every other Raw word (`RawInt(5) == 0` is
  true), and `"abc" == 0` is true. Float equality: NaN is unequal to everything, -0.0 == 0.0. `NE` is `EQ` inverted,
  so `NaN != x` is true [exe].
- NaN can occur (0.0 / 0.0), so `!(a < b)` is `a >= b` except when a NaN reaches the comparison [exe].

## Calls by name

Script calls, tail calls and the engine's own calls find a function by (module, function) [exe].

**Module names** [exe]:

| Module | What it finds |
|---|---|
| `''` | the thread's current script; no lookup |
| `this` | the scripts of the thread's owner object: its main script, then its list of extra scripts. A function missing everywhere still returns the main script, and the error then comes from the function lookup |
| `self` | the object for the caller's character id: its main script, its extra scripts, the common script `ani/common`, then the full `module.function` resolver; tried only when the caller has an owner id, otherwise the name goes on to the table |
| `map` | the field map's script list (8 scripts at most): the first one that has the function wins. If none has it, the search goes on to the table, which finds nothing unless some script is named `map` |
| `btl` | the battle's one script, returned even when it lacks the function |
| any other name | the table of loaded scripts, by the file's base name (`common` for `ani/common.dat`); an entry matches if its owner id is 0xFFFF or the caller's id, and a caller with no owner id (0xFFFF) matches every entry |

- The four special names are compared including the terminating NUL, so they must match exactly. `common` is not a
  special case, just a loaded script with that name. A lookup never loads a script: it must already be in the table
  [exe].
- **The `module.function` resolver** (the engine's calls) takes one string, splits it at the first `.` (the module
  part goes into a 32-byte buffer with no length check, so it must stay within 31 characters: a longer one overflows)
  and applies the same module rules; with no `.`, the whole string is a function in the current script [exe].
- **The function lookup:** `name_hash` is the bitwise NOT of the standard CRC-32 (`~crc32`; the empty name gives
  0xFFFFFFFF) [scripts]. The function table is scanned linearly, comparing `name_hash` first and the name text second,
  so the table's order does not matter; the index found is thrown away and the function looked up again by name
  [exe]. The compiled scripts sort the table by name [compiler].
- **Failures:** an unknown script returns false silently; an unknown function logs "function not found" and returns
  false. False makes `CALL_SCRIPT` pop the arguments and return [exe].
- **Entering the function** (script calls and tail calls; the engine's calls start a function through thread start
  instead, Threads and the engine's calls) [exe]:
  - It refuses a script whose header `dword_14` has bit 0 set and a function with a Pointer parameter; both are logged
    and return false.
  - When argc equals `param_count`, the arguments stay as they are. Otherwise it pops them (keeping at most 32), then
    pushes the defaults for the missing trailing parameters, the last default deepest; Integer 0 for any parameter
    still missing, logging "too few arguments"; then the given arguments, back on top. Extra trailing arguments are
    dropped, logging "too many arguments". So the callee always gets exactly `param_count` arguments.
  - The Value / Offset / Nullable bits of the parameter flags are neither checked nor converted.
  - If the thread is running and bit 3 is clear, it stops the thread and runs the finished hook. That happens for the
    tail call only: `CALL_SCRIPT` sets bit 3 around this call. If the stack overflowed while the arguments were
    fitted, the thread is already stopped and the hook is skipped; the flags = 1 below then starts it anyway. Then it
    clears bit 3, sets the callee's script, PC and current function (always: no `is_common_func` test here) and sets
    flags = 1.
- String arguments are not converted: the words are copied raw, so a String passed into another script's function is
  read as an offset into the callee's file, the wrong text [exe].
- So trailing defaults can be left out in script calls and engine calls, but not in local `CALL`s, which ignore
  parameters [exe].

## Threads and the engine's calls

- Globals live in the script object (one per loaded file and owner), not in the thread. A `CALL_SCRIPT` callee runs
  with its own file's object and sees that file's globals; `RETURN` restores the caller's [exe].
- The 18 system scripts are loaded at startup and shared (the loader has a second call site, not read), so every thread
  that runs or calls into one uses the same object and its globals: `scena/system`, `system2`, `sound`, `npc_setting`,
  `sys_event`, `talk_common`; `ani/btlcom`, `btlmagic`, `btlitem`, `btlsupport`, `btlpom_common`, `common`, `sound_ani`;
  `obj/door`, `brk_obj`, `tbox`, `recover`; `battle/btlsys` [exe].
- Thread start stops a running thread (finished hook), sets the script, PC = 0 and sp = 0, pushes the `0x0FFFFFFF`
  marker (if the stack has at least 4 bytes), then the defaults and arguments, sets flags = 1 and runs the thread once
  at once [exe].
- It fits the arguments as entering a function does (Calls by name), refusing the same scripts and functions, with
  these differences: an argument still missing gets Raw 0, extra arguments are dropped silently, and the cut to 32
  arguments is not on this path [exe].
- The engine's synchronous calls run the function on a temporary thread and take `REG[0]` as the result (Integer 0
  if the start fails); the thread is then destroyed, and calls still queued on it are dropped without running [exe].
- The engine's dispatch starts the function on one of the 11 named script threads (thread 0 for most callers),
  at once, like thread start: nothing is queued. The function runs until it ends or waits, and a wait goes on in
  that thread's later runs. The dispatch is refused if that thread has a job posted, or if the function is not found
  ("script function name is invalid" is logged) [exe].
- Each run of a thread stores a float argument in the thread; it behaves like a time step: the caller passes its own
  float straight on and can add it to a running total [exe].

## Engine-called names

The engine calls script functions by name; those names are part of the contract between the engine and the scripts, and
a decompiler or rewriter must keep them with their parameters. A missing function only logs, with a message that depends
on the route, or, where the engine tests for it first or walks a list of scripts itself, it silently skips the start or
runs another name, so a dropped one fails silently in game [exe].

**Fixed `module.function` names** (195: every whole string of that form in the exe, and still a lower bound: the engine
also calls names it reads from objects and scripts, below) [exe]:

| Module | Functions |
|---|---|
| `system` (65) | `ApplyPartyOutMembers`, `CookPlay`, `EventItemCheck`, `ExecuteEventNext`, `ExecuteWarp`, `FieldItemGet`, `FoodBuffEffectPlay`, `FoodBuffEffectStop`, `GetBreakObjItem`, `GetMapEnvironmentID`, `GetNowLoadingType`, `GetShopOKVoice`, `GetShopOpenVoice`, `GetShopOpenVoiceGuest`, `HealObjProcess`, `InitGame`, `MapJumpAfterCallScript`, `MapJumpCallScript`, `MapJumpState`, `MapJumpVoice`, `MapReinit`, `MinigameFishingStart`, `NewGame`, `OnAddMedal`, `OnBooksNoteClose`, `OnCampDecidedTab`, `OnCampMenuClose`, `OnCampMenuOpen`, `OnCampOrbmentAutoEquipStart`, `OnCampOrbmentChangeMenu`, `OnCampOrbmentChangeTab`, `OnCampOrbmentEquipQuartz`, `OnCampTopChangeMenu`, `OnChangePlace`, `OnCheckTalkMode`, `OnChrEventEntry`, `OnChrEventExit`, `OnItemCountChanged`, `OnLeaderChanged`, `OnMainNoteClose`, `OnMapInit`, `OnNoteMenuClose`, `OnNoteMenuOpen`, `OnShopClose`, `OnShopCloseOrbmentSlotMessage`, `OnShopGetItem`, `OnShopOpen`, `OnShopTopMenu`, `PlayCookSupportGetVoice`, `PlayCookVoice`, `PlayFishSpotVoice`, `PlayFoodEatVoice`, `PlayQuestBoardVoice`, `PlayQuestStartVoice`, `PlayReportVoice`, `QuestBoardTutorial`, `QuestBoardTutorialEnd`, `QuestEndVoiceCheck`, `QuestFailedProcess`, `SetRandomMonstetFlag`, `SetupCostumeFlags`, `SetupReplacePathInfo`, `ShopMenuOpen`, `TBoxProcess`, `UnLockRecipe` |
| `btlsys` (28) | `BattleBraveAttack`, `BattleCommandArts`, `BattleCommandBegin`, `BattleCommandCraft`, `BattleCommandItem`, `BattleCommandSub`, `BattleDead`, `BattleEnd`, `BattleGameOverClose`, `BattleGameOverMenu`, `BattleGameOverOpen`, `BattleGameOverRelease`, `BattleInit`, `BattlePreEnd`, `BattleResultEnd`, `BattleSetting`, `BattleStart`, `BattleTurnBegin`, `BattleTurnEnd`, `CanFullBurst`, `CanRestoreHelpFlagOnRetry`, `FieldBattleRetry`, `NextBattle`, `OnFieldBounceAttack`, `OnFieldClingAttack`, `OnStatueAIActive`, `OnSubInfoOpened`, `PlayCommandPromptAVoice` |
| `btlcom` (48) | `AniBtlArtsFailed`, `AniBtlAttackMoveStart`, `AniBtlAttrAbsorbEffect`, `AniBtlAvoidSuccess`, `AniBtlBraveAttackBurst`, `AniBtlBraveAttackChase`, `AniBtlBraveAttackCutinSetup`, `AniBtlBraveAttackEffect`, `AniBtlBraveAttackFullBurst`, `AniBtlBraveAttackOpen`, `AniBtlBraveAttackRush`, `AniBtlBuffCancel`, `AniBtlBuffEffect`, `AniBtlCancelAria`, `AniBtlChargeCraft`, `AniBtlConditionCantAction`, `AniBtlConditionEffect`, `AniBtlConditionEndEffect`, `AniBtlConditionReset`, `AniBtlConditionStun`, `AniBtlDamageTargetsSkip`, `AniBtlEncount`, `AniBtlEnd`, `AniBtlEndChr`, `AniBtlOnceResurectItem`, `AniBtlOverDriveButton`, `AniBtlPauseFilterOff`, `AniBtlPinchEffect`, `AniBtlRegene`, `AniBtlScapegoat`, `AniBtlSkipInit`, `AniBtlStart`, `AniBtlStartChr`, `AniBtlTurnStart`, `AniFieldBraveChargeCamera`, `AniFieldBraveChargeIn`, `AniFieldBraveChargePlayerWait`, `AttackCritical`, `FAttackBounce`, `FAttackCritical`, `OnAttackHit`, `OnDropItemGet`, `OnFieldAttackFlashEnd`, `OnFieldAttackFlashStart`, `OnFieldAttackReflect`, `OnFieldBraveChargeEnd`, `PlayFielctAttackReflectEffect`, `ShowUnlockRecipeMessage` |
| `sound` (11) | `BattleTalkEndSound`, `BattleTalkStartSound`, `ChangeEnvSE`, `Init`, `InitEnvSE`, `LogMenuCloseSound`, `LogMenuOpenSound`, `MapBBGMChange`, `MenuCloseSound`, `MenuOpenSound`, `OnMapReinit` |
| `fishing` (15) | `EventCheck`, `FishingEnd`, `FishingFailed`, `FishingHookFailed`, `FishingMessage`, `FishingNoFish`, `ItemSelectStart`, `PlayFishingVoice`, `ResultEnd`, `ResultItemSet`, `ResultItemStart`, `ResultSet`, `ResultStart`, `SetFirstCamera`, `SetSecondCamera` |
| `map` (2) | `ExtraMovie`, `Get1stClearReward` |
| `sound_ani` (2) | `SeBattleConfigDefault`, `SeBattleConfigScraftSkip` |
| `brk_obj` (8) | `AniBreak`, `AniDamage`, `AniSwitchOff`, `AniSwitchOn`, `AniSwitchOnWait`, `AniTargetSelect`, `AniTargetUnselect`, `AniWait` |
| `door` (7) | `AniDoorClose1`, `AniDoorClose2`, `AniDoorOpen1`, `AniDoorOpen2`, `AniDoorWait1`, `AniDoorWait2`, `AniWait` |
| `tbox` (5) | `AniClose`, `AniOpen`, `AniOpened`, `AniWait`, `AniWaitMonster` |
| `common` (2) | `AniDarkRoomIn`, `AniDarkRoomOut` |
| `btlsupport` (1) | `AniBtlSupportCoverEnd` |
| `recover` (1) | `AniWait` |

- Bare names looked up in a given script: `Init`, `BattleInit`, `BattleSetting`, `BattleDead`, `BattleInterrupSkillEnd`,
  `SkillTable`, `SummonTable`, `SpecifyMovePos`, `OnEventFinalize` (the `system` script, on the Manager's thread 0,
  unless a start is already posted there), `OnEnemyInfoOpened` (`btlsys`), `OnTitleLoad` and `TitleEvent` (each of the
  field map's scripts in turn: the first that has the name and can start it, on the Manager's thread 0; if none does,
  nothing happens and nothing is logged). These last four take no arguments [exe].
- Names the engine runs on a character, found by the `self` rules, so a `module.function` name works there too (a name
  can be in more than one list) [exe]:
  - on a temporary thread, the character as owner, no arguments: `AniAttachWeapon`, `AniAttachWeaponDisarm`,
    `AniBtlRelease`, `AniBtlReinit`, `AniDetachOrbmentAria`, `AniDetachWeapon`, `AniNoteSetup`, `AniRestoreDefault`,
    `AniVoiceFieldChange`, `AnimeClipTable`, `AnimeClipTable2`, `DefaultFace`, `Init` (a character's, besides the map's
    above), `LoadResidentEffect`, `OnAttachEquip`, `OnTurnBattleCommandBegin`, `OnTurnBattleCommandEnd`,
    `btlcom.AniBtlEndChr`, `btlcom.AniBtlStartChr`, `btlcom.AniBtlTurnStart`, `btlcom.OnFieldAttackFlashEnd`,
    `btlcom.OnFieldAttackFlashStart`, and probably `btlcom.AniBtlBuffCancel` (its count is not settled);
    `GetCameraLookHeightOffset` (the result is read)
  - the same with arguments: `AniMoveWaterEffect` (two Floats; the result is read); one: `AniChangeRodID`,
    `btlcom.OnDropItemGet`, `btlcom.PlayFielctAttackReflectEffect`, `common.AniDarkRoomIn`, `common.AniDarkRoomOut`;
    three: `AniFieldBounce`, `btlcom.AniBtlConditionStun`; four: `btlcom.AniBtlConditionEffect`,
    `btlcom.OnFieldAttackReflect`. What those arguments hold is not read
  - started on an Ani thread with the three arguments below: `AniWait`, `AniBtlWait`, `AniBtlWeak`, `AniBtlStun`,
    `AniBtlAria`, `AniBtlCharge`, `AniBtlWaitDiamondGuard`, `AniWalk`, `AniDash`, `AniRun`, `AniBtlWalk`, `AniBtlRun`,
    `AniBtlDash`, `AniTurnL`, `AniTurnL35`, `AniTurnL140`, `AniBtlTurnL`, `AniTurnR`, `AniTurnR35`, `AniTurnR140`,
    `AniBtlTurnR`, `AniAttachWeapon`, `AniBtlReinit`, `AniDetachWeapon`, `AniFieldAttackEntry`, `AniFieldChargeAttack`,
    `AniMgFish`, `AniMgFishEnd`, `AniMgFishResult`, `AniMgFishStart`, `AniBtlDead`, `AniFall`, `AniSwim`,
    `AniAttachCocktail`, `AniAttachCup`, `AniAttachGlass`, `AniAttachMug`, `AniAttachOrbmentAria`, `AniBtlArmed`,
    `AniBtlArts`, `AniBtlBackRolling`, `AniBtlDamage`, `AniBtlDamageAria`, `AniBtlDamageWeak`, `AniBtlDeadEnd`,
    `AniBtlDefend`, `AniBtlDisarm`, `AniBtlDisarmShort`, `AniBtlKnockDown`, `AniBtlKnockDownEnd`, `AniBtlRolling`,
    `AniBtlStartBackStep`, `AniBtlStartExpand`, `AniBtlStopRun`, `AniBtlStunEnd`, `AniBtlTurnLLever`,
    `AniBtlTurnRLever`, `AniBtlWalkBack`, `AniBtlWalkLeft`, `AniBtlWalkRight`, `AniCampBtlWait`, `AniCampWait`,
    `AniChargeAttackEntry`, `AniDamage`, `AniDamageSmall`, `AniDead`, `AniDetachCocktail`, `AniDetachCup`,
    `AniDetachGlass`, `AniDetachMug`, `AniDetachOrbmentAria`, `AniDownStair`, `AniFieldCling`, `AniFieldClingStart`,
    `AniFieldCombiAttackSingle`, `AniFieldCraft`, `AniFieldSuicide`, `AniFieldSwarmAttack`, `AniInfested`,
    `AniInfestedSweep`, `AniInfestedWalk`, `AniInfestedWalkSweep`, `AniMGAttack`, `AniMGDamage`, `AniMGDead`,
    `AniMGEscape`, `AniMGEvolution`, `AniMGMove`, `AniMGWait`, `AniMgFishEnd2`, `AniRunEnd`, `AniSitWait`, `AniSprint`,
    `AniStopRun`, `AniSwayBack`, `AniSwayFront`, `AniTurnL140Walk`, `AniTurnL70Walk`, `AniTurnR140Walk`,
    `AniTurnR70Walk`, `AniWalkBack`, `AniWalkEnd`, `AniWalkStart`, `btlcom.AniBtlChargeCraft`, `btlcom.AniBtlScapegoat`,
    `btlcom.AniFieldBraveChargeIn`, `btlcom.AniFieldBraveChargePlayerWait`. Thread 2, except thread 0 for
    `AniCampBtlWait`, `AniCampWait` and the `AniMG` names, thread 3 for `AniDamageSmall` and at two of its three sites
    `AniBtlDisarm`; a turn name can use thread 3. `AniFieldClingStart` and `AniFieldSwarmAttack` go the way
    `AniFieldBounceAttack` does (third argument Integer 0); `AniFieldSwarmAttack` only when a byte of the character's is
    set, else `AniFieldAttack` runs
  - started on an Ani thread as Chr 47 starts one with no arguments given (its first three defaults, else Integer 0, 1,
    0): `AniLadderDown`, `AniWait` in one function (Event 36), `AniBtlWait`, `AniDetachEqu0505`, `AniMgFishHitting`,
    `AniBtlDead`, `AniFall`, `AniSwim`, `AniAfter`, `AniAppearFromBreakObject`, `AniBackStep`, `AniBtlChangeCharaIn`,
    `AniBtlChangeCharaOut`, `AniBtlEscape`, `AniBtlItem`, `AniDoorOpenLeftArm`, `AniDoorOpenRightArm`,
    `AniFieldCombiAttack`, `AniFieldDodge`, `AniHit`, `AniLadderDownEnd`, `AniLadderDownStart`, `AniLadderUp`,
    `AniLadderUpStart`, `AniLand`, `AniTurnLLever`, `AniTurnRLever`, `btlcom.AniBtlAttackMoveStart`,
    `btlcom.AniFieldBraveChargeCamera`, `btlsupport.AniBtlSupportCoverEnd`. Thread 2, except thread 0 for `AniSwim` here
    and `btlcom.AniFieldBraveChargeCamera`, thread 3 for the two `AniDoorOpen` names
  - `AniLadderUpEnd`: the same, with three arguments given: Float 0, Float 1.0, an Integer
  - Before starting some of these the engine tests that the function exists (32 tests, besides Chr 150's). The test logs
    nothing. If the function is missing the engine skips the start or picks another name (both seen), so dropping one
    changes what runs.
- Names the engine compares: it also tests which function a character's Ani thread 2 is running, by comparing the
  thread's current function name with a literal (35 names at string-compare calls in the code read; a few compares are
  inlined and not in that count). So a renamed function changes what the engine does even where it never starts that
  name. The current name is the function entry's own, so it is bare, even for a function started as `module.function`.
  Compared and not started in the code read: `AniBtlKnockDownLoop`, `AniFieldAttack2`, `AniFieldAttackJump`, and
  `AniFieldBraveChargePlayerWait` (the bare form of the `btlcom` name above) [exe].
- Names the map objects run: the handlers of doors, treasure boxes, break objects and recovery points start the `door`,
  `tbox`, `brk_obj` and `recover` names above as Map 20 starts one: on the object's own thread, with three Values
  (Float, Float, Integer flags). When these run in play is not read [exe].
- The spellings must match exactly, including what look like typos (`AniBtlEncount`, `AniBtlOnceResurectItem`,
  `SetRandomMonstetFlag`, `BattleInterrupSkillEnd`, `UnLockRecipe`, `PlayFielctAttackReflectEffect`) [exe].
- Known arguments: after a map's scripts load, `Init` in the *first* map script runs with no arguments (no existence
  check), then `system.OnMapInit` with one Integer (1 if the map's load mode is 1, else 0); later
  `system.GetMapEnvironmentID()`'s result is used as an integer (an Integer as it is, a Float truncated, anything else
  or a failed call 0). With an empty map-script list, `Init` and `OnMapInit` are both skipped. On a character's battle
  death, `btlsys.BattleDead` runs with one Integer (the character's id), then the per-battle script's `BattleDead`, if
  it has one, with the same argument [exe].
- More known arguments, with no result used unless said [exe]:
  - one Integer: `system.OnItemCountChanged` (the item id), `system.OnLeaderChanged`, `system.QuestFailedProcess`,
    `system.ShopMenuOpen`, `system.OnChrEventEntry`, `system.OnChrEventExit`, `btlcom.OnAttackHit`,
    `btlcom.AniBtlBraveAttackEffect`, `btlcom.AniBtlCancelAria` (a byte from its caller: 0 from Btl 95, other callers
    not read), `btlcom.AniBtlConditionReset` (Integer 0), `btlcom.AniBtlConditionEndEffect` (a condition's id),
    `btlcom.AniBtlRegene` (0, 1 or 2), `system.GetBreakObjItem` (the result is read), `system.OnCampMenuClose` (a close
    code from the camp menu's state: 0 to 6, 8, 9 or 10; on the `camp` thread, when Game 3 gave no name),
    `btlsys.BattleSetting` then the per-battle script's `BattleSetting` (Integer 0 at the battle start, Integer 1 from a
    second function; what that one is is not read)
  - two Integers: `system.OnChangePlace`, `sound.ChangeEnvSE` (the old place's id and the new one's)
  - none: `system.OnAddMedal`, `system.SetupCostumeFlags`, `system.SetRandomMonstetFlag`, `system.MapJumpState`,
    `system.ExecuteWarp`, `system.PlayQuestStartVoice`, `sound.BattleTalkEndSound`, `btlcom.AniBtlAvoidSuccess`,
    `btlcom.AttackCritical`, `btlcom.OnFieldBraveChargeEnd`, `map.ExtraMovie`, `map.Get1stClearReward`,
    `btlsys.BattleInit` then the per-battle script's `BattleInit`, `btlcom.AniBtlStart`, `sound.MenuOpenSound`,
    `sound.MenuCloseSound`; and, with the result read, `system.PlayFishSpotVoice`, `system.QuestEndVoiceCheck`,
    `system.GetNowLoadingType`
  - one raw argument, the result read: `system.OnCheckTalkMode` (Mes 19's arg 1)
  - started, the count read and not the values: `fishing.FishingEnd`, `fishing.ItemSelectStart`,
    `fishing.ResultItemStart`, `system.CookPlay` (2), `fishing.ResultItemSet`, `system.OnBooksNoteClose` (4),
    `fishing.ResultSet` (5)
- `fishing` and the scripts `minigame/blackjack`, `poker`, `roulette`, `slot` are loaded per scene; `fishing` is not one
  of the 18 system scripts [exe].
- Character scripts: a Chr syscall (arguments: a character id, then a script name) loads `ani/<name>` and appends it to
  that character's extra scripts, the list `this` searches [exe].
- The per-battle script: Btl 21's arg 2 is a script file name, not a function name. The battle start keeps up to 31
  characters of it and loads `battle/<name>`. It reads the name in its loop over the joining members, so with no member
  that has a setting object nothing is kept, even with arg 2 given. With arg 2 empty, and from the battle start's two
  other callers, which pass no name, the name comes from the joining monsters' data; if two of them differ the first
  stays, and the exe's log says to check `t_mon_????`. With no name nothing is loaded. That script's `BattleInit`,
  `BattleSetting` and `BattleDead` run after the `btlsys` ones, and its `BattleInterrupSkillEnd` runs by itself, if it
  has them. So a rewriter must keep the file name, and those function names in that file [exe].
- **Names the engine does not hold:** at many call sites the name is not in the exe. It comes from a game object
  (characters, events, treasure boxes, break objects, map objects), from a data table, from `map.<name>` built from an
  object's name (the whole string cut at 255 characters), or from a String argument of a syscall (below). So a script
  can give the engine a function name to call later, and a rewriter must keep a function alive if its name is passed as
  a String or stored in data. The `door`, `tbox`, `brk_obj` and `recover` names their handlers start are fixed in the
  exe (the rows above); the other names those objects supply are not [exe].
- **Syscalls that take a function name.** 22 handlers take one from a script argument. That comes from reading the 234
  handlers a profile of all 1,023 marks as possibly reading a String, and the 48 others it shows reaching a name
  function. Every one that runs it starts it through thread start, so the rules above hold: a Pointer parameter refuses
  the call (after a function already running there has been stopped), missing trailing parameters take the defaults and
  then Raw 0, extra arguments are dropped silently. The 32-argument cut belongs to `CALL_SCRIPT`'s entry and is not on
  these paths; Sys 3 keeps at most 64 arguments and Chr 208 at most 32 itself. Arguments marked raw are copied as pushed
  (Calls by name: a String among them is read in the callee's file). "Started" below means thread start: the function
  runs at once until it first waits or ends, and only then does the caller go on [exe].

  Which forms of a name resolve:
  - **All:** the caller's thread is given, so a bare name and `.name` (the current script), `this.`, `map.`, `btl.` and
    `module.function`. `self.` only with an owner id, which only Sys 3 passes (arg 1).
  - **Module:** no thread and no owner id, so only `module.function`, `map.` and `btl.`. `module.function` then sees
    every loaded script.
  - **Module, self:** no thread, an object's id: `module.function`, `map.`, `btl.` and `self.`. A bare name fails.
    `module.function` sees scripts with no owner or that object's.
  - **Module, self, bare:** the same, and a bare name found in the character's main script.
  - **Self rules:** as `self` in Calls by name, for the character the command names. The last step is the resolver with
    that character's thread 0 and no owner id, so bare names, `.name`, `this.`, `map.`, `btl.` and `module.function`
    work there, but a `self.` prefix does not.

  A named thread (Chr 170, Map 36, Map 120's arg 5 below) is refused unless the value's high nibble is non-zero and its
  low nibble is below 11, so 0 is refused; thread 0 is 0xF0.

  Run at once:

  | Syscall | Arg | Forms | When and on which thread | What the function gets |
  |---|---|---|---|---|
  | Sys 3 | 3 | All | started: arg 2 with its high nibble set and low nibble below 11 picks a Manager thread, otherwise it is the Ani thread (0..4) of arg 1's character; arg 1 also filters the owner and is the thread's owner. If that thread is running, a warning is logged and the running function is stopped, its finished hook included | args 4.. raw, arg 4 first |
  | Chr 47 | 3 | Self rules, arg 1's character | started on that character's Ani thread arg 2 (0..4); not if that thread runs the found function, unless arg 6 has bit 0 set | always three: args 4..6 raw; a missing one takes the function's first, second or third default, else Integer 0, 1, 0. Arg 6 is both the third argument and the restart flag |
  | Chr 208 | 2 | Self rules, arg 1's character | synchronously on a temporary thread, the character as owner. Its result is the syscall's REG[0]: Raw 0 if the function is not found, Integer 0 if the character is not | args 3.. raw |
  | Map 20 | 2 | All but `self.` | started on the thread of the map object named by arg 1 (empty: the calling thread's second object slot), unless flags bit 0 is clear and that thread runs a function named exactly as the passed text. A record is also kept and can run it again (below) | Float, Float, Integer flags (args 3..5). Flags bits 1 to 3 take the function's first, second and third defaults, and missing arguments set those bits |
  | Map 81 | 2 | Module | synchronously on a temporary thread, with arg 1's map object (as in Map 20) in the thread's second object slot, not as owner. A record is also kept (below) | none |
  | Btl 26 | 4 | Module, self, bare | synchronously, on the command's first run, the character of battle unit arg 1 as owner, when that unit's state field is 1 or 2 (the other gates are not all read). The command then waits | none |

  Stored, run later:

  | Syscall | Arg | Forms | When and on which thread | What the function gets |
  |---|---|---|---|---|
  | Sys 14 | 1 | All but `self.` | on the calling thread's list (4 at most; a fifth is dropped with no log). When that thread finishes, or a start stops it, each runs on a temporary thread, the thread's owner as owner. On a temporary thread the list is dropped, so a name queued there does not run | none |
  | Chr 108 | 3 (mode 0 and 1) | Module, self | mode 1's name first, else mode 0's, when the player interacts with the character (a reading) or by Event 44, on thread 0, the character as owner. A character whose placement data has a certain flag also runs mode 0's name on thread 0, with Integer 1 | mode 1's: none. Mode 0's: one or two Integers |
  | Chr 170 | 3 (mode 0 and 1) | Module, self | when the player interacts with the character (a reading), in place of the shop and fishing start: thread 0, the character as owner. In mode 1 a non-empty arg 4 with arg 5 above 0 can hold it back | none |
  | Chr 187 | 2, 3 | Module, self, bare | arg 2 once when the character's move is interrupted, arg 3 when it resumes (a reading; the scripts' wrapper names fit); temporary thread, the character as owner | none |
  | Chr 215 | 2 (cut at 63 characters) | Module | when a range test passes (the player coming within arg 3's distance and arg 4's angle: a reading), on thread 0, no owner | one Integer, the character's id |
  | Map 36 | 2 (cut at 63 characters) | Module | when a character touches event box arg 1 (a reading), only while Manager thread 0 is idle and if Map 34 or 35 has set its bit: on Manager thread arg 3, or at once on a temporary thread when arg 3 is -1. With no arg 3 the id is 0, which is refused. No object | none |
  | Map 120 | 4 | Module, self (arg 5 != -1); Module, self, bare (arg 5 = -1) | when a character meets map object arg 1, only while Manager thread 0 is idle: on Manager thread arg 5, or at once on a temporary thread when it is -1. The character is the owner. A record is also kept (below) | one Integer: 1 if the hit check on arg 2's table row and arg 3 returned non-zero (a reading: a skill hit), else 0 |
  | Game 3 | 2 (cut at 255 characters) | Module | when the camp menu closes (a reading from the default's name), in place of `system.OnCampMenuClose`, on the menu's `camp` thread | none |
  | Menu 2 | 5 | Module | at once if the menu has items, and again on the menu's event 0 (the cursor moving: a reading); temporary thread, no owner. Kept as a pointer into the calling script's file | one Integer, the current item's value |

  Kept with no reader found: **Btl 33** keeps args 34, 35 and 36 as pointers into the calling script's file, in a record
  on the battle AI's list (32 at most). Nothing read uses them, so whether arg 34 runs, and how, is not settled.

  Taken but never run:
  - **Chr 150**, arg 2: REG[0] says whether the character has a function of that name (a bare name only: main script,
    then extra scripts).
  - **Chr 37, Chr 38**, arg 2: the function is found by the `self` rules and its call records are walked. The animation
    clips and attachments named in them are loaded (Chr 37) or released (Chr 38), as arg 3's bits select.
  - **Chr 48, Chr 49**, arg 3: compared with the function a character's thread runs. **Sys 37**, arg 3: the same, for a
    Manager thread or a character's thread. The thread holds the function's bare name, so a `module.function` text never
    matches.

  These still matter to a rewriter: a dropped or renamed function changes the answer, or what gets loaded.

  Two map rules:
  - **Records.** Map 20, 81 and 120 also keep a record of the call on a list, skipping one equal to a record already
    there, and replay it later, so the name can run again. On replay Map 20 has no thread, so only the Module forms
    work. Map 120's record keeps a pointer into the calling script's file. When the replay happens is not found.
  - **Event boxes.** Map 0 (arg 2), Map 3, 34, 35, 72 and 83 take an event box's name only to find the box, but the box
    runs functions by that name: `map.<name>`, with no object and no arguments, if the box's own bit 0x800 is set (none
    of these commands sets it); otherwise, for box types 0 and 3, the bare name, looked up in the field map's script
    list and started on thread 0 when that thread is idle. Map 74 adds a script to that list. So an event box's name is
    a function name as well, and Map 83 with an empty name uses the calling thread's current function name.

  Not function names: Debug 10 does nothing (Debug has no handlers). Chr 23, 25, 26, 32, 43, 190, 209, 230 and Map 21
  take animation clip names. Map 39, 40 take object group names, and Map 61, 125, 126 lookpoint names.
- **In `sora2`'s scripts:** 19 of the 22 occur; Chr 215, Map 36 and Map 81 don't. Only Sys 3, Chr 47, Chr 208 and Map 20
  take a constant name at the syscall. The other 15 sit in common functions that pass a parameter through
  (`set_end_hook_function`, `menu_open`, `chr_load_animeclip_by_anifunc`), so the name is at that function's call. No
  constant name uses a form its handler refuses; a few name a function no script has, which fails the same after a
  rebuild [scripts].
- **Names from data tables**, with no script argument involved [exe]:
  - Btl 0, 76, 77: a table row's text, for a battle row type, so only the Module forms; three Integers (the row's id,
    the type and a third value), and the result is read. The table is not identified.
  - Event 1 and 20: a row's name in the event table (Event 20: only `<name>_END`), looked up bare: a `sys_event` row's
    through thread 0, others in the field map's script list. Event 1 also runs `<module>.<name>` from event-table,
    lookpoint and event box rows (the last two by the log messages beside those tables), skipping an empty name and
    `NONE`, with no owner and no arguments.
  - Event 29: the NPC placement data's name, Module forms only, on the character's thread 0, once, with one Integer from
    a row found by the character's id and the map.
  - Event 1 also runs names from the event queue. Chr 181 and Event 44 run names stored by Chr 187 and Chr 108.
- **Defaults an object can replace:** three callers choose, by a field of the object, between a fixed function and a
  name from the object (that the field means "no name of its own" is a reading): `system.ExecuteEventNext` with two
  Integers (a value from the event and a 0/1 flag), `system.TBoxProcess` with one Integer (a value from the treasure
  box) and `system.MinigameFishingStart` with one Integer (the object's index in the event box list). These are
  dispatched to thread 0 [exe].
- **Character battle scripts:** besides its main script, a character has a second script, and at its battle setup the
  engine runs, in that second script, if it has one [exe]:
  1. `SkillTable`, without checking first that it exists
  2. every function whose name *contains* `Routine` (case-sensitive, anywhere in the name, e.g. `Routine01`), in
     function-table order
  3. `SummonTable`, if it exists and is not the first function of the table (index 0 does not run)

  All three kinds run synchronously with no arguments, and their results are ignored. The setup skips all this for
  character ids 0xE9FC..0xEA18 and when one of its flags is set. Afterwards it runs `AniBtlInit`, found by the `self`
  rules, if the character has a main script.
- **`SpecifyMovePos`**, in the same second script: one Integer argument (a 16-bit value the engine holds). The result
  means yes only when it is 1 (an Integer 1, or a Float that truncates to 1); the engine then computes a position. Any
  other value or tag means no [exe].
- **Ani functions:** each character has 5 threads for its "Ani" functions. The engine runs one by name on one of them,
  finding it by the `self` rules, and starts it at once with exactly three arguments: Float, Float, Integer. Its flags
  word [exe]:
  - bit 0 set forces the start; clear refuses it if that thread is already running a function of the same name
  - bits 1, 2, 3: the first, second and third argument take the function's first, second and third default value, if it
    has that many
  - without bit 3, the Integer argument is the flags word itself (30 bits), so an Ani function's third parameter can see
    the engine's flags

  A missing Ani function logs "Ani function not found" when the caller asks for the log. Names the engine uses (bare,
  looked up by the `self` rules): for a field monster, `AniFieldAttack`, or, when a flag of the monster's is set, first
  `btlsys.OnFieldBounceAttack` (no arguments) and then `AniFieldBounceAttack` (third argument Integer 0); `AniBtlWait`
  when the character's main script has a global named `is_armed` whose value is not 0 (an Integer, or a Float
  truncated), else `AniWait`; and `AniBtlInit` (above).

## File-format fields

- **The function table:** the VM uses the 0x20-byte entry as `ED9_FORMAT.md` lays it out [exe].
- `is_common_func` (+0x05) is a byte of its own, not part of a u16 with `byte06`: `CALL` and `RETURN` test only that
  byte. A common function, entered or returned into, does not update the thread's current function index and name;
  nothing else changes. The by-name entry, and a `RETURN` through a script call frame, set them regardless [exe].
- `CALL` and `RETURN` read a function's name only to store it as the current function's; `byte06`, the call-site debug
  records and global names are not read by the VM. `param_count`, the defaults and the parameter flags are read only
  by the by-name paths (Calls by name); the defaults also by the engine's Ani runners and Map 20; `param_count`,
  `default_params_count` and the defaults also by the clip walk (Who reads the call-site records) [exe].
- `dword_14` bit 0 means "compiled with `-s`" (short-circuit evaluation). Script calls and thread start refuse such
  a script, logging that the runtime does not support it; a local `CALL` does not check it [exe].
- **Globals:** the `LOAD_GLOBAL` / `SET_GLOBAL` u32 index is compared, unsigned, with the global count. Past the end,
  `LOAD_GLOBAL` pushes Integer 0 and `SET_GLOBAL` drops the value, with no error [exe]. Each global starts as Integer
  0 if its type byte is 0 and as String `""` otherwise [exe]. The VM and the loader do not use global names; the engine
  reads one by name, `is_armed`, in a character's main script (Engine-called names), so a rewriter must keep that global
  and its name [exe].
- A file without `#scp` still gets a table entry and the load reports success; its fields are never filled (the
  loader's failure is not acted on) [exe].

## Who reads the call-site records

The loader, the name lookup, the function entry, thread start and the VM do not read the call-site debug records. Native
code outside the VM does, in two places, and what it reads changes what the game does, so a rewriter must keep them
correct [exe]. What a record holds: `ED9_FORMAT.md`, Call-site debug records.

- The readers take a String from an argument only if its kind is 0 (constant). A syscall's first two arguments are its
  subsystem and number, and its own arguments follow [exe].
- **The clip walk:** the exe's log calls this script analysis for loading animation clips. It runs nothing. It starts
  from Chr 37 (load) and Chr 38 (release) on arg 2's function, from the character load on two names in a data record the
  character points to, when they are not empty, and from the fishing minigame on five fixed names (Engine-called names).
  For each record of a function [exe]:
  - Types 1 and 2: it goes into the function with that id in the script being walked, or with id 0xFFFFFFFF the one
    named by the first argument, found by the `self` rules (skipped if the lookup finds it in the script being walked).
    A first argument that is not a constant String is skipped without a log.
  - Type 0: if the called function is one of nine known by name hash, it takes names from the constant arguments: clips
    for eight of them, attachments for one. Two of the nine count only when their first argument is the constant 0xFFFE
    or the character's id. The other seven fall back on the function's defaults for arguments the call does not give. A
    non-constant argument logs the message below, except in the attachment function, which is silent, and a bad default
    logs that the script analysis failed and the function's argument order may have changed. The nine are never entered;
    any other function is.
  - Type 3: for Chr 47 only, it walks the function named by arg 3 the same way. If arg 3 is not a constant String it
    logs that it cannot analyse a clip play command using something other than a literal value. Other syscalls are
    skipped.
  - Without a record, what it names is not loaded or released at that point. What the game then does when such a clip
    plays is not read.
- **Mes 0's window:** this measures later messages. It does not give the text: the shown text comes from Mes 0's own
  arguments. Mes 0 looks for its own call among the running function's records: the first type 3 record for Mes 0 or Mes
  19 with the same argument count and a constant String equal to this call's at the same position. One such String is
  enough. The two Values are compared, so the record's String must hold the same offset as the one the code pushes. The
  running function is the thread's current one, which a common function does not update (File-format fields), so a Mes 0
  in a common function would search the function that called it. It then goes through the records after it, unless its
  last scan was for this speaker and stopped past this one. For each Mes 0 or Mes 19 by the same speaker it sets the
  constant Strings (an Integer 10 is a newline) on a second text object and keeps the largest width and height on the
  window, the same two values it later raises from the shown text. It goes into a local call's records and past Chr
  syscalls. It stops at other syscalls, a script call, a new speaker, or a local call to a function with no records,
  unless that function's name starts with `chr` or `emo` (in any case). One function, known by name hash, is skipped.
  With no record found it skips all this and the message is still shown. The two values feed the window's size, and a
  position worked out from it: when a virtual call on the window returns true (what it tests is not read), the size fits
  the larger of them and the shown text; otherwise the shown text alone. So a wrong record can change the window's size
  and position, not its text [exe].
- **So:** a renumbered function needs its record's id changed, and a moved String needs its argument changed. An id at
  or past the function count is not ignored: the walk reads through a null function pointer, which would fault (read in
  the code, not seen at run time). A rename can matter too: the walk knows nine functions by name hash and leaves a
  tenth out, and the scan skips one by hash and tests `chr` and `emo` [exe].
- **Limit:** found by following the callers of the functions read. Of the 14 callers of the by-name entry lookup, Mes
  0's two read the records and three others were read and only test the result. For the other nine, and for a reader
  that gets a function entry another way, a scan of +0x14 finds no use, but it has 726 plain loads in 409 functions and
  cannot tell a function entry from other data. Other readers of Mes 0's second text object weren't searched [exe].
- **The name hashes:** the clip walk knows nine functions by name hash, among them `chr_play_animeclip` and
  `chr_attach_load_model`; the seven others are not identified. The function it does not walk is `EVENT_NEXT`, and the
  one Mes 0's scan skips is `wait_prompt` [scripts].

## What this spec does not say

- **Dynamic behaviour:** what follows an Integer division or `MOD` by zero (the CPU's divide error); what the float a
  thread run gets is; the rounding mode while scripts run (round to nearest assumed); whether the finished hook's second
  call does anything; whether another thread writes a shared script's globals while a syscall waits; whether a function
  the engine calls synchronously ever waits.
- **Syscall handlers:** five were read for their effects. Those that read a String or reach a name function were read
  only for how they use the name, and the rest not at all: their arguments, results and whether they write `REG[0]` or
  script globals are open.
- **Not read yet:** whether anything else outside the VM reads `DEBUG_SET_LINENO`'s value (Sys 3's warning prints the
  field it is stored in); which threads clear bit 0 or bit 1 of their command mask, and whether anything adds bits to a
  command's mask after startup, so what masks 2 and 3 change in play; what sets the thread's flags bit 1; which file a
  character's second script is (the scripts that define `SkillTable` would tell); what the virtual call that lets Mes
  0's window use its measured sizes tests; what the Integers passed to `ExecuteEventNext` and `TBoxProcess` and the Ani
  functions' two Floats mean.
- **Function names, not settled:**
  - No reader found: Btl 33's args 34 to 36; Chr 170's mode 0 args 4 and 5 and the text of mode 1's arg 4 (only whether
    it is empty is used); Chr 108's arg 4 in mode 0; Map 125's two texts. So whether `Shop`, `Rest`, `Roulette` and the
    like are function names is open, and nothing read runs them.
  - What the "when" of Chr 108, 170, 187, 215, Map 36, Game 3 and Menu 2 means in play: these are readings of the code
    around them. How often Chr 215's function starts.
  - When the map records are replayed; Btl 26's gates.
  - Where the names in objects' data come from: Event 29's placement names, the table behind Btl 0, 76 and 77.
  - The table holds every whole string in the exe of the form `module.function`, but the fixed names are still a lower
    bound: bare names have that check only for the `Ani` and `On` prefixes, names built at run time or held in data are
    not strings in the exe, and stored callbacks and indirect calls on these paths weren't followed, 34 of the 38 state
    entries of the object Game 2 builds are not read, and two others run a bare name not read. What makes the game enter
    those states is not read, nor what sets the flag `system.ExecuteWarp` needs when Event 42 runs, nor the one
    `AniLadderDown` needs on one of its three routes.
  - The count of 22 handlers rests on the profile's marks, and the profile can miss a String read in a helper: it missed
    Mes 6, 8 and 13's, which are message text.
  - Names held in data: 17 of the 343 calls to the character-side runners read the name from a field of object or table
    data, and so do the two callers of a small wrapper of the name lookup; where those fields are filled is not read.
  - Whether an earlier battle's per-battle script stays loaded when a battle has no name: the code read has one store to
    it and no clear.
- **Hypotheses not confirmed:** that the first map script is always the map's own; that a script's load category (1
  system, 2 `ani/`, 3 map) is a category at all.
- **Other games:** the `sora1`, `kuro1`, `kuro2` and `kai1` exes.
