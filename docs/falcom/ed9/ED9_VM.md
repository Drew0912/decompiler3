# ED9 VM

> Status: current. The rules of the ED9 script VM: what each opcode does, the stack and its frames, registers,
> syscalls, arithmetic, truth, calls by name and the functions the engine calls. The file format and how
> decompiler3 reads it: `docs/falcom/ed9/ED9_FORMAT.md`.

**Source.** A static read of `sora_2nd.exe` 1.5.0.0 (Trails in the Sky 2nd Chapter, the game of the `sora2` corpus;
SHA-256 `CEAED8DA75BC1B1A32BAB2694D2CFF816DFB58A4AB16693041DCD7EEE0E258F4`), most rules confirmed by a second,
independent read. Nothing here is traced in the running game, and the other four games' exes are unread (their
scripts share the format, `ED9_FORMAT.md`). The reads, with instruction addresses, are kept outside the repo.

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
  script file) and flags: bit 0 running, bit 2 syscall pending, bit 3 inside `CALL_SCRIPT`. Flags 0 means stopped,
  and the thread's finished hook then runs [exe].
- The loop fetches one opcode byte at PC and dispatches over 0x00-0x28. It goes on while the thread runs, no syscall
  is pending and PC is below the file's size [exe].
- An opcode above 0x28 stops the thread *without* the finished hook; every other error runs the hook [exe].
- PC is checked only at the loop's head and after each instruction, against the size of the whole file, not the end
  of the code: a jump into the string pool runs data. Operand bytes are not checked, so a truncated last instruction
  reads past the code [exe].
- Pushes are bound-checked (an overflow stops the thread); pops are never checked for underflow [exe].
- An operation on types it cannot handle logs a type error ("trying to operate on types that can't be operated on")
  and execution goes on [exe].
- While a syscall is pending (flags bit 2), each run of the thread calls the syscall handler again instead of
  fetching an opcode, then returns [exe].

## Opcodes and operands

- 41 opcodes, 0x00-0x28. Their operand formats and stack effects are decompiler3's opcode table
  (`falcom/ed9/disasm/ed9_optable.py`, `falcom/ed9/disasm/stack_effects.py`), but for the lines below [scripts].
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
- `CALL` reads only its u16 operand, the function index: it checks it against the function count and sets PC to the
  entry's code offset. Unless the entry's `is_common_func` byte is set, it records the index and name as the current
  function. It pushes and pops nothing, ignores `param_count` and the defaults, and does not read the pushed function
  id [exe].
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
- On success it pops nothing and bit 3 stays set; the callee pops the arguments, and its `RETURN` pops the 5-slot
  frame [exe].
- On failure it pops argc slots, clears bit 3 and runs `RETURN`, which pops the caller frame and resumes at the
  frame's return PC: a failed call is skipped, and `REG[0]` is unchanged [exe].

**Tail call** (`CALL_SCRIPT_NO_RETURN`):
- It copies the top argc values (at most 32 are kept), sets sp = 0, pushes `0x0FFFFFFF`, re-pushes the arguments in
  their original order and calls call-by-name. It does not touch flags bit 3, so entering the function runs the
  finished hook once first [exe].
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
  with every bit set. Every command's mask is 1, except Sys 17 and Portrait 0 and 9, which are 2, and all of Debug,
  which is 0 (Debug has no handlers) [exe].
- Handlers read their arguments in place: argument k at sp - 4k. No handler pops; a later `POP` removes them [exe].
  The compiled scripts pop them right after the syscall [compiler].
- argc is checked per argument: a missing argument gets a default (Integer 0 in the handlers read) [exe].
- Each handler decodes its own arguments (tag tests, then float / int conversion); Strings resolve in the current
  script [exe].
- A handler's result is a tagged word written to `REG[0]`, only from inside a `SYSCALL`, and only when it has a
  result: a handler with none leaves `REG[0]` holding an older value (in the handlers read) [exe].
- A handler can suspend the thread: while flags bit 2 is set, each run of the thread re-calls the handler instead of
  fetching an opcode, and other threads and the engine run in between. Handlers set the bit themselves (Sys 17 does,
  while the thread's "job posted" flag is set) [exe].
- The handlers read write no script global and nothing through a pointer argument. Sys 12 reads the engine's
  256-entry "global work" array, engine-wide variables separate from script globals (an index above 0xFF logs and
  reads entry 0) [exe].

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
  (`"a" + "b"` is Integer 0; `x / "a"` divides by zero). `MOD`, bitwise ops, `NOT`, `NEG` and `EZ` need Integers
  (some accept a Float), else a type error and the operand unchanged [exe].

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
| `self` | the object for the caller's character id: its main script, its extra scripts, the common script `ani/common`, then the `module.function` resolver |
| `map` | the field map's script list (8 scripts at most): the first one that has the function wins. If none has it, the search goes on to the table, which finds nothing unless some script is named `map` |
| `btl` | the battle's one script, returned even when it lacks the function |
| any other name | the table of loaded scripts, by the file's base name (`common` for `ani/common.dat`); an entry matches if its owner id is 0xFFFF or the caller's id |

- The four special names are compared including the terminating NUL, so they must match exactly. `common` is not a
  special case, just a loaded script with that name. Scripts are never loaded on demand [exe].
- **The `module.function` resolver** (the engine's calls) takes one string, splits it at the first `.` (the module
  part at most 31 characters) and applies the same module rules; with no `.`, the whole string is a function in the
  current script [exe].
- **The function lookup:** `name_hash` is the bitwise NOT of the standard CRC-32 (`~crc32`; the empty name gives
  0xFFFFFFFF) [scripts]. The function table is scanned linearly, comparing `name_hash` first and the name text second,
  so the table's order does not matter; the index found is thrown away and the function looked up again by name
  [exe]. The compiled scripts sort the table by name [compiler].
- **Failures:** an unknown script returns false silently; an unknown function logs "function not found" and returns
  false. False makes `CALL_SCRIPT` pop the arguments and return [exe].
- **Entering the function** (script calls, tail calls and the engine's calls alike) [exe]:
  - It refuses a script whose header `dword_14` has bit 0 set and a function with a Pointer parameter; both are logged
    and return false.
  - When argc equals `param_count`, the arguments stay as they are. Otherwise it pops them (keeping at most 32), then
    pushes the defaults for the missing trailing parameters, the last default deepest; Integer 0 for any parameter
    still missing (Raw 0 at thread start), logging "too few arguments"; then the given arguments, back on top. Extra
    trailing arguments are dropped, logging "too many arguments" (silently at thread start). So the callee always
    gets exactly `param_count` arguments.
  - The Value / Offset / Nullable bits of the parameter flags are neither checked nor converted.
  - If the thread is running and bit 3 is clear (a tail call, or an engine call on a running thread), it first stops
    the thread and runs the finished hook. Then it clears bit 3, sets the callee's script, PC and current function
    (always: no `is_common_func` test here) and sets flags = 1.
- String arguments are not converted: the words are copied raw, so a String passed into another script's function is
  read as an offset into the callee's file, the wrong text [exe].
- So trailing defaults can be left out in script calls and engine calls, but not in local `CALL`s, which ignore
  parameters [exe].

## Threads and the engine's calls

- Globals live in the script object (one per loaded file and owner), not in the thread. A `CALL_SCRIPT` callee runs
  with its own file's object and sees that file's globals; `RETURN` restores the caller's [exe].
- The 18 system scripts are loaded once and shared, so every thread that runs or calls into one uses the same object
  and its globals: `scena/system`, `system2`, `sound`, `npc_setting`, `sys_event`, `talk_common`; `ani/btlcom`,
  `btlmagic`, `btlitem`, `btlsupport`, `btlpom_common`, `common`, `sound_ani`; `obj/door`, `brk_obj`, `tbox`,
  `recover`; `battle/btlsys` [exe].
- Thread start stops a running thread (finished hook), sets the script, PC = 0 and sp = 0, pushes the `0x0FFFFFFF`
  marker (if the stack has at least 4 bytes), then the defaults and arguments (Calls by name), sets flags = 1 and runs
  the thread once at once [exe].
- The engine's synchronous calls run the function on a temporary thread and take `REG[0]` as the result (Integer 0
  if the start fails); the thread is then destroyed, and calls still queued on it are dropped without running [exe].
- The engine's dispatch starts the function on one of the 11 named script threads (thread 0 for most callers),
  at once, like thread start: nothing is queued. The function runs until it ends or waits, and a wait goes on in
  that thread's later runs. The dispatch is refused if that thread has a job posted, or if the function is not found
  [exe].
- Each run of a thread stores a float argument in the thread; it behaves like a time step: the caller passes its own
  float straight on and can add it to a running total [exe].

## Engine-called names

The engine calls script functions by name; those names are part of the contract between the engine and the scripts.
A function missing or renamed only logs "function not found", so dropping one fails silently in game [exe].

**Fixed `module.function` names** (141; a lower bound, see the end of this section) [exe]:

| Module | Functions |
|---|---|
| `system` (62) | `ApplyPartyOutMembers`, `EventItemCheck`, `ExecuteEventNext`, `ExecuteWarp`, `FieldItemGet`, `FoodBuffEffectPlay`, `FoodBuffEffectStop`, `GetMapEnvironmentID`, `GetNowLoadingType`, `GetShopOKVoice`, `GetShopOpenVoice`, `GetShopOpenVoiceGuest`, `HealObjProcess`, `InitGame`, `MapJumpAfterCallScript`, `MapJumpCallScript`, `MapJumpState`, `MapJumpVoice`, `MapReinit`, `MinigameFishingStart`, `NewGame`, `OnAddMedal`, `OnCampDecidedTab`, `OnCampMenuClose`, `OnCampMenuOpen`, `OnCampOrbmentAutoEquipStart`, `OnCampOrbmentChangeMenu`, `OnCampOrbmentChangeTab`, `OnCampOrbmentEquipQuartz`, `OnCampTopChangeMenu`, `OnChangePlace`, `OnCheckTalkMode`, `OnChrEventEntry`, `OnChrEventExit`, `OnItemCountChanged`, `OnLeaderChanged`, `OnMainNoteClose`, `OnMapInit`, `OnNoteMenuClose`, `OnNoteMenuOpen`, `OnShopClose`, `OnShopCloseOrbmentSlotMessage`, `OnShopGetItem`, `OnShopOpen`, `OnShopTopMenu`, `PlayCookSupportGetVoice`, `PlayCookVoice`, `PlayFishSpotVoice`, `PlayFoodEatVoice`, `PlayQuestBoardVoice`, `PlayQuestStartVoice`, `PlayReportVoice`, `QuestBoardTutorial`, `QuestBoardTutorialEnd`, `QuestEndVoiceCheck`, `QuestFailedProcess`, `SetRandomMonstetFlag`, `SetupCostumeFlags`, `SetupReplacePathInfo`, `ShopMenuOpen`, `TBoxProcess`, `UnLockRecipe` |
| `btlsys` (28) | `BattleBraveAttack`, `BattleCommandArts`, `BattleCommandBegin`, `BattleCommandCraft`, `BattleCommandItem`, `BattleCommandSub`, `BattleDead`, `BattleEnd`, `BattleGameOverClose`, `BattleGameOverMenu`, `BattleGameOverOpen`, `BattleGameOverRelease`, `BattleInit`, `BattlePreEnd`, `BattleResultEnd`, `BattleSetting`, `BattleStart`, `BattleTurnBegin`, `BattleTurnEnd`, `CanFullBurst`, `CanRestoreHelpFlagOnRetry`, `FieldBattleRetry`, `NextBattle`, `OnFieldBounceAttack`, `OnFieldClingAttack`, `OnStatueAIActive`, `OnSubInfoOpened`, `PlayCommandPromptAVoice` |
| `btlcom` (26) | `AniBtlArtsFailed`, `AniBtlAttrAbsorbEffect`, `AniBtlBraveAttackBurst`, `AniBtlBraveAttackChase`, `AniBtlBraveAttackCutinSetup`, `AniBtlBraveAttackEffect`, `AniBtlBraveAttackFullBurst`, `AniBtlBraveAttackOpen`, `AniBtlBraveAttackRush`, `AniBtlBuffEffect`, `AniBtlConditionCantAction`, `AniBtlDamageTargetsSkip`, `AniBtlEncount`, `AniBtlEnd`, `AniBtlOnceResurectItem`, `AniBtlOverDriveButton`, `AniBtlPauseFilterOff`, `AniBtlPinchEffect`, `AniBtlSkipInit`, `AniBtlStart`, `AttackCritical`, `FAttackBounce`, `FAttackCritical`, `OnAttackHit`, `OnFieldBraveChargeEnd`, `ShowUnlockRecipeMessage` |
| `sound` (11) | `BattleTalkEndSound`, `BattleTalkStartSound`, `ChangeEnvSE`, `Init`, `InitEnvSE`, `LogMenuCloseSound`, `LogMenuOpenSound`, `MapBBGMChange`, `MenuCloseSound`, `MenuOpenSound`, `OnMapReinit` |
| `fishing` (10) | `EventCheck`, `FishingFailed`, `FishingHookFailed`, `FishingMessage`, `FishingNoFish`, `PlayFishingVoice`, `ResultEnd`, `ResultStart`, `SetFirstCamera`, `SetSecondCamera` |
| `map` (2) | `ExtraMovie`, `Get1stClearReward` |
| `sound_ani` (2) | `SeBattleConfigDefault`, `SeBattleConfigScraftSkip` |

- **Bare names** looked up in a given script: `Init`, `BattleInit`, `BattleSetting`, `BattleDead`,
  `BattleInterrupSkillEnd`, `SkillTable`, `SummonTable`, `SpecifyMovePos` [exe].
- The spellings must match exactly, including what look like typos (`AniBtlEncount`, `AniBtlOnceResurectItem`,
  `SetRandomMonstetFlag`, `BattleInterrupSkillEnd`, `UnLockRecipe`) [exe].
- **Known arguments:** after a map's scripts load, `Init` in the *first* map script runs with no arguments (no
  existence check), then `system.OnMapInit` with one Integer (1 if the map's load mode is 1, else 0); later
  `system.GetMapEnvironmentID()`'s result is used as an integer (an Integer as it is, a Float truncated, anything else
  or a failed call 0). With an empty map-script list, `Init` and `OnMapInit` are both skipped. On a character's
  battle death, `btlsys.BattleDead` runs with one Integer (the character's id), then the per-battle script's
  `BattleDead`, if it has one, with the same argument [exe].
- `fishing` and the scripts `minigame/blackjack`, `poker`, `roulette`, `slot` are loaded per scene; `fishing` is not
  one of the 18 system scripts [exe].
- **Character scripts:** a Chr syscall (arguments: a character id, then a script name) loads `ani/<name>` and appends
  it to that character's extra scripts, the list `this` searches [exe].
- **Defaults an object can replace:** three callers run a fixed function when the object does not name its own:
  `system.ExecuteEventNext` with two Integers (a value from the event and a 0/1 flag), `system.TBoxProcess` with one
  Integer (a value from the treasure box) and `system.MinigameFishingStart` with one Integer (an index). They are
  dispatched to thread 0 [exe].
- **Character battle scripts:** besides its main script, a character has a second script, and at its battle setup
  the engine runs, in that second script, synchronously, with no arguments and the results ignored [exe]:
  1. `SkillTable`, without checking first that it exists
  2. every function whose name *contains* `Routine` (case-sensitive, anywhere in the name), in function-table order
  3. `SummonTable`, if it exists and is not the first function of the table (index 0 does not run)

  The setup skips all this for character ids 0xE9FC..0xEA18 and when one of its flags is set. Afterwards it runs
  `AniBtlInit`, found by the `self` rules, if the character has a main script.
- **`SpecifyMovePos`**, in the same second script: one Integer argument (a 16-bit value the engine holds). The result
  means yes only when it is 1 (an Integer 1, or a Float that truncates to 1) [exe].
- **Ani functions:** each character has 5 threads for its Ani functions. The engine runs one by name on one of them,
  found by the `self` rules, and starts it at once with exactly three arguments: Float, Float, Integer. Its flags
  word: bit 0 set forces the start (clear refuses it if that thread already runs a function of the same name); bits
  1, 2, 3 make the first, second and third argument the function's own default for that parameter, if it has one;
  without bit 3 the Integer argument is the flags word itself. A missing Ani function logs "Ani function not found".
  Names the engine uses (bare, by the `self` rules): `AniFieldAttack` for a field monster, or, when a flag of the
  monster's is set, first `btlsys.OnFieldBounceAttack` (no arguments) and then `AniFieldBounceAttack` (third argument
  Integer 0); `AniBtlWait` or `AniWait`; and `AniBtlInit` (above) [exe].
- **Names the engine does not hold:** at many call sites the name is not in the exe. It comes from a game object
  (characters, events, treasure boxes, break objects, map objects), from `map.<name>` built from an object's name (cut
  at 255 characters), or from a String a script passes to a syscall handler; which handlers take one is not
  identified yet. So a script can give the engine a function name to call later, and a function must stay alive if
  its name is passed as a String or stored in data [exe].

## File-format fields

- **The function table:** the VM uses the 0x20-byte entry as `ED9_FORMAT.md` lays it out [exe].
- `is_common_func` (+0x05) is a byte of its own, not part of a u16 with `byte06`: `CALL` and `RETURN` test only that
  byte. A common function, entered or returned into, does not update the thread's current function index and name;
  nothing else changes. The by-name entry sets them regardless [exe].
- `byte06`, the call-site debug records, global names and function names are not read by the VM (a function's name
  only by the lookup by name); `param_count`, the defaults and the parameter flags only by the by-name paths (Calls by
  name) [exe].
- `dword_14` bit 0 means "compiled with `-s`" (short-circuit evaluation). Script calls and thread start refuse such
  a script, logging that the runtime does not support it; a local `CALL` does not check it [exe].
- **Globals:** the `LOAD_GLOBAL` / `SET_GLOBAL` u32 index is compared, unsigned, with the global count. Past the end,
  `LOAD_GLOBAL` pushes Integer 0 and `SET_GLOBAL` drops the value, with no error [exe]. Each global starts as Integer
  0 if its type byte is 0 and as String `""` otherwise [exe].
- A file without `#scp` is still loaded and registered (the loader's failure is not acted on) [exe].
- Nothing in the loader, the name lookup, the function entry, thread start or the VM reads the call-site debug
  records; a reader elsewhere (a debugger, a crash reporter) is not ruled out [exe].

## What this spec does not say

- **Dynamic behaviour:** what follows an Integer division or `MOD` by zero (the CPU's divide error); what the float a
  thread run gets is; the rounding mode while scripts run (round to nearest assumed); whether the finished hook's
  second call does anything; whether another thread writes a shared script's globals while a syscall waits; whether a
  function the engine calls synchronously ever waits.
- **Syscall handlers:** all but five are unread: their arguments, results, whether they write `REG[0]` or script
  globals, and which take a function name.
- **Where names come from:** which file a character's second script is; where the objects' function names come from;
  what the Integers passed to `ExecuteEventNext`, `TBoxProcess` and `MinigameFishingStart` and the Ani functions' two
  Floats mean.
- **Hypotheses not confirmed:** that the first map script is always the map's own; that a script's load category (1
  system, 2 `ani/`, 3 map) is a category at all.
- **Other games:** the `sora1`, `kuro1`, `kuro2` and `kai1` exes.
