# Low Level IL (LLIL) Design

> Status: Implemented. Written 2026-09-28 against the real builder and lifter; it replaces the
> old draft `falcom/ed9/spec/llil_spec.md` (deleted; git history keeps it), whose stack, frame and
> call sections no longer matched the code. See `docs/MLIL_DESIGN.md` for the layer above.

## Role in the Pipeline

```
SCP → Parser → Disassembler → Lifter → LLIL → MLIL → HLIL → Codegen (TypeScript)
```

LLIL is the VM's stack machine made explicit: every push, pop, stack-pointer change, call and branch
of the bytecode becomes an instruction, one bytecode instruction at a time. It recovers no structure
(that is HLIL's job) and names no variables (that is MLIL's). What it adds over the bytecode is
checked bookkeeping: which stack slot each value lives in, which call setup each call consumes, and
the stack state every control-flow edge carries.

The layer is split in two. `ir/llil/` is VM-neutral: the node types, the stack and frame
primitives, and a builder that tracks slots, slot lifetimes and per-edge stack state.
`falcom/ed9/ir/llil/` is the ED9 VM on top of it: the opcode lifter, call setups, the exit rule,
global variables and script calls. Another VM would reuse the first half and bring its own second
half.

## Module Layout

| Path | Responsibility |
| --- | --- |
| `ir/llil/llil.py` | Node model: `LowLevelILOperation`, the `LowLevelILExpr`/`LowLevelILStatement` split, every generic node, `LowLevelILBasicBlock`, `LowLevelILFunction` (instruction numbering, `build_cfg()`), `WORD_SIZE`. |
| `ir/llil/llil_builder.py` | `LowLevelILBuilder`: stack pointer and virtual stack, push/pop, slot storage (`_holds_parameter`), per-edge stack state (`StackSnapshot`, `save_stack_for_offset`, `_record_edge_state`); `LLILFormatter` for the `.llil.asm` text and `.llil.dot` graphs. |
| `falcom/ed9/ir/llil/llil_builder.py` | `FalcomVMBuilder`: one method per VM operation, call setups (`PendingCallSetup`), `EMPTY_STACK_SP`, `finalize()`; `FalcomLLILFormatter`. |
| `falcom/ed9/ir/llil/llil_ext.py` | ED9 nodes: `LowLevelILPushCallerFrame`, `LowLevelILCallScript`, `LowLevelILCallScriptNoReturn`, `LowLevelILGlobalLoad`/`Store`, `LowLevelILDebugLog`. |
| `falcom/ed9/ir/llil/constants.py` | ED9 constants the call setups push: function ID, return-address block, script pointer, script name. |
| `falcom/ed9/ir/llil/vm_lifter.py` | `ED9VMLifter.lift_function()`: the production entry point, one `match` arm per opcode. |
| `ir/llil/lifters/`, `ir/llil/passes/` | Empty placeholder packages. |

## Node Model

Every node derives from `LowLevelILInstruction` (`operation`, `address` = the bytecode offset it
came from, `inst_index`, `options.hidden_for_formatter`). Nodes are either a
`LowLevelILExpr` (a value, usable as an operand and on the virtual stack) or a
`LowLevelILStatement` (an effect). The builder refuses a statement where a value is expected, and
its virtual stack accepts only expressions.

| Category | Nodes |
| --- | --- |
| Stack | `LowLevelILStackStore(value, offset, slot_index)`, `LowLevelILStackLoad(offset, slot_index)`, `LowLevelILSpAdd(delta)`, `LowLevelILStackAddr(slot_index)` |
| Frame (parameters) | `LowLevelILFrameStore(value, offset)`, `LowLevelILFrameLoad(offset)`, `LowLevelILFrameAddr(offset)` |
| Pointer (runtime address) | `LowLevelILLoad(src)` (`*src`), `LowLevelILStore(dest, value)` (`*dest = value`) |
| Registers | `LowLevelILRegStore(reg_index, value)`, `LowLevelILRegLoad(reg_index)` |
| Globals (ED9) | `LowLevelILGlobalStore(index, value)`, `LowLevelILGlobalLoad(index)` |
| Arithmetic / compare / logic | `LowLevelILBinaryOp` subclasses (`Add`, `Sub`, `Mul`, `Div`, `Mod`, `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`, bitwise `And`/`Or`, eager `LogicalAnd`/`LogicalOr`); `LowLevelILUnaryOp` subclasses (`Neg`, `BitwiseNot`, `TestZero`) |
| Terminals | `LowLevelILGoto` (alias `LowLevelILJmp`), `LowLevelILIf(condition, true_target, false_target)`, `LowLevelILCall(target, return_target, args, returns)`, `LowLevelILRet()`; ED9 `LowLevelILCallScript`, `LowLevelILCallScriptNoReturn` (both subclass `LowLevelILCall`) |
| Other | `LowLevelILConst(value, is_hex, is_raw)`, `LowLevelILSyscall(subsystem, cmd, argc, args)`, `LowLevelILDebug('line', n)` (from `DEBUG_SET_LINENO`), `LowLevelILDebugLog(args)` |

Offsets are **bytes** (`slot * WORD_SIZE`); `slot_index` is an absolute slot number. Stack offsets
count from the current `sp`, frame offsets from the frame base.

**Terminals.** A block ends with exactly one terminal, as its last instruction:
`LowLevelILBasicBlock.add_instruction` raises when the block already ends with one. Conditional
jumps become `If(Eq(value, 0), ...)`: `POP_JMP_ZERO` takes the targets as given, `POP_JMP_NOT_ZERO`
swaps them. A call is a terminal too - its block ends at the call and the return block continues
after it (MLIL's `BlockMergePass` splices the two back together).

**Instruction numbering.** `inst_index` is -1 until the instruction joins a block of a function,
which gives it the next number; adding an instruction that already has one raises (no node is
shared between blocks). `finalize()` renumbers everything in block order
(`reindex_in_block_order()`), and `get_instruction_by_index()`, `get_instruction_block_by_index()`
and `iter_instructions()` look them up. Each MLIL statement's `llil_index` is one of these numbers.

## Stack Model

**Slots.** The stack is a list of word-sized slots numbered from 0; a push writes slot `sp` and
then increments `sp`. A function starts with `sp = num_params` and the frame base (`fp`) at slot
0: slots `0 .. num_params - 1` hold the caller's arguments, and nothing is on the virtual stack yet
(`_seed_entry_state`). MLIL names the parameters `arg1 .. argN` (`docs/MLIL_GUIDE.md`, Variable
Model).

**Push and pop.** `push(value)` emits `StackStore(value, offset 0, slot sp)` then `SpAdd(+1)`, and
puts a `StackLoad` of that slot on the virtual stack - not the value itself. A consumer therefore
reads "the value in slot k", as the VM does; MLIL's SSA passes merge and propagate the values.
`pop()` emits `SpAdd(-1)` and returns the virtual stack's top entry. `POP` / `POP_N` emit one
`SpAdd(-n)` and drop the entries at or above the new `sp`; what remains must be one contiguous run
of slots ending just below `sp`, or the builder raises.

**Stack-pointer changes.** Inside a block every `sp` change is an explicit `SpAdd`
(`emit_sp_add`). Two changes emit none, on purpose:
- after a call, the builder drops the call's setup and arguments from its tracked `sp` and virtual
  stack (`_cleanup_stack`): the callee removes them, so the caller's bytecode has no POP for them.
  `CALL_SCRIPT_NO_RETURN` drops its arguments the same way;
- at a block start, `begin_block` restores the state recorded for that block (see Control Flow).

**Reads, stores and addresses by slot.** `LOAD_STACK`, `POP_TO` and `PUSH_STACK_OFFSET` name a slot
by its byte offset from `sp`. Reading a slot at or above `sp`, or taking its address, raises
`NotImplementedError` (it holds no live value); a store there is an ordinary `StackStore`. A store
into a slot the virtual stack tracks replaces that entry with a fresh `StackLoad`
(`_refresh_stored_slot`), so a check that compares entries by identity - a call setup's - sees the
overwrite.

**Parameter slots and their lifetime.** A slot is frame storage only while it still holds the
caller's argument (`_holds_parameter`): it is a parameter slot, it lies below `sp`, and no virtual
stack entry tracks it. Then reads, stores and addresses are `FrameLoad`/`FrameStore`/`FrameAddr`
(MLIL `argN`). Once the function pops its parameters, a push into the same slot starts a new
lifetime and every access to it is a `StackLoad`/`StackStore`/`StackAddr` (MLIL `var_sN`) - the
tail-call idiom `SET_REG ...; POP frame; GET_REG ...; CALL_SCRIPT_NO_RETURN` does exactly this.
Pointer access (`LOAD_STACK_DEREF`, `POP_TO_DEREF`) goes only through a slot still holding a
caller's argument; any other pointer may point into the function's own frame, and raises.

## Calls and Exits (ED9)

**Local call** - `PUSH_CURRENT_FUNC_ID`, `PUSH_RET_ADDR <block>`, the arguments, `CALL <func id>`:
- `PUSH_CURRENT_FUNC_ID` opens a `PendingCallSetup` (kind `LOCAL`) holding the `sp` before the
  call; `PUSH_RET_ADDR` must land directly above the function ID and completes the setup with its
  return block.
- `CALL` needs the innermost pending setup to be a complete local one whose pushed slots are all
  still in place (not popped, re-pushed or overwritten). It emits `LowLevelILCall` with the callee
  name, the return block and the arguments (the top `sp - sp_before_call - LOCAL_SETUP_SLOTS`
  virtual stack entries, last pushed first), then drops the setup and the arguments, pops the
  setup record and records the return edge.

**Script call** - `PUSH_CALLER_FRAME <block>`, the arguments, `CALL_SCRIPT module func argc`:
`PUSH_CALLER_FRAME` pushes the function ID, the return address, the script pointer (two slots) and
the script name - `CALLER_FRAME_SLOTS` = 5 slots - and opens a `SCRIPT` setup. `CALL_SCRIPT` needs
`sp` to be exactly `sp_before_call + CALLER_FRAME_SLOTS + argc`, emits `LowLevelILCallScript` and
cleans up like a local call. The `LowLevelILPushCallerFrame` node is kept on the setup and on the
call (`caller_frame`); it is never added to a block.

Setups nest (an argument may contain another call), so the builder keeps a stack of them,
innermost last, and they are part of the stack state an edge carries: two arms of a branch each see
the setups pushed before it.

**Tail call** - `CALL_SCRIPT_NO_RETURN module func argc`: no setup precedes it. It emits
`LowLevelILCallScriptNoReturn` (`returns = False`, no return block, no CFG edge) and drops its
arguments; `sp` must then be `EMPTY_STACK_SP` (0) and no setup may be pending.

**Return.** `RETURN` requires `sp == EMPTY_STACK_SP` and no pending setup: a function pops its own
parameters before it returns, so every real exit leaves its stack empty.
`LowLevelILRet` carries no value - a function's result travels in register 0, which calls write and
`RETURN` reads (`RESULT_REG_INDEX`, `falcom/ed9/ir/mlil/mlil_translator.py`).

**Not terminals:** `SYSCALL` reads its `argc` arguments from the top of the stack without popping
them and leaves `sp` unchanged; `DEBUG_LOG argc` reads its arguments (message first), then pops
them.

## Control Flow and Per-Edge Stack State

`ED9VMLifter.lift_function()` creates every reachable block first, in address order (so block
indices follow addresses), then lifts them in reverse post-order from the entry, so every block
but the entry is lifted after at least one of its predecessors. `begin_block` restores the stack
state recorded for the block and raises if there is none (no lifted edge reaches it).

Every terminal records the state its edge carries into the target (`_record_edge_state`): jumps and
branches when they are emitted, calls after their cleanup (the return edge). The first record for a
block becomes its state; every later one must have the same **shape** - the same `sp`, the same
tracked slots and, for ED9, the same pending setups with the same slots still in place
(`FalcomStackSnapshot.shape()`). Values may differ between edges: MLIL's SSA merges them. The entry
state is seeded, not recorded from an edge, so a back edge into the entry must match it too. The
parser's disassembly-time stack simulation checks the same stack heights earlier
(`docs/ARCHITECTURE.md`, Layer 2).

`FalcomVMBuilder.finalize()` then:
1. `build_cfg()` - recomputes every edge from the terminals, checking everything before an edge
   changes: the entry block must exist, no entry or edge target may be empty, an `If` needs both
   targets, a returning call needs a return block and a non-returning one must not have one, and
   every target must be a block of this function;
2. requires the recorded edges to be exactly the CFG's edges, so every real edge had its state
   checked;
3. renumbers the instructions in block order.

Each block also keeps `sp_in` / `sp_out`, the `sp` at its start and end.

## Formatting

`falcom/ed9/scena2py.py` writes `FalcomLLILFormatter.format_llil_function()` to `<script>.llil.asm`:
one header per block (`block_N(0xADDR), label, [sp = N]`, plus `fp` on the entry) and each
instruction in an expanded pseudo-code form (`STACK[sp] = ...`, `STACK[--sp]`). String constants
print single-quoted with Python escapes (`quote_string`), so a quote or line break stays inside
its token. A float prints through `str()`: a `SourceFloat` (`ir/core/il_literals.py`; the Falcom lifter
keeps the exact decoded value and attaches the `.py`'s spelling, `ScpValue.float_literal`) prints that
text, a plain float its exact `repr`. A pushed `SourceFloat` also gets its bits from
`FalcomLLILFormatter`: `STACK[sp] = 27.2 ; [5] f32 0x41D99998, raw 0x90766666` (`f32` is what the VM
computes with, `raw` the stored word). `hidden_for_formatter` drops the `SpAdd` lines that form
already spells out. `to_dot()` draws a function's CFG (`.llil.dot`).

## Testing

`tests/test_llil_build_cfg.py` (CFG construction), `tests/test_llil_call_setup.py` (call setups),
`tests/test_llil_call_script_no_return.py`, `tests/test_llil_deref.py` (pointer opcodes),
`tests/test_llil_frame_addr.py` / `tests/test_llil_frame_store.py` / `tests/test_llil_slot_lifetime.py`
(parameter slots), `tests/test_llil_lift_order.py` (lifting order, per-edge state, numbering),
`tests/test_llil_stack_sync.py` (`POP`/`POP_N` and the virtual stack), and
`tests/test_scp_stack_simulation.py` (the parser's simulation). `demos/llil_demo.py` builds small
functions by hand.

## Open Items

- Blocks are meant to hold statements, but `LowLevelILBasicBlock.add_instruction` accepts any
  instruction, and the builder's binary/unary operations have a `push = False` mode that appends
  the bare expression. The lifter never uses it.
- `ir/llil/lifters/` and `ir/llil/passes/` are empty placeholder packages.
