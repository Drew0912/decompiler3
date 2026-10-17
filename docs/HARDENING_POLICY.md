# Hardening policy (threat model)

Which inputs deserve a test, a guard or a bug finding. Read this before any review, test-writing, hardening or
bug-hunt work, and put it in every brief for that work.

## Where input comes from

- **Game scripts**: real `.dat` bytecode from the shipped games, read by the parser.
- **User edits**: today the LLIL DSL `.py` output and its hook files; later the HLIL DSL (planned), which lowers to
  LLIL DSL text. Both reach the game through `ScpWriter` and its compile check.

## In scope

- Any real game script.
- **Reasonable LLIL**: the idioms the decompiler's own `.py` output uses, recombined the way an HLIL edit would:
  constants, strings and floats changed; statements added, removed or moved; new `if`/`else`, loops, switches,
  returns, calls, locals, parameters and globals.
- **Plausible editing mistakes**: an unbalanced stack on one path, a wrong argument count, a missing `RETURN`, an
  undefined label, a duplicate name. These must fail with an error that names the script line.

## Out of scope

- Bytes no writer emits; corrupted or malformed `.dat` files.
- Misuse of internal APIs; IR objects that only tests build.
- Constructs nothing in the repo uses: custom-equality or property-overriding subclasses, shallow copies, hostile
  containers, rewritten public fields.
- Bugs in our own tools that an existing gate already catches (the test suite, the logic and byte-exact round trips,
  `tools/ir_semantic_validator.py`, `tools/scp_roundtrip_validator.py`, the writer's compile check).
- The same condition checked again at a later layer. Keep the check where the input enters (the parser for game
  scripts, `ScpWriter`'s compile check for edits), which can name the byte offset or script line; a later layer
  repeats it only if some path reaches that layer without passing the first check.

## Priority

1. A reasonable edit that compiles or decompiles to wrong game logic.
2. A plausible mistake that passes silently or fails with a misleading error.
3. Untested code on the edit path.

## Judging a finding

For each finding, answer explicitly: can this happen through a user edit or a source byte, or only through a bug in
our own code?

- **Only an impossible input reaches it**: decline as out of contract. Do not add type contracts, identity checks or
  read-only machinery to close it.
- **Only a future edit of code the change does not touch could break it**: decline the test. Example: a review asks
  for a test pinning a helper's output, but the step under review does not modify that helper.
- **A slip in the new code that real bytecode or a user edit can reach, and no gate catches**: keep; add the test.
- **A slip in the new code that a gate already catches**: no new test. Check it once in that step: run the gate, then
  run it against a deliberately broken copy (a mutant) to prove the gate catches it.
- A test is redundant only if a mutation run shows another test already fails on the same mutant.
