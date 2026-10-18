
# Coding Style Guide

## Rules

### -0.5. Git Commit Policy
NEVER auto-commit. Only create commits when explicitly requested by user.

### -0.25. Code Modification Policy
NEVER modify code during discussion. Only modify code AFTER user explicitly confirms the approach.

### -0.1. decompiler2 Submodule Access
NEVER read, search, or reference files under the `decompiler2` submodule unless the user explicitly says to use it in the current request. If you think looking at `decompiler2` would help, ASK the user first and wait for confirmation before accessing it.

### -0.05. Codex (reviews only)
Codex only reviews; it never edits or commits. Reviews in `notes/codex_rules.md` (read it before invoking):
**IR change review** (correctness, condensability and generic/game-specific placement of `ir/` and `falcom/ed9/ir/`
changes; required, and a plan touching those folders includes it as a step), **plan review** (adversarial, before a
plan's first implementation step) and **user-asked review**. Ask before invoking any of them, and name the review
when you do (e.g. "Invoking Codex - plan review").

### -0.045. Corpus Runs
Read `notes/corpus_run_rules.md` before any corpus-wide run (census, regression dump, round-trip validator over many files).

### -0.04. Root-Cause Fixes in `ir/`
When a bug is found while editing `ir/` (LLIL/MLIL/HLIL structures and passes), prioritize fixing the root cause over patching just the reported symptom. If a genuine root-cause fix isn't achievable, fix the version that catches the most cases the underlying gap can produce — never the narrowest guard clause scoped to the one reported instance; that's the outcome to avoid even as a fallback, not a shortcut to take. This directory's passes tend to hand-roll their own tree traversal, and that produces two recurring shapes of the same problem: a walker missing a node type — not a one-off mistake at that call site, but a class of bug that recurs across every hand-rolled walker in the file, so prefer closing the class (e.g. a shared traversal helper every predicate/collector is built on) over a narrow guard clause that only fixes the specific finding; and two related walkers (a detector and a rewriter, e.g.) that must agree on traversal shape but are maintained independently — fixing one to produce the right output for the reported case without making it structurally match the other leaves the same asymmetry free to resurface the next time either is edited alone, so prefer making them share the same traversal shape, not just the same answer for one input. Not every `ir/` bug is a traversal-coverage bug — some are genuine logic gaps (wrong equality check, missing case) that a shared walker would not have caught either; for those, still ask what the underlying gap is before patching, rather than defaulting to the narrowest possible fix.

### -0.03. Round-Trip Policy
Required: logic round trip — decompile (`round_trip=False`) → recompile → decompile must keep the same game logic and reach a fixed point within a few rounds. Byte-exact round trip is a nice-to-have, low priority. Full rule: `docs/dsl/LLIL_DSL.md` §2.

### -0.02. Hardening Policy
Tests, guards, reviews and bug hunts follow `docs/HARDENING_POLICY.md` (read it first).

### 1. NO HARDCODED MAGIC NUMBERS
Use named constants: `offset // WORD_SIZE` not `offset // 4`
Common: `WORD_SIZE = 4` (in `ir/llil/llil.py`)

### 2. Import at Module Top Level
Import at file top, not inside functions (except circular dependency with comment).

### 3. Comment Documentation
Reference constants in comments: `offset // WORD_SIZE` not `offset // 4`

### 4. Assignment Spacing
Always space around `=`: `x = 5`

### 5. Blank Lines Between Conditional Blocks
Add blank line between `if`/`elif`, `elif`/`elif`, `elif`/`else`, `if`/`else`.
```python
if cond1:
    action1()

elif cond2:
    action2()

else:
    action3()
```

### 6. English-Only Comments
No Chinese or other languages.

### 7. NO @staticmethod
Use `@classmethod` for inheritance support.

### 8. Concise Git Commit Messages
Short (1-2 sentences), no signatures/metadata.

### 9. Concise Comments
Keep comments brief and meaningful. Avoid redundant explanations.
- ✅ `# Skip self-assignment (var = var)`
- ❌ `# This code checks if the variable is equal to itself and if so we skip it`
- ✅ Use self-explanatory names instead of verbose comments
- ❌ Don't state the obvious: `x = 5  # Set x to 5`

## Environment

### Python
- Python 3.14+, standard library only: no third-party packages and no venv (`python` on PATH is 3.14.6)
- Run tests from the repo root: `python -m unittest discover -s tests` (always pass `-s tests`; bare `python -m unittest` walks every package and hits the unused `falcom.ed9.signatures` package's missing `yaml` import). One file: `python -m unittest tests.hlil_tests.test_hlil_traversal`, or `python tests/hlil_tests/test_hlil_traversal.py`. Layout and shared helpers: `docs/TESTS_GUIDE.md`
- Tests and tools insert the repo root into `sys.path` themselves; a generated script `.py` inserts the repo root into `sys.path` itself (the path of the checkout that generated it), so no `PYTHONPATH` is needed to run it
- Environment: Git Bash (MINGW64) on Windows
