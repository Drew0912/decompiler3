
# Coding Style Guide

## Rules

### -2. Read CLAUDE.md First
ALWAYS read CLAUDE.md before starting any task to refresh the rules.

### -1. Language Usage
- **User communication**: English
- **Code, comments, commit messages, tool descriptions**: English

### -0.5. Git Commit Policy
NEVER auto-commit. Only create commits when explicitly requested by user.

### -0.25. Code Modification Policy
NEVER modify code during discussion. Only modify code AFTER user explicitly confirms the approach.

### -0.1. decompiler2 Submodule Access
NEVER read, search, or reference files under the `decompiler2` submodule unless the user explicitly says to use it in the current request. If you think looking at `decompiler2` would help, ASK the user first and wait for confirmation before accessing it.

### -0.05. Codex Secondary-Agent Invocation
Full rule set in `notes/codex_rules.md` — read it before invoking Codex. Only invoke Codex for one of its listed rules (user-directed one-off action, validator-output verification, HLIL/MLIL condensability review, user-directed implementation, adversarial plan review); it is not a general-purpose delegate. Rule 5 (user-directed implementation) is the only one granting Codex real implementation authority, and only when the user explicitly asks for it by name — Claude must independently verify the result against real source afterward, not just trust Codex's self-report. Whenever Codex is invoked, or invocation is being considered, tell the user and cite which rule triggered it (e.g. "Invoking Codex — Rule 2"). Codex reviews/verifies/critiques only unless a rule explicitly grants implementation, or Claude explicitly instructs it to implement something as a separate, later step. **When writing a plan that touches `ir/hlil/` or `ir/mlil/`, include a Rule 2 Codex condensability-review step in the plan itself** (see `notes/codex_rules.md` Rule 2 "Plan integration") — don't leave it to be remembered after the fact.

### -0.045. Corpus Runs
Read `notes/corpus_run_rules.md` before any corpus-wide run (census, regression dump, round-trip validator over many files).

### -0.04. Root-Cause Fixes in `ir/`
When a bug is found while editing `ir/` (LLIL/MLIL/HLIL structures and passes), prioritize fixing the root cause over patching just the reported symptom. If a genuine root-cause fix isn't achievable, fix the version that catches the most cases the underlying gap can produce — never the narrowest guard clause scoped to the one reported instance; that's the outcome to avoid even as a fallback, not a shortcut to take. This directory's passes tend to hand-roll their own tree traversal, and that produces two recurring shapes of the same problem: a walker missing a node type — not a one-off mistake at that call site, but a class of bug that recurs across every hand-rolled walker in the file, so prefer closing the class (e.g. a shared traversal helper every predicate/collector is built on) over a narrow guard clause that only fixes the specific finding; and two related walkers (a detector and a rewriter, e.g.) that must agree on traversal shape but are maintained independently — fixing one to produce the right output for the reported case without making it structurally match the other leaves the same asymmetry free to resurface the next time either is edited alone, so prefer making them share the same traversal shape, not just the same answer for one input. Not every `ir/` bug is a traversal-coverage bug — some are genuine logic gaps (wrong equality check, missing case) that a shared walker would not have caught either; for those, still ask what the underlying gap is before patching, rather than defaulting to the narrowest possible fix.

### -0.03. Round-Trip Policy
Required: logic round trip — decompile (`round_trip=False`) → recompile → decompile must keep the same game logic and reach a fixed point within a few rounds. Byte-exact round trip is a nice-to-have, low priority. Full rule: `docs/LLIL_DSL.md` §2.

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

## Checklist
- [ ] User communication in English, everything else in English
- [ ] No auto-commit (wait for user request)
- [ ] No code changes during discussion (wait for user confirmation)
- [ ] No accessing `decompiler2` submodule unless explicitly requested (ask first)
- [ ] Codex invoked only per `notes/codex_rules.md`, with the triggering rule cited to the user
- [ ] Bugs found while editing `ir/` get a root-cause fix (or, if that's not achievable, the broadest-coverage fix, never a narrow guard clause) for the reported instance
- [ ] Recompilation work follows the round-trip policy (`docs/LLIL_DSL.md` §2): logic round trip required, byte-exact is a low-priority nice-to-have
- [ ] No hardcoded numbers (use named constants)
- [ ] Imports at top level
- [ ] Spaces around `=`
- [ ] Blank lines between conditional blocks
- [ ] English-only code comments
- [ ] `@classmethod` not `@staticmethod`
- [ ] Concise commits (no signatures)
- [ ] Concise comments (no redundant explanations)

## Environment

### Python
- Python 3.14+, standard library only: no third-party packages and no venv (`python` on PATH is 3.14.6)
- Run tests from the repo root: `python -m unittest discover -s tests` (always pass `-s tests`; bare `python -m unittest` walks every package and hits the unused `falcom.ed9.signatures` package's missing `yaml` import)
- Tests and tools insert the repo root into `sys.path` themselves; set `PYTHONPATH` to the repo root (`setPythonPath.bat` in cmd) only to run a generated script `.py` from elsewhere
- Environment: Git Bash (MINGW64) on Windows

## Active Technologies
- Python 3.14 + Existing IR modules (ir/llil, ir/mlil, ir/hlil), falcom/ed9 parser (003-ir-pass-validation)
- N/A (in-memory analysis, text/JSON report output) (003-ir-pass-validation)

## Recent Changes
- 003-ir-pass-validation: Added Python 3.14 + Existing IR modules
