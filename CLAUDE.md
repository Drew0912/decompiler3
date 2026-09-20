
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

### -0.09. binaryninja-api Third-Party Code
NEVER modify, create, or delete any file under `binaryninja-api/` — it is third-party vendor code, no exceptions. NEVER read, search, or reference files under `binaryninja-api/` either, unless the user explicitly says to use it in the current request. If you think looking at `binaryninja-api` would help, ASK the user first and wait for confirmation before accessing it.

### -0.05. Codex Secondary-Agent Invocation
Full rule set in `notes/codex_rules.md` — read it before invoking Codex. Only invoke Codex for one of its listed rules (user-directed one-off action, validator-output verification, HLIL/MLIL condensability review, corpus-harness offload, user-directed implementation, adversarial plan review); it is not a general-purpose delegate. Rule 5 (user-directed implementation) is the only one granting Codex real implementation authority, and only when the user explicitly asks for it by name — Claude must independently verify the result against real source afterward, not just trust Codex's self-report. Whenever Codex is invoked, or invocation is being considered, tell the user and cite which rule triggered it (e.g. "Invoking Codex — Rule 2"). Codex reviews/verifies/critiques only unless a rule explicitly grants implementation, or Claude explicitly instructs it to implement something as a separate, later step. **When writing a plan that touches `ir/hlil/` or `ir/mlil/`, include a Rule 2 Codex condensability-review step in the plan itself** (see `notes/codex_rules.md` Rule 2 "Plan integration") — don't leave it to be remembered after the fact.

### 1. NO HARDCODED MAGIC NUMBERS
Use named constants: `offset // WORD_SIZE` not `offset // 4`
Common: `WORD_SIZE = 4` (in `ir/llil.py`)

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
- [ ] No editing `binaryninja-api/` ever; no reading it unless explicitly requested (ask first)
- [ ] Codex invoked only per `notes/codex_rules.md`, with the triggering rule cited to the user
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
- Use the project venv, not a system install: `D:\Dev\decompiler3\.venv\Scripts\python.exe` (Python 3.14.6)
- Activate with `.venv/Scripts/activate` (Git Bash) or `activateVenv.bat` (cmd) — also sets `PYTHONPATH` to the repo root
- Environment: Git Bash (MINGW64) on Windows

## Active Technologies
- Python 3.14 + Existing IR modules (ir/llil, ir/mlil, ir/hlil), falcom/ed9 parser (003-ir-pass-validation)
- N/A (in-memory analysis, text/JSON report output) (003-ir-pass-validation)

## Recent Changes
- 003-ir-pass-validation: Added Python 3.14 + Existing IR modules
