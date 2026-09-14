
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
- Path: `D:\Dev\Python\python.exe`
- Version: 3.14.0
- Environment: Git Bash (MINGW64) on Windows

## Active Technologies
- Python 3.14 + Existing IR modules (ir/llil, ir/mlil, ir/hlil), falcom/ed9 parser (003-ir-pass-validation)
- N/A (in-memory analysis, text/JSON report output) (003-ir-pass-validation)

## Recent Changes
- 003-ir-pass-validation: Added Python 3.14 + Existing IR modules
