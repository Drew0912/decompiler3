# AGENTS.md

Instructions for Codex, which only reviews in this repo. (Claude Code reads `CLAUDE.md`, not this file.)

## Hard Rules

- Review only: do not edit, create, move or delete any file anywhere (no report file either: your final message is
  the whole report). Only read-only commands.
- Never run `git commit`, `git commit-tree` or `git tag -s`, anywhere, not even in a scratch repo (commits are signed
  and would prompt the user).
- Never read, search or list anything under `decompiler2/` or any other folder in `.gitmodules`.
- Scripts over the game scripts (`sora2_1.0/`, `sora1/`, `kuro1/`) run only as far as the brief allows: read-only,
  within its limits.
- If the brief can reasonably be read in two ways that lead to different reviews, do not stop to ask: go with the
  likelier reading and state the ambiguity and your assumption at the top of your report.
- These rules hold unless the brief says the user lifted one for this review.

## Read First

- Before any review: `docs/CODING_STYLE.md` (house style) and `docs/HARDENING_POLICY.md` (which inputs deserve a
  test, a guard or a finding).
- Before the matching work: `docs/ROUND_TRIP_POLICY.md` (a change to the parser, the writer, an IR pass or an
  output), `docs/TESTS_GUIDE.md` (test work), `docs/VALIDATOR_GUIDE.md` (judging `tools/ir_semantic_validator.py`
  output); for a change in `ir/` or `falcom/ed9/ir/`: `.claude/rules/ir.md` and `docs/ARCHITECTURE.md`,
  "Generic/Falcom Boundary"; for a change to the writer, `metadata/`, the disassembler or the script generator:
  `docs/dsl/HOOKS.md`, "Public names".
- Which doc covers what: `docs/INDEX.md`.
