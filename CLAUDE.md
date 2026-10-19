# Project Rules

## Git Commit Policy
Never commit unless the user explicitly asks for that commit: no `git commit`, `git commit-tree`, `git tag -s` or
other command that creates a commit (`merge`, `cherry-pick`, `revert`, `rebase`, `am`, `pull`), in this repo or in
any scratch repo (commits are signed, so even a scratch commit prompts the user). Never stage (`git add`, `git mv`)
without asking; move files with plain `mv`.

## Code Modification Policy
NEVER modify code during discussion. Only modify code AFTER user explicitly confirms the approach.

## decompiler2 Submodule Access
NEVER read, search, or reference files under the `decompiler2` submodule unless the user explicitly says to use it in the current request. If you think looking at `decompiler2` would help, ASK the user first and wait for confirmation before accessing it.
The same holds for every folder in `.gitmodules`. Grep from the repo root already skips `decompiler2` (gitignored);
Glob, `find` and `grep -r` do not, so exclude it there.

## Codex (reviews only)
Codex only reviews; it never edits or commits. Its reviews, run by the `codex-review` skill (local to this machine):
**IR change review** (correctness, condensability and generic/game-specific placement of `ir/` and `falcom/ed9/ir/`
changes; required, and a plan touching those folders includes it as a step), **plan review** (adversarial, before a
plan's first implementation step) and **user-asked review**. Ask before invoking any of them, and name the review
when you do (e.g. "Invoking Codex - plan review"). Codex reads `AGENTS.md` itself: its hard rules and what to read.

## Round-Trip Policy
Required: logic round trip — decompile (`round_trip=False`) → recompile → decompile must keep the same game logic and reach a fixed point within a few rounds. Byte-exact round trip: medium priority (wanted; never blocks a step or a logic fix). Full rule: `docs/ROUND_TRIP_POLICY.md`.

## Hardening Policy
Tests, guards, reviews and bug hunts follow `docs/HARDENING_POLICY.md` (read it first).

## Docs
On a cold start, or when asked for an overview, read `docs/INDEX.md` first and follow its routing. Docs are the first stop, not ground truth: check a claim against the source before acting on it.

## Runs Write Nothing in the Repo
A run of a repo script (`scena2py.py`, the writer, a `tools/` or `demos/` script, a generated script, a validator)
writes nothing inside the repo. Point its outputs at a scratch folder with absolute paths. A script whose outputs
cannot be redirected (it writes next to its input, next to itself or into the current folder) runs from a scratch
copy: of its input, or, when it also needs its place in the repo (its `sys.path` line), of the repo or the files it
needs, layout kept (per script: `docs/INDEX.md`, Running the decompiler). `git status --ignored` shows nothing new
afterwards (outputs are gitignored: plain `git status` misses them).

## Coding Style

@docs/CODING_STYLE.md

## Environment
- Python 3.14+, standard library only: no third-party packages and no venv
- Run tests from the repo root: `python -m unittest discover -s tests` (always pass `-s tests`); other forms, layout
  and shared helpers: `docs/TESTS_GUIDE.md`
