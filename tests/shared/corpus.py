#!/usr/bin/env python3
"""Paths into the game-script corpora, and the skips for a checkout without them or the library generated from them"""

from pathlib import Path
import unittest

from falcom.ed9.parser.scp import common_library_index


REPO_ROOT = Path(__file__).resolve().parents[2]     # tests/shared/corpus.py -> the repo
SORA2_SCRIPTS = REPO_ROOT / 'falcom' / 'ed9' / 'games' / 'sora2' / 'extracted' / 'script_en'


def require(path: Path) -> Path:
    """path, or skip the test when the file is missing (e.g. the corpus is not checked out)"""
    if not path.exists():
        raise unittest.SkipTest(f'corpus file not found: {path}')

    return path


def require_library(game: str) -> dict[str, tuple[str, str]]:
    """game's common-function library index (name -> module, digest), or skip the test when the library is not
    generated"""
    index = common_library_index(game)
    if not index:
        raise unittest.SkipTest(f'common-function library of {game} not generated')

    return index
