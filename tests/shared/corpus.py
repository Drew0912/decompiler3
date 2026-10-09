#!/usr/bin/env python3
'''Paths into the game-script corpora, and the skip for a checkout without them'''

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]     # tests/shared/corpus.py -> the repo
SORA2_SCRIPTS = REPO_ROOT / 'sora2_1.0' / 'script_en'


def corpus_file(corpus: Path, relative_path: str) -> Path:
    '''A script in a corpus folder - only a path, it never skips'''
    return corpus / relative_path


def require(path: Path) -> Path:
    '''path, or skip the test when the file is missing (e.g. the corpus is not checked out)'''
    if not path.exists():
        raise unittest.SkipTest(f'corpus file not found: {path}')

    return path
