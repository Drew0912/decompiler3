#!/usr/bin/env python3
'''Shared test helpers for compiling DSL scripts against a throwaway ScpWriter'''

from pathlib import Path
from types import ModuleType
import importlib.util
import re
import tempfile
import unittest

from dc3 import fileio
from falcom.ed9.writer import scp_writer


HEX = '0x[0-9A-F]+'     # an address in a writer message, as a regex


def fresh_writer(dat: Path | None = None) -> scp_writer.ScpWriter:
    '''Replace the module-level writer singleton so a compile starts from a clean state (for dat, if given). The
    writer supports only one compile per interpreter in production (docs/LLIL_DSL.md) - it has no reset - so tests
    isolate this way instead.'''
    scp_writer._gScp = scp_writer.ScpWriter()
    return scp_writer.create_scp_writer(str(dat)) if dat is not None else scp_writer._gScp


def marked_line(path: str | Path, marker: str) -> int:
    '''The line of a file that ends with the comment # line: <marker>'''
    lines = Path(path).read_text(encoding = 'utf-8').splitlines()
    [number] = [number for number, text in enumerate(lines, 1) if text.rstrip().endswith(f'# line: {marker}')]
    return number


def location(path: str | Path, marker: str) -> str:
    '''The location 'file:line' of a marked line of a file, as a regex'''
    return re.escape(f'{path}:{marked_line(path, marker)}')


def at(path: str | Path, marker: str) -> str:
    '''A message prefix 'file:line: ' for a marked line of a file, as a regex'''
    return location(path, marker) + ': '


def load_module(path: Path) -> ModuleType:
    '''Run a .py file as a fresh module, kept out of sys.modules: a hook or library file whose globals no other test
    sees. Run it after fresh_writer(): what it registers goes to the writer of that moment'''
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body_writer() -> scp_writer.ScpWriter:
    '''A fresh writer inside a function body, so a test can emit opcodes one at a time; writer.fs holds the bytes'''
    writer = fresh_writer()

    def Body():
        pass

    writer.LLILCode()(Body)
    writer.current_function = writer.functions_by_name['Body']
    writer.fs = fileio.FileStream().OpenMemory()
    return writer


class WriterTestCase(unittest.TestCase):
    '''A fresh writer that compiles test.dat in a temp dir'''

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.dat = self.tmp / 'test.dat'
        self.writer = self.fresh_writer()

    def fresh_writer(self, check: bool = True) -> scp_writer.ScpWriter:
        '''A fresh writer for test.dat, with the compile check on or off'''
        writer = fresh_writer(self.dat)
        writer.check_compiled = check
        return writer
