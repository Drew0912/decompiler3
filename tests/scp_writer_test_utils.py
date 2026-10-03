#!/usr/bin/env python3
'''Shared test helpers for compiling DSL scripts against a throwaway ScpWriter'''

from ml import fileio

from common.config import default_encoding
from falcom.ed9.writer import scp_writer


def fresh_writer() -> scp_writer.ScpWriter:
    '''Replace the module-level writer singleton so a compile starts from a clean state. The writer
    supports only one compile per interpreter in production (docs/LLIL_DSL.md) - it has no reset -
    so tests isolate this way instead.'''
    scp_writer._gScp = scp_writer.ScpWriter()
    return scp_writer._gScp


def body_writer() -> scp_writer.ScpWriter:
    '''A fresh writer inside a function body, so a test can emit opcodes one at a time; writer.fs holds the bytes'''
    writer = fresh_writer()

    def Body():
        pass

    writer.LLILCode()(Body)
    writer.current_function = writer.functions_by_name['Body']
    writer.fs = fileio.FileStream(encoding = default_encoding()).OpenMemory()
    return writer
