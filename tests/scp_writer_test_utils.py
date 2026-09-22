#!/usr/bin/env python3
'''Shared test helpers for compiling DSL scripts against a throwaway ScpWriter'''

from falcom.ed9.writer import scp_writer


def fresh_writer() -> scp_writer.ScpWriter:
    '''Replace the module-level writer singleton so a compile starts from a clean state. The writer
    supports only one compile per interpreter in production (docs/LLIL_DSL.md) - it has no reset -
    so tests isolate this way instead.'''
    scp_writer._gScp = scp_writer.ScpWriter()
    return scp_writer._gScp
