"""Which syscall arguments hold an ID, per game: the rows of falcom/ed9/games/<game>/metadata/syscall_args.py
(hand-written, tracked), one per command and argument count"""

from dataclasses import dataclass
import functools
import importlib

from dc3 import IntEnum2
from ..consts import CHR_ID_KIND
from ..structs.common_library import game_metadata_module

SYSCALL_ARGS_MODULE = 'syscall_args'   # in a game's metadata package; its SYSCALL_TABLE holds the rows

ANY_ARGC = None     # a row for every argument count of its command

# One letter per argument: the ID kind it holds, or None for anything else
ARG_LETTER_KINDS = {
    'N' : CHR_ID_KIND,
    '.' : None,
}


class Subsystem(IntEnum2):
    """A SYSCALL's first operand: the index of the VM's command object (ED9_VM.md, Syscalls)"""

    Sys         = 0
    Chr         = 1
    Camera      = 2
    Event       = 3
    Fade        = 4
    Mes         = 5
    Sound       = 6
    Pad         = 7
    Movie       = 8
    Trophy      = 9
    Debug       = 10
    Map         = 11
    Party       = 12
    Btl         = 13
    Effect      = 14
    Menu        = 15
    Item        = 16
    SaveData    = 17
    Portrait    = 18
    Screen      = 19
    AVoice      = 20
    MapJump     = 21
    UI          = 22
    Quest       = 23
    ChrStatus   = 24
    Shop        = 25
    Minigame    = 26
    Game        = 27


@dataclass(frozen=True)
class SyscallEntry:
    """One row: the command called with argc arguments (ANY_ARGC: any count) and a letter per argument
    (ARG_LETTER_KINDS); arguments past the letters are anything else"""

    subsystem   : Subsystem
    cmd         : int
    argc        : int | None
    args        : str


class SyscallArgs:
    """A game's rows, looked up by command and argument count: a row for the exact count wins over one for ANY_ARGC,
    and a later row over an earlier one with the same key"""

    def __init__(self, entries: list[SyscallEntry]):
        self.kinds = {(entry.subsystem, entry.cmd, entry.argc): self.entry_kinds(entry) for entry in entries}

    @classmethod
    def entry_kinds(cls, entry: SyscallEntry) -> dict[int, str]:
        """Argument index -> ID kind of the row's ID arguments; a letter that means nothing raises, naming the row"""
        unknown = set(entry.args) - ARG_LETTER_KINDS.keys()
        if unknown:
            raise ValueError(f'{entry}: argument letters {''.join(sorted(unknown))!r} are none of '
                             f'{''.join(ARG_LETTER_KINDS)!r}')

        return {index: ARG_LETTER_KINDS[letter] for index, letter in enumerate(entry.args)
                if ARG_LETTER_KINDS[letter] is not None}

    def id_kinds(self, subsystem: int, cmd: int, argc: int) -> dict[int, str]:
        """Argument index -> ID kind for the command called with argc arguments; {} without a row"""
        kinds = self.kinds.get((subsystem, cmd, argc))
        if kinds is None:
            kinds = self.kinds.get((subsystem, cmd, ANY_ARGC), {})

        return kinds


@functools.cache
def game_syscall_args(game: str | None) -> SyscallArgs | None:
    """game's rows, loaded once per game per process; None without a game or a syscall_args module. An import failure
    inside the module, or a missing game package, re-raises (as common_library_index)"""
    if game is None:
        return None

    module = game_metadata_module(game, SYSCALL_ARGS_MODULE)
    try:
        return SyscallArgs(importlib.import_module(module).SYSCALL_TABLE)
    except ModuleNotFoundError as e:
        if e.name != module:
            raise

    return None
