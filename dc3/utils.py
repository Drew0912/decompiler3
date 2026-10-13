import sys
import unicodedata
from collections.abc import Iterable
from pathlib import Path

__all__ = (
    'PROJECT_ROOT',
    'UINT32_MASK',
    'RECURSION_LIMIT',
    'quote_string',
    'format_uint32_hex',
    'format_signed_hex',
    'display_width',
    'raise_recursion_limit',
    'collect_paths',
    'write_text_lf',
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent   # dc3/ sits directly under the repo root

DAT_PATTERN = '*.dat'

# The HLIL passes and the TS generator recurse once or twice per nesting level, and Python's
# default limit of 1000 is close for the most deeply nested scripts; a RecursionError would drop
# that function from the output. Past the real C stack, Python still raises rather than crashing.
RECURSION_LIMIT = 10000

STRING_ESCAPES          = {'\\': '\\\\', '\r': '\\r', '\n': '\\n', '\t': '\\t'}
MIN_PRINTABLE_CODEPOINT = 0x20
DELETE_CODEPOINT        = 0x7F

UINT32_MASK       = 0xFFFFFFFF
UINT32_HEX_DIGITS = 8

WIDE_EAST_ASIAN_WIDTHS  = ('W', 'F')    # wide and full-width (CJK); ambiguous ones like '◆' are drawn narrow
WIDE_CHAR_COLUMNS       = 2

def _escape_table(quote: str) -> dict[int, str]:
    '''str.translate table: STRING_ESCAPES, the quote, and every other control character as \\xNN'''
    table = {cp: f'\\x{cp:02x}' for cp in [*range(MIN_PRINTABLE_CODEPOINT), DELETE_CODEPOINT]}
    table.update({ord(ch): escaped for ch, escaped in STRING_ESCAPES.items()})
    table[ord(quote)] = '\\' + quote
    return table

ESCAPES_BY_QUOTE = {quote: _escape_table(quote) for quote in ('"', "'")}

def quote_string(text: str, quote: str = '"') -> str:
    '''Python string literal for text; printable non-ASCII (e.g. Japanese game text) is kept verbatim'''
    return quote + text.translate(ESCAPES_BY_QUOTE[quote]) + quote

def format_uint32_hex(value: int) -> str:
    '''Format value as an unsigned 32-bit hex literal: -1 -> 0xFFFFFFFF'''
    return f'0x{value & UINT32_MASK:0{UINT32_HEX_DIGITS}X}'

def format_signed_hex(value: int, digits: int = 0) -> str:
    '''Hex literal with the sign in front, zero-padded to digits: -31 -> -0x1F'''
    return f'-0x{-value:0{digits}X}' if value < 0 else f'0x{value:0{digits}X}'

def display_width(text: str) -> int:
    '''Columns text takes in a monospace editor, which draws CJK characters two columns wide'''
    if text.isascii():
        return len(text)

    return sum(WIDE_CHAR_COLUMNS if unicodedata.east_asian_width(ch) in WIDE_EAST_ASIAN_WIDTHS else 1 for ch in text)

def raise_recursion_limit():
    '''Raise Python's recursion limit to RECURSION_LIMIT; never lowers it'''
    sys.setrecursionlimit(max(sys.getrecursionlimit(), RECURSION_LIMIT))

def collect_paths(paths: Iterable[str | Path]) -> list[Path]:
    '''Expand directories (recursively, sorted) to their .dat files; keep file paths as-is'''
    files = []
    for name in paths:
        path = Path(name)
        if path.is_dir():
            files.extend(sorted(path.rglob(DAT_PATTERN)))

        else:
            files.append(path)

    return files

def write_text_lf(path: Path, text: str):
    '''Write text as UTF-8 with LF line endings on every platform'''
    path.write_text(text, encoding = 'utf-8', newline = '\n')
