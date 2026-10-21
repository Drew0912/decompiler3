import struct
import sys
import unicodedata
from collections.abc import Iterable
from pathlib import Path

from .config import default_encoding, default_endian

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
    'int_to_bytes',
    'pad_string',
    'float32_bits',
    'float32_from_bits',
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
    """str.translate table: STRING_ESCAPES, the quote, and every other control character as \\xNN"""
    table = {cp: f'\\x{cp:02x}' for cp in [*range(MIN_PRINTABLE_CODEPOINT), DELETE_CODEPOINT]}
    table.update({ord(ch): escaped for ch, escaped in STRING_ESCAPES.items()})
    table[ord(quote)] = '\\' + quote
    return table


ESCAPES_BY_QUOTE = {quote: _escape_table(quote) for quote in ('"', "'")}


def quote_string(text: str, quote: str = '"') -> str:
    """Python string literal for text; printable non-ASCII (e.g. Japanese game text) is kept verbatim"""
    return quote + text.translate(ESCAPES_BY_QUOTE[quote]) + quote


def format_uint32_hex(value: int) -> str:
    """Format value as an unsigned 32-bit hex literal: -1 -> 0xFFFFFFFF"""
    return f'0x{value & UINT32_MASK:0{UINT32_HEX_DIGITS}X}'


def format_signed_hex(value: int, digits: int = 0) -> str:
    """Hex literal with the sign in front, zero-padded to digits: -31 -> -0x1F"""
    return f'-0x{-value:0{digits}X}' if value < 0 else f'0x{value:0{digits}X}'


def display_width(text: str) -> int:
    """Columns text takes in a monospace editor, which draws CJK characters two columns wide"""
    if text.isascii():
        return len(text)

    return sum(WIDE_CHAR_COLUMNS if unicodedata.east_asian_width(ch) in WIDE_EAST_ASIAN_WIDTHS else 1 for ch in text)


def raise_recursion_limit():
    """Raise Python's recursion limit to RECURSION_LIMIT; never lowers it"""
    sys.setrecursionlimit(max(sys.getrecursionlimit(), RECURSION_LIMIT))


def collect_paths(paths: Iterable[str | Path]) -> list[Path]:
    """Expand directories (recursively, sorted) to their .dat files; keep file paths as-is"""
    files = []
    for name in paths:
        path = Path(name)
        if path.is_dir():
            files.extend(sorted(path.rglob(DAT_PATTERN)))
        else:
            files.append(path)

    return files


def write_text_lf(path: Path, text: str):
    """Write text as UTF-8 with LF line endings on every platform"""
    path.write_text(text, encoding='utf-8', newline='\n')


# Unused: records pack through their LAYOUT struct instead. Kept for now
def int_to_bytes(i, size) -> bytes:
    return int.to_bytes(i, size, default_endian())


# Unused: kept on purpose (user)
def pad_string(s: str, padding: int) -> bytes:
    return s.encode(default_encoding()).ljust(padding, b'\x00')


_FLOAT32 = struct.Struct('<f')  # a float32 cast to or from its bits: any one byte order on both sides
_UINT32 = struct.Struct('<I')   # the float32's 32 bits


def float32_bits(value: float) -> int:
    """value's IEEE float32 bits"""
    return _UINT32.unpack(_FLOAT32.pack(value))[0]


def float32_from_bits(bits: int) -> float:
    return _FLOAT32.unpack(_UINT32.pack(bits))[0]
