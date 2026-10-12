import unicodedata
from pathlib import Path

__all__ = (
    'PROJECT_ROOT',
    'UINT32_MASK',
    'quote_string',
    'format_uint32_hex',
    'display_width',
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent   # common/ sits directly under the repo root

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

def display_width(text: str) -> int:
    '''Columns text takes in a monospace editor, which draws CJK characters two columns wide'''
    if text.isascii():
        return len(text)

    return sum(WIDE_CHAR_COLUMNS if unicodedata.east_asian_width(ch) in WIDE_EAST_ASIAN_WIDTHS else 1 for ch in text)
