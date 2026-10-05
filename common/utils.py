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

def quote_string(text: str, quote: str = '"') -> str:
    '''Python string literal for text; printable non-ASCII (e.g. Japanese game text) is kept verbatim'''
    chars = []

    for ch in text:
        if ch in STRING_ESCAPES:
            chars.append(STRING_ESCAPES[ch])

        elif ch == quote:
            chars.append('\\' + quote)

        elif ord(ch) < MIN_PRINTABLE_CODEPOINT or ord(ch) == DELETE_CODEPOINT:
            chars.append(f'\\x{ord(ch):02x}')

        else:
            chars.append(ch)

    return quote + ''.join(chars) + quote

def format_uint32_hex(value: int) -> str:
    '''Format value as an unsigned 32-bit hex literal: -1 -> 0xFFFFFFFF'''
    return f'0x{value & UINT32_MASK:0{UINT32_HEX_DIGITS}X}'

def display_width(text: str) -> int:
    '''Columns text takes in a monospace editor, which draws CJK characters two columns wide'''
    return sum(WIDE_CHAR_COLUMNS if unicodedata.east_asian_width(ch) in WIDE_EAST_ASIAN_WIDTHS else 1 for ch in text)
