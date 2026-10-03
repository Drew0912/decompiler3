STRING_ESCAPES          = {'\\': '\\\\', '\r': '\\r', '\n': '\\n', '\t': '\\t'}
MIN_PRINTABLE_CODEPOINT = 0x20
DELETE_CODEPOINT        = 0x7F

UINT32_MASK       = 0xFFFFFFFF
UINT32_HEX_DIGITS = 8

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
