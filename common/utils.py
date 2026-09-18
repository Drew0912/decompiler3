from .config import *

FLOAT_ROUND_REL_TOL = 1e-6
FLOAT_ROUND_ABS_TOL = 1e-9

STRING_ESCAPES          = {'\\': '\\\\', '\r': '\\r', '\n': '\\n', '\t': '\\t'}
MIN_PRINTABLE_CODEPOINT = 0x20
DELETE_CODEPOINT        = 0x7F

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

def format_float(value: float) -> str:
    precision = default_float_precision_decimals()
    round_value = round(value, precision)

    rel_tol = FLOAT_ROUND_REL_TOL
    abs_tol = FLOAT_ROUND_ABS_TOL

    if abs(round_value - value) <= max(abs(value) * rel_tol, abs_tol):
        # if value != round_value:
        #     print(f'float: {precision} {value} -> {round_value}')
        value = round_value

    return f'{value}'
