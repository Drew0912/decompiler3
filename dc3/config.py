'''Project-wide byte order, text encoding and indent'''

__all__ = (
    'default_endian',
    'default_encoding',
    'default_indent',
)

ENDIAN      = 'little'
ENCODING    = 'UTF8'
INDENT      = '    '


def default_endian() -> str:
    '''Byte order of the script files (little/big)'''
    return ENDIAN


def default_encoding() -> str:
    '''Text encoding of the script files'''
    return ENCODING


def default_indent() -> str:
    return INDENT
