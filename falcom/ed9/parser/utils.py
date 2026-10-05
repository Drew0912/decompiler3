from common import *
import struct

def int_to_bytes(i, size) -> bytes:
    return int.to_bytes(i, size, default_endian())

def str_to_bytes(s: str) -> bytes:
    return s.encode(default_encoding()) + b'\x00'

def float_to_bytes(i) -> bytes:
    return struct.pack(default_endian() + 'f', i)

def double_to_bytes(i) -> bytes:
    return struct.pack(default_endian() + 'd', i)

def pad_string(s: str, padding: int) -> bytes:
    return s.encode(default_encoding()).ljust(padding, b'\x00')

def read_fixed_string(fs: fileio.FileStream, size: int) -> str:
    return fs.Read(size).split(b'\x00', maxsplit = 1)[0].decode(default_encoding())
