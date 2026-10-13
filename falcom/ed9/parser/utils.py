from dc3 import default_encoding, default_endian, fileio
import struct

# Unused: the records in types_scp pack through their LAYOUT. Kept for now
def int_to_bytes(i, size) -> bytes:
    return int.to_bytes(i, size, default_endian())

def str_to_bytes(s: str) -> bytes:
    return s.encode(default_encoding()) + b'\x00'

def float_to_bytes(i) -> bytes:
    return fileio.struct_layout('f').pack(i)

def double_to_bytes(i) -> bytes:
    return fileio.struct_layout('d').pack(i)

_FLOAT32 = struct.Struct('<f')  # a float32 cast to or from its bits: any one byte order on both sides
_UINT32 = struct.Struct('<I')   # the float32's 32 bits

def float32_bits(value: float) -> int:
    '''value's IEEE float32 bits: the VM computes in float32, ScpValue stores the top 30 bits'''
    return _UINT32.unpack(_FLOAT32.pack(value))[0]

def float32_from_bits(bits: int) -> float:
    return _FLOAT32.unpack(_UINT32.pack(bits))[0]

def pad_string(s: str, padding: int) -> bytes:
    return s.encode(default_encoding()).ljust(padding, b'\x00')

def read_fixed_string(fs: fileio.FileStream, size: int) -> str:
    return fs.Read(size).split(b'\x00', maxsplit = 1)[0].decode(default_encoding())
