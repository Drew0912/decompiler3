import binascii

from dc3 import default_encoding, UINT32_MASK


def hash_function_name(name: str) -> int:
    """A function entry's name_hash: the bitwise NOT of the name's CRC-32"""
    return ~binascii.crc32(name.encode(default_encoding())) & UINT32_MASK
