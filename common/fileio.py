'''Binary stream over a file or an in-memory buffer

Ported from the external ml (Ouroboros PyLibs) FileStream; round trips rely on these deliberate quirks
(tests/test_fileio.py checks each one):
- Write(*bufs) stops at the first empty buffer and returns None; a FileStream buffer writes its whole content
- integer writers truncate like a C cast, so a signed writer is its unsigned twin
- WriteFloat turns an out-of-range float into inf instead of raising
- ReadMultiByte drops undecodable bytes (errors = 'ignore')
- an empty stream is falsy (len() is its length), and callers test `if not fs`
'''

import io
import struct
from ctypes import c_float
from .config import default_encoding, default_endian

LITTLE_ENDIAN = '<'
BIG_ENDIAN = '>'
BITS_PER_BYTE = 8

_ENDIAN_NAMES = {
    'little': LITTLE_ENDIAN,
    'big': BIG_ENDIAN,
}


class _PositionSaver:
    '''Restores the stream position on exit'''

    def __init__(self, fs: 'FileStream'):
        self.fs = fs

    def __enter__(self) -> 'FileStream':
        self.pos = self.fs.Position
        return self.fs

    def __exit__(self, exc_type, exc_value, traceback):
        self.fs.Position = self.pos


class FileStream:
    '''Typed reads/writes at the current position; endian/encoding None means default_endian()/default_encoding()'''

    def __init__(self, file: str | bytes | bytearray = None, mode: str = 'rb', *, endian: str = None, encoding: str = None):
        endian = endian or default_endian()
        self._stream = None
        self._endian = _ENDIAN_NAMES.get(endian, endian)
        self._encoding = encoding or default_encoding()

        if file is not None:
            self.Open(file, mode)

    def __enter__(self) -> 'FileStream':
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.Close()

    # An empty stream is falsy, as callers testing `if not fs` expect
    def __len__(self) -> int:
        return self.Length

    @property
    def Stream(self) -> io.IOBase:
        return self._stream

    def Open(self, file: str | bytes | bytearray, mode: str = 'rb') -> 'FileStream':
        if isinstance(file, (bytes, bytearray)):
            return self.OpenMemory(file)

        self._stream = open(file, mode)
        return self

    def OpenMemory(self, buffer: bytes = b'') -> 'FileStream':
        self._stream = io.BytesIO(buffer)
        return self

    def Close(self):
        if self._stream is not None:
            self._stream.close()

    @property
    def Length(self) -> int:
        pos = self._stream.tell()
        size = self._stream.seek(0, io.SEEK_END)
        self._stream.seek(pos)
        return size

    @property
    def Position(self) -> int:
        return self._stream.tell()

    @Position.setter
    def Position(self, offset: int):
        self._stream.seek(offset, io.SEEK_SET)

    @property
    def PositionSaver(self) -> _PositionSaver:
        return _PositionSaver(self)

    def Read(self, n: int = -1) -> bytes:
        if not n:
            return b''

        return self._stream.read(n)

    def ReadAll(self) -> bytes:
        self.Position = 0
        return self.Read()

    def Write(self, *bufs: 'bytes | bytearray | FileStream') -> int | None:
        '''Write each buffer (a FileStream contributes its whole content); an empty buffer ends the write and returns None'''
        written = 0
        for buf in bufs:
            if not buf:
                return None

            if isinstance(buf, FileStream):
                with buf.PositionSaver:
                    buf = buf.ReadAll()

            written += self._stream.write(buf)

        return written

    def _read(self, fmt: str) -> int | float:
        fmt = self._endian + fmt
        return struct.unpack(fmt, self._stream.read(struct.calcsize(fmt)))[0]

    def _write_int(self, fmt: str, values: tuple) -> int:
        '''Write each value truncated to fmt's width, like a C cast (fmt is the unsigned format of that width)'''
        fmt = self._endian + fmt
        mask = (1 << (struct.calcsize(fmt) * BITS_PER_BYTE)) - 1
        return sum(self._stream.write(struct.pack(fmt, int(v) & mask)) for v in values)

    def ReadChar(self) -> int:
        return self._read('b')

    def ReadByte(self) -> int:
        return self._read('B')

    def ReadShort(self) -> int:
        return self._read('h')

    def ReadUShort(self) -> int:
        return self._read('H')

    def ReadLong(self) -> int:
        return self._read('l')

    def ReadULong(self) -> int:
        return self._read('L')

    def ReadFloat(self) -> float:
        return self._read('f')

    def ReadMultiByte(self, cp: str = None) -> str:
        '''Null-terminated string; undecodable bytes are dropped'''
        s = bytearray()
        while True:
            b = self._stream.read(1)
            if b in (b'', b'\x00'):
                break

            s.extend(b)

        return s.decode(cp or self._encoding, errors = 'ignore')

    def WriteByte(self, *values: int) -> int:
        return self._write_int('B', values)

    def WriteUShort(self, *values: int) -> int:
        return self._write_int('H', values)

    def WriteULong(self, *values: int) -> int:
        return self._write_int('L', values)

    # Truncation makes the signed bytes identical
    WriteChar = WriteByte
    WriteShort = WriteUShort
    WriteLong = WriteULong

    def WriteFloat(self, *values: float) -> int:
        # Round through a C float first: an out-of-range value becomes inf instead of raising
        return sum(self._stream.write(struct.pack(self._endian + 'f', c_float(float(v)).value)) for v in values)
