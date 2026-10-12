'''Binary stream over a file or an in-memory buffer

Ported from the external ml (Ouroboros PyLibs) FileStream; round trips rely on these deliberate quirks
(tests/dc3_tests/test_fileio.py checks each one but WriteFloat's: no opcode writes a float through it):
- Write(*bufs) stops at the first empty buffer and returns None; a FileStream buffer writes its whole content
- integer writers truncate like a C cast, so a signed writer is its unsigned twin
- WriteFloat turns an out-of-range float into inf instead of raising
- ReadMultiByte drops undecodable bytes (errors = 'ignore'), with a warning
'''

import io
import struct
from ctypes import c_float
from .config import default_encoding, default_endian
from .logging import log

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

    STRUCT_FORMATS = 'bBhHlLf'

    def __init__(self, file: str | bytes | bytearray = None, mode: str = 'rb', *, endian: str = None, encoding: str = None):
        endian = endian or default_endian()
        self._stream = None
        self._endian = _ENDIAN_NAMES.get(endian, endian)
        self._structs = {fmt: struct.Struct(self._endian + fmt) for fmt in self.STRUCT_FORMATS}
        self._encoding = encoding or default_encoding()

        if file is not None:
            self.Open(file, mode)

    def __enter__(self) -> 'FileStream':
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.Close()

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
        layout = self._structs[fmt]
        return layout.unpack(self._stream.read(layout.size))[0]

    def _write_int(self, fmt: str, values: tuple) -> int:
        '''Write each value truncated to fmt's width, like a C cast (fmt is the unsigned format of that width)'''
        layout = self._structs[fmt]
        mask = (1 << (layout.size * BITS_PER_BYTE)) - 1
        written = 0
        for v in values:
            written += self._stream.write(layout.pack(int(v) & mask))

        return written

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

    STRING_CHUNK_SIZE = 64    # bytes read at a time while looking for a string's terminating NUL

    def ReadMultiByte(self, cp: str = None) -> str:
        '''Null-terminated string, leaving the stream after its NUL; undecodable bytes are dropped with a warning'''
        start = self._stream.tell()
        s = bytearray()
        while True:
            chunk = self._stream.read(self.STRING_CHUNK_SIZE)
            end = chunk.find(b'\x00')
            if end >= 0:
                s += chunk[:end]
                self._stream.seek(start + len(s) + 1)
                break

            s += chunk
            if len(chunk) < self.STRING_CHUNK_SIZE:
                break

        encoding = cp or self._encoding
        try:
            return s.decode(encoding)

        except UnicodeDecodeError as e:
            log.warning(f'string at 0x{start:X}: {e.reason} at byte {e.start}; undecodable bytes dropped')
            return s.decode(encoding, errors = 'ignore')

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
