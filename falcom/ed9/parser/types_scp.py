import math
from typing import TypeAlias

from common import *
from common.logging import log
from . import utils

class ScpParamFlags(IntEnum2):
    Pointer     = 0x04
    Nullable    = 0x08

    Mask        = 0x0C


class ScpParamType(IntEnum2):
    Value   = 0x01
    Offset  = 0x02

    Mask    = 0x03

    Pointer         = Value | ScpParamFlags.Pointer
    NullableValue   = Value | ScpParamFlags.Nullable
    NullableOffset  = Offset | ScpParamFlags.Nullable


class ScpParamFlags:
    LAYOUT  = fileio.struct_layout('L')     # flags
    SIZE    = LAYOUT.size

    def __init__(self, typ: object = None, *, fs: fileio.FileStream = None):
        self.flags = 0
        self.defaultValue = None

        if typ is not None:
            if typ == Value32:
                self.flags = ScpParamType.Value

            elif typ == Nullable32:
                self.flags = ScpParamType.NullableValue

            elif typ == str:
                self.flags = ScpParamType.Offset

            elif typ == NullableStr:
                self.flags = ScpParamType.NullableOffset

            elif typ == Pointer:
                self.flags = ScpParamType.Pointer

            else:
                raise NotImplementedError(f'unsupported type: {typ}')

        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if fs is None:
            return

        (self.flags,) = self.LAYOUT.unpack(fs.Read(self.SIZE))

    def to_bytes(self) -> bytes:
        return self.LAYOUT.pack(self.flags)

    def get_python_type(self) -> str:
        # type = self.flags & ScenaFunctionParamType.Mask

        match self.flags:
            case ScpParamType.Value:
                return 'Value32'

            case ScpParamType.Offset:
                return 'str'

            case ScpParamType.NullableValue:
                return 'Nullable32'

            case ScpParamType.NullableOffset:
                return 'NullableStr'

            case ScpParamType.Pointer:
                return 'Pointer'

        raise NotImplementedError(str(self))

    def takes_string(self) -> bool:
        """str / NullableStr: the value, and so the default, is a string"""
        return (self.flags & ScpParamType.Mask) == ScpParamType.Offset

    def __str__(self) -> str:
        return f'flags = 0x{self.flags:08X}'

    __repr__ =  __str__


class RawInt(int):
    def __repr__(self) -> str:
        return f'RawInt(0x{self:08X})'

# Explicit aliases: Pylance takes a bare assignment star-imported along many paths (a hook's `from <script> import *`)
# for a variable, and rejects it in an annotation
Value32: TypeAlias     = int | float
Nullable32: TypeAlias  = Value32 | None
NullableStr: TypeAlias = str | None
Pointer: TypeAlias     = object


class ScpValue:
    TYPE_SHIFT      = 30                        # type tag is the top 2 bits
    PAYLOAD_MASK    = (1 << TYPE_SHIFT) - 1     # value, or string pool offset for String
    INTEGER_MIN     = -(1 << (TYPE_SHIFT - 1))  # an Integer payload is a signed 30-bit value
    INTEGER_MAX     = (1 << (TYPE_SHIFT - 1)) - 1
    WORD            = fileio.struct_layout('L')    # the stored word, in the scripts' byte order

    FLOAT32_BITS                   = 32
    FLOAT_DROPPED_BITS              = FLOAT32_BITS - TYPE_SHIFT     # a Float payload is float32 bits >> FLOAT_DROPPED_BITS
    FLOAT32_MAX_SIGNIFICANT_DIGITS  = 9                             # enough to name any float32 exactly

    class Type(IntEnum2):
        Raw             = 0
        Integer         = 1
        Float           = 2
        String          = 3

    ClassMap = {
        RawInt  : Type.Raw,
        int     : Type.Integer,
        float   : Type.Float,
        str     : Type.String,
    }

    def __init__(self, value: int | float | str | RawInt = None, *, fs: fileio.FileStream = None):
        self.value  = value

        if value is not None:
            # Exact type lookup: bool (an int subclass) and other types are rejected rather than mis-encoded
            if type(value) not in self.ClassMap:
                raise TypeError(f'ScpValue takes int, float, str or RawInt, not {type(value).__name__}: {value!r}')

            self.type = self.ClassMap[type(value)]
        else:
            self.type = None

        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if fs is None:
            return

        value = fs.ReadULong()
        return self.from_value(value, fs = fs)

    def from_value(self, value: int, *, fs: fileio.FileStream = None):
        self.type, self.value = self.decode_word(value, fs = fs)
        return self

    @classmethod
    def decode_word(cls, word: int, *, fs: fileio.FileStream = None) -> tuple['ScpValue.Type', int | float | str | RawInt]:
        """The type and value a stored word holds, without building an ScpValue; a String's text is read from fs"""
        typ = word >> cls.TYPE_SHIFT

        match typ:
            case ScpValue.Type.Raw:
                value = RawInt(word)

            case ScpValue.Type.Integer:
                payload = word & cls.PAYLOAD_MASK
                value = payload - (1 << cls.TYPE_SHIFT) if payload > cls.INTEGER_MAX else payload

            case ScpValue.Type.Float:
                value = utils.float32_from_bits(cls.word_float32_bits(word))
                if not math.isfinite(value):
                    log.warning(f"non-finite float {value} (word 0x{word:08X}): the game can't use it, so compiling the .py will fail")

            case ScpValue.Type.String:
                with fs.PositionSaver:
                    fs.Position = word & cls.PAYLOAD_MASK
                    value = fs.ReadMultiByte()

        return ScpValue.Type(typ), value

    def to_bytes(self) -> bytes:
        return self.WORD.pack(self.to_word())

    def to_word(self) -> int:
        '''The 32-bit word the value is stored as'''
        match self.type:
            # A decoded value is always in range, so only a hand-written one can fail these checks
            case ScpValue.Type.Raw:
                if not 0 <= self.value <= self.PAYLOAD_MASK:
                    raise ValueError(f'RawInt {self.value:#x} is outside 0..{self.PAYLOAD_MASK:#x}: its top 2 bits would be read as the type')

                return int(self.value)

            case ScpValue.Type.Integer:
                if not self.INTEGER_MIN <= self.value <= self.INTEGER_MAX:
                    raise ValueError(f'Integer {self.value} is outside {self.INTEGER_MIN}..{self.INTEGER_MAX}: the game stores a signed 30-bit value')

                return (self.value & self.PAYLOAD_MASK) | (ScpValue.Type.Integer << self.TYPE_SHIFT)

            case ScpValue.Type.Float:
                return self.encode_float(self.value)

            case _:
                raise NotImplementedError(f'unsupported type: {self.value}')

    @classmethod
    def word_float32_bits(cls, word: int) -> int:
        '''The float32 bits a Float word stores, with the dropped bits zero'''
        return (word << cls.FLOAT_DROPPED_BITS) & UINT32_MASK

    @classmethod
    def encode_float(cls, value: float) -> int:
        '''The Float word value is stored as: its float32 bits without the lowest FLOAT_DROPPED_BITS, under the Float
        tag; OverflowError past float32's range'''
        return (utils.float32_bits(value) >> cls.FLOAT_DROPPED_BITS) | (ScpValue.Type.Float << cls.TYPE_SHIFT)

    @classmethod
    def float_word(cls, value: float) -> int | None:
        '''The word value is stored as, or None past float32's range'''
        try:
            return cls.encode_float(value)

        except OverflowError:
            return None

    @classmethod
    def float_literal(cls, value: float) -> str:
        '''Shortest Python float literal that stores the same word as value - PUSH_FLOAT(0.3), not
        PUSH_FLOAT(0.2999999523162842). Always a float literal ('1.0', never '1', which would encode an
        Integer). Non-finite values, which the game can't use, print as a float() call.'''
        if math.isnan(value):
            return "float('nan')"

        if math.isinf(value):
            return "float('inf')" if value > 0 else "-float('inf')"

        word = cls.float_word(value)
        if word is None:
            # A double past float32's range has no word to match
            return repr(value)

        # The word covers 1 << FLOAT_DROPPED_BITS float32 values: search from the lowest (the one it decodes to) and
        # the middle one, so the text depends only on the word
        bits = cls.word_float32_bits(word)
        half_range = 1 << (cls.FLOAT_DROPPED_BITS - 1)
        sources = (utils.float32_from_bits(bits), utils.float32_from_bits(bits | half_range))

        for digits in range(1, cls.FLOAT32_MAX_SIGNIFICANT_DIGITS + 1):
            # The decoded value first: the midpoint's shortest form can be a different number (0.0 -> 2e-45)
            for source in sources:
                candidate = float(f'{source:.{digits}g}')
                if cls.float_word(candidate) == word:
                    return repr(candidate)

        return repr(value)

    @classmethod
    def float_bits_text(cls, value: float) -> str:
        '''The float32 bits the VM computes with and the stored word: 'f32 0x41D99998, raw 0x90766666'.'''
        word = cls.encode_float(value)
        return f'f32 {format_uint32_hex(cls.word_float32_bits(word))}, raw {format_uint32_hex(word)}'

    def __str__(self) -> str:
        # return f'ScpValue<{self.value!r}>'
        return f'ScpValue({self.value!r})'

    __repr__ = __str__


class ScpHeader(StrictBase):
    LAYOUT  = fileio.struct_layout('4s5L')  # MAGIC, function_entry_offset, function_count, global_var_offset,
    SIZE    = LAYOUT.size                   # global_var_count, dword_14: 0x18
    MAGIC   = b'#scp'

    function_entry_offset   : int = SIZE
    function_count          : int = 0
    global_var_offset       : int = 0
    global_var_count        : int = 0
    dword_14                : int = 0

    def __init__(self, *, fs: fileio.FileStream = None):
        self.from_stream(fs)
        
    def from_stream(self, fs: fileio.FileStream):
        if fs is None:
            return

        (magic, self.function_entry_offset, self.function_count, self.global_var_offset, self.global_var_count,
         self.dword_14) = self.LAYOUT.unpack(fs.Read(self.SIZE))
        assert magic == self.MAGIC

    def to_bytes(self) -> bytes:
        return self.LAYOUT.pack(self.MAGIC, self.function_entry_offset, self.function_count, self.global_var_offset,
                                self.global_var_count, self.dword_14)

    def __str__(self) -> str:
        return '\n'.join([
            f'function_entry_offset : 0x{self.function_entry_offset:08X}',
            f'function_count        : {self.function_count}',
            f'global_var_offset     : 0x{self.global_var_offset:08X}',
            f'global_var_count      : {self.global_var_count}',
            f'dword_14              : 0x{self.dword_14:08X}',
        ])

    __repr__ = __str__

class ScpFunctionEntry(StrictBase):
    # offset, param_count, is_common_func, byte06, default_params_count, default_params_offset, param_flags_offset,
    # debug_info_count, debug_info_offset, name_hash (crc32), name_offset: 0x20
    LAYOUT = fileio.struct_layout('L4B6L')
    SIZE = LAYOUT.size

    offset                      : int
    param_count                 : int
    is_common_func              : int
    byte06                      : int
    default_params_count        : int
    default_params_offset       : int
    param_flags_offset          : int
    debug_info_count            : int
    debug_info_offset           : int
    name_hash                   : int
    name_offset                 : int

    def __init__(self, *, fs: fileio.FileStream = None):
        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if fs is None:
            return

        (self.offset, self.param_count, self.is_common_func, self.byte06, self.default_params_count,
         self.default_params_offset, self.param_flags_offset, self.debug_info_count, self.debug_info_offset,
         self.name_hash, self.name_offset) = self.LAYOUT.unpack(fs.Read(self.SIZE))

        if self.byte06 != 0:
            raise NotImplementedError(f'byte06 != 0: {self.byte06}. ScpFunctionEntry.is_common_func is UShort?')

    def to_bytes(self) -> bytes:
        return self.LAYOUT.pack(self.offset, self.param_count, self.is_common_func, self.byte06,
                                self.default_params_count, self.default_params_offset, self.param_flags_offset,
                                self.debug_info_count, self.debug_info_offset, self.name_hash, self.name_offset)

    def __str__(self) -> str:
        return '\n'.join([
            f'offset                : 0x{self.offset:08X}',
            f'param_count           : {self.param_count}',
            f'is_common_func        : {self.is_common_func}',
            f'byte06                : {self.byte06}',
            f'default_params_count  : {self.default_params_count}',
            f'default_params_offset : 0x{self.default_params_offset:08X}',
            f'param_flags_offset    : 0x{self.param_flags_offset:08X}',
            f'debug_info_count      : {self.debug_info_count}',
            f'debug_info_offset     : 0x{self.debug_info_offset:08X}',
            f'name_hash             : 0x{self.name_hash:08X}',
            f'name_offset           : 0x{self.name_offset:08X}',
        ])

    __repr__ = __str__


class ScpFunctionCallDebugInfoArg(StrictBase):
    WORD                = fileio.struct_layout('L')     # each of its two words: the value, then the type
    SIZE                = 2 * WORD.size
    NON_CONSTANT_VALUE  = RawInt(0)     # value of every arg but a Constant (wrap in ScpValue)

    class Type(IntEnum2):
        Constant    = 0     # value is the pushed constant
        CallResult  = 1     # GET_REG after a nested call, value is Raw 0
        Variable    = 2     # LOAD_STACK / PUSH_STACK_OFFSET, value is Raw 0
        Expression  = 3     # computed value, value is Raw 0

    value : ScpValue
    type  : int

    def __init__(self, type: int, value: ScpValue):
        self.type   = type
        self.value  = value

    def __str__(self) -> str:
        return f'Arg<{self.type} {self.value}>'

    __repr__ = __str__

class ScpFunctionCallDebugInfo(StrictBase):
    LAYOUT      = fileio.struct_layout('LHHL')      # func_id, call_type, arg_count, info_offset: 0x0C
    SIZE        = LAYOUT.size
    NO_FUNC_ID  = 0xFFFFFFFF    # func_id of script calls and syscalls

    class CallType(IntEnum2):
        Local           = 0
        Script          = 1
        ScriptNoReturn  = 2     # CALL_SCRIPT_NO_RETURN - tail call, no PUSH_CALLER_FRAME precedes it
        Syscall         = 3

    func_id     : int
    call_type   : CallType
    arg_count   : int
    info_offset : int

    def __init__(self, *, fs: fileio.FileStream = None):
        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if fs is None:
            return

        self.func_id, call_type, self.arg_count, self.info_offset = self.LAYOUT.unpack(fs.Read(self.SIZE))
        self.call_type = self.CallType(call_type)

    def to_bytes(self) -> bytes:
        return self.pack(self.func_id, self.call_type, self.arg_count, self.info_offset)

    @classmethod
    def pack(cls, func_id: int, call_type: int, arg_count: int, info_offset: int) -> bytes:
        """to_bytes from the fields, without building a record"""
        return cls.LAYOUT.pack(func_id, call_type, arg_count, info_offset)

    def arg_offsets(self) -> range:
        """File offset of each ScpFunctionCallDebugInfoArg of this record"""
        size = ScpFunctionCallDebugInfoArg.SIZE
        return range(self.info_offset, self.info_offset + self.arg_count * size, size)

    def __str__(self) -> str:
        return '\n'.join([
            f'func_id       : 0x{self.func_id:08X}',
            f'call_type     : {self.call_type}',
            f'arg_count     : {self.arg_count}',
            f'info_offset   : 0x{self.info_offset:08X}',
        ])

    __repr__ = __str__

class ScpGlobalVar(StrictBase):
    LAYOUT = fileio.struct_layout('LL')     # name (a String-tagged ScpValue word), type: 0x08
    SIZE = LAYOUT.size

    name : str
    type : int

    class Type(IntEnum2):
        Integer = 0
        String  = 1

    def __init__(self, name: str = '', type: int = 0, *, fs: fileio.FileStream = None):
        self.name = name
        self.type = type
        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if fs is None:
            return

        # name is a String-tagged ScpValue (pool ref), not a raw pool offset
        name_word, self.type = self.LAYOUT.unpack(fs.Read(self.SIZE))
        _, self.name = ScpValue.decode_word(name_word, fs = fs)
