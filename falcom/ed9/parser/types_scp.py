from ml import *
from common import *
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
        if not fs:
            return

        self.flags = fs.ReadULong()

    def to_bytes(self) -> bytes:
        return utils.int_to_bytes(self.flags, 4)

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

    def __str__(self) -> str:
        return f'flags = 0x{self.flags:08X}'

    __repr__ =  __str__


class RawInt(int):
    def __repr__(self) -> str:
        return f'RawInt(0x{self:08X})'

Value32     = int | float
Nullable32  = Value32 | None
NullableStr = str | None
Pointer     = object


class ScpValue:
    TYPE_SHIFT      = 30                        # type tag is the top 2 bits
    PAYLOAD_MASK    = (1 << TYPE_SHIFT) - 1     # value, or string pool offset for String

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
            self.type = self.ClassMap[type(value)]
        else:
            self.type = None

        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if not fs:
            return

        value = fs.ReadULong()
        return self.from_value(value, fs = fs)

    def from_value(self, value: int, *, fs: fileio.FileStream = None):
        typ = value >> 30

        match typ:
            case ScpValue.Type.Raw:
                value = RawInt(value)

            case ScpValue.Type.Integer:
                value = (value << 2) & 0xFFFFFFFF
                sign = 0xC0000000 if value & 0x80000000 != 0 else 0
                value = int.from_bytes((sign | (value >> 2)).to_bytes(4, 'little'), 'little', signed = True)

            case ScpValue.Type.Float:
                float_bytes = ((value << 2) & 0xFFFFFFFF).to_bytes(4, 'little')
                value = struct.unpack('f', float_bytes)[0]

            case ScpValue.Type.String:
                with fs.PositionSaver:
                    fs.Position = value & 0x3FFFFFFF
                    value = fs.ReadMultiByte()

        self.value = value
        self.type = ScpValue.Type(typ)

        return self

    def to_bytes(self) -> bytes:
        match self.type:
            case ScpValue.Type.Raw:
                v = self.value.to_bytes(4, default_endian())

            case ScpValue.Type.Integer:
                assert self.value <= 0x3FFFFFFFF if self.value >= 0 else self.value >= -(0x1FFFFFFF + 1)

                v = (self.value & 0x3FFFFFFF) | (ScpValue.Type.Integer << 30)
                v = int(v).to_bytes(4, default_endian(), signed = False)

            case ScpValue.Type.Float:
                v = int.from_bytes(struct.pack('f', self.value), default_endian())
                v = (v >> 2) | (ScpValue.Type.Float << 30)
                v = v.to_bytes(4, default_endian())

            case _:
                raise NotImplementedError(f'unsupported type: {self.value}')

        return v

    def __str__(self) -> str:
        # return f'ScpValue<{self.value!r}>'
        return f'ScpValue({self.value!r})'

    __repr__ = __str__


class ScpHeader(StrictBase):
    SIZE    = 0x18
    MAGIC   = b'#scp'

    function_entry_offset   : int = SIZE
    function_count          : int = 0
    global_var_offset       : int = 0
    global_var_count        : int = 0
    dword_14                : int = 0

    def __init__(self, *, fs: fileio.FileStream = None):
        self.from_stream(fs)
        
    def from_stream(self, fs: fileio.FileStream):
        if not fs:
            return

        assert fs.Read(4) == self.MAGIC

        self.function_entry_offset  = fs.ReadULong()    # 0x04
        self.function_count         = fs.ReadULong()    # 0x08
        self.global_var_offset      = fs.ReadULong()    # 0x0C
        self.global_var_count       = fs.ReadULong()    # 0x10
        self.dword_14               = fs.ReadULong()    # 0x14

    def to_bytes(self) -> bytes:
        return (
            self.MAGIC +
            utils.int_to_bytes(self.function_entry_offset, 4) +
            utils.int_to_bytes(self.function_count, 4) +
            utils.int_to_bytes(self.global_var_offset, 4) +
            utils.int_to_bytes(self.global_var_count, 4) +
            utils.int_to_bytes(self.dword_14, 4)
        )

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
    SIZE = 0x20

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
        if not fs:
            return

        self.offset                 = fs.ReadULong()
        self.param_count            = fs.ReadByte()
        self.is_common_func         = fs.ReadByte()
        self.byte06                 = fs.ReadByte() # is_common_func is UShort?
        self.default_params_count   = fs.ReadByte()
        self.default_params_offset  = fs.ReadULong()
        self.param_flags_offset     = fs.ReadULong()
        self.debug_info_count       = fs.ReadULong()
        self.debug_info_offset      = fs.ReadULong()
        self.name_hash              = fs.ReadULong() # crc32
        self.name_offset            = fs.ReadULong()

        if self.byte06 != 0:
            raise NotImplementedError(f'byte06 != 0: {self.byte06}. ScpFunctionEntry.is_common_func is UShort?')

    def to_bytes(self) -> bytes:
        return (
            utils.int_to_bytes(self.offset, 4) +
            utils.int_to_bytes(self.param_count, 1) +
            utils.int_to_bytes(self.is_common_func, 1) +
            utils.int_to_bytes(self.byte06, 1) +
            utils.int_to_bytes(self.default_params_count, 1) +
            utils.int_to_bytes(self.default_params_offset, 4) +
            utils.int_to_bytes(self.param_flags_offset, 4) +
            utils.int_to_bytes(self.debug_info_count, 4) +
            utils.int_to_bytes(self.debug_info_offset, 4) +
            utils.int_to_bytes(self.name_hash, 4) +
            utils.int_to_bytes(self.name_offset, 4)
        )

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
    SIZE = 0x08

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
    SIZE        = 0x0C
    NO_FUNC_ID  = 0xFFFFFFFF    # func_id of script calls and syscalls

    class CallType(IntEnum2):
        Local           = 0
        Script          = 1
        ScriptNoReturn  = 2     # unverified - no sample script uses CALL_SCRIPT_NO_RETURN
        Syscall         = 3

    func_id     : int
    call_type   : CallType
    arg_count   : int
    info_offset : int

    def __init__(self, *, fs: fileio.FileStream = None):
        self.from_stream(fs)

    def from_stream(self, fs: fileio.FileStream):
        if not fs:
            return

        self.func_id     = fs.ReadULong()
        self.call_type   = self.CallType(fs.ReadUShort())
        self.arg_count   = fs.ReadUShort()
        self.info_offset = fs.ReadULong()

    def to_bytes(self) -> bytes:
        return (
            utils.int_to_bytes(self.func_id, 4) +
            utils.int_to_bytes(self.call_type, 2) +
            utils.int_to_bytes(self.arg_count, 2) +
            utils.int_to_bytes(self.info_offset, 4)
        )

    def __str__(self) -> str:
        return '\n'.join([
            f'func_name     : {self.func_name}',
            f'func_id       : 0x{self.func_id:08X}',
            f'call_type     : {self.call_type}',
            f'arg_count     : {self.arg_count}',
            f'info_offset   : 0x{self.info_offset:08X}',
            f'args          : {self.args}',
        ])

    __repr__ = __str__

class ScpGlobalVar(StrictBase):
    SIZE = 0x08

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
        if not fs:
            return

        # name is a String-tagged ScpValue (pool ref), not a raw pool offset
        self.name = ScpValue(fs = fs).value
        self.type = fs.ReadULong()
